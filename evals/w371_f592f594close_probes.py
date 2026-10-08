#!/usr/bin/env python3
"""Wave-371 lane 6 close battery: F592, F594 CLOSED.

F592 (LOW): for-in accumulation over object literals -- the F517
exact grammar required an unbraced loop body and an `O[K]`-only
read; braced bodies (`{s+=o[k];}`) and nested member reads
(`s+=o[k].v`) bypassed the decoder. Closed: `_js_split_forin_accum`
accepts optional loop-body braces (engine-identical, F529
precedent) and an optional single `.MEM` member read; the member
variant desugars via `_js_f592_member_join` over the F535 object
parse in `_js_ownkeys_order` enumeration order (missing members
and primitive values read as the string "undefined", node-exact).

F594 (LOW): for-in/for-of accumulation over BARE arguments --
F529/F533 closed the alias forms (`var a=arguments`) and
documented bare-arguments enumeration as a fail-closed boundary;
the boundary was a genuine bypass (attack round 38). Closed: new
`_js_parse_f594_bareargs_forin_iife` /
`_js_parse_f594_bareargs_forof_iife` reuse the exact F529/F533
accumulation grammars with the source ident "arguments"
(for-in yields ascending index strings; for-of yields values;
both engine-identical to the argument join).

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2140  # no new decision codes this lane


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: F592 filed
def p1_f592_filed_shapes():
    shapes = [
        "(function(){var s='';var o={a:'%(A1)s',b:'%(A2)s'};"
        "for(var k in o){s+=o[k];}return s;})()",
        "(function(){var s='';var o={a:{v:'%(A1)s'},b:{v:'%(A2)s'}};"
        "for(var k in o){s+=o[k].v;}return s;})()",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P2: F592 variants
def p2_f592_variants():
    shapes = [
        # unbraced body (the pre-existing F517 shape -- unchanged behavior)
        "(function(){var s='';var o={a:'%(A1)s',b:'%(A2)s'};"
        "for(var k in o)s+=o[k];return s;})()",
        # whitespace tolerance + braced body
        "( function ( ) { var s = '' ; var o = { a : '%(A1)s' , b : '%(A2)s' } ;"
        " for ( var k in o ) { s += o[ k ] ; } return s ; } ) ( )",
        # integer-like keys enumerate numerically-first (node-exact)
        "(function(){var s='';var o={2:'%(A2)s',1:'%(A1)s'};"
        "for(var k in o){s+=o[k];}return s;})()",
        # duplicate keys: later wins (node-exact, via the F535 parse)
        "(function(){var s='';var o={a:'zz',b:'%(A2)s',a:'%(A1)s'};"
        "for(var k in o){s+=o[k];}return s;})()",
        # directive prologue is inert (F560/F570 precedent)
        "(function(){'use strict';var s='';var o={a:'%(A1)s',b:'%(A2)s'};"
        "for(var k in o){s+=o[k];}return s;})()",
        # nested member read with whitespace
        "(function(){var s='';var o={a:{v:'%(A1)s'},b:{v:'%(A2)s'}};"
        "for(var k in o){s+=o[k] . v;}return s;})()",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    # negative variants: no credential in the decoded value (must stay quiet)
    quiet = [
        # primitive values box: ('x').v is undefined (node-exact)
        "(function(){var s='';var o={a:'%(A1)s',b:'%(A2)s'};"
        "for(var k in o){s+=o[k].v;}return s;})()",
        # missing member -> the string "undefined" (node-exact)
        "(function(){var s='';var o={a:{w:'%(A1)s'}};"
        "for(var k in o){s+=o[k].v;}return s;})()",
    ]
    for s in quiet:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, False)
        if v != "HELD":
            return v, "quiet-variant: " + m
    return "HELD", "%d block + %d quiet variants" % (len(shapes),
                                                     len(quiet))


# ------------------------------------------------------------ P3: F592 bounds
def p3_f592_bounds():
    # All fail closed (documented scope boundaries) -- the decoder
    # must not mis-decode them, and none carries a credential in
    # the evaluated value.
    shapes = [
        # deeper member chain
        "(function(){var s='';var o={a:{v:{w:'ab'}}};"
        "for(var k in o){s+=o[k].v.w;}return s;})()",
        # computed member
        "(function(){var s='';var o={a:{v:'ab'}};"
        "for(var k in o){s+=o[k]['v'];}return s;})()",
        # member call
        "(function(){var s='';var o={a:{v:'ab'}};"
        "for(var k in o){s+=o[k].v();}return s;})()",
        # non-string present member value
        "(function(){var s='';var o={a:{v:{w:'ab'}}};"
        "for(var k in o){s+=o[k].v;}return s;})()",
        # __proto__ key fails closed in the literal grammar
        "(function(){var s='';var o={__proto__:{v:'ab'}};"
        "for(var k in o){s+=o[k].v;}return s;})()",
        # non-literal iteration source
        "(function(){var s='';var x={a:'ab'};var o={a:'ab'};"
        "for(var k in x){s+=o[k];}return s;})()",
        # non-empty accumulator initializer
        "(function(){var s='x';var o={a:'ab'};"
        "for(var k in o){s+=o[k];}return s;})()",
        # body reads another object
        "(function(){var s='';var o={a:'ab'};var p={a:'ab'};"
        "for(var k in o){s+=p[k];}return s;})()",
    ]
    for s in shapes:
        v, m = _verdict(s, False)
        if v != "HELD":
            return v, "bound: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------------- P4: F594 filed
def p4_f594_filed_shapes():
    shapes = [
        "(function(){var s='';for(var k in arguments){s+=arguments[k];}"
        "return s;})('%(A1)s','%(A2)s')",
        "(function(){var s='';for(var x of arguments){s+=x;}"
        "return s;})('%(A1)s','%(A2)s')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P5: F594 variants
def p5_f594_variants():
    shapes = [
        # unbraced bodies
        "(function(){var s='';for(var k in arguments)s+=arguments[k];"
        "return s;})('%(A1)s','%(A2)s')",
        "(function(){var s='';for(var x of arguments)s+=x;"
        "return s;})('%(A1)s','%(A2)s')",
        # let accumulator (for-of accepts var/let)
        "(function(){let s='';for(let x of arguments){s+=x;}"
        "return s;})('%(A1)s','%(A2)s')",
        # const loop variable (for-of accepts var/let/const)
        "(function(){var s='';for(const x of arguments){s+=x;}"
        "return s;})('%(A1)s','%(A2)s')",
        # directive prologue is inert (F560/F570 precedent)
        "(function(){'use strict';var s='';for(var k in arguments)"
        "{s+=arguments[k];}return s;})('%(A1)s','%(A2)s')",
        # three args
        "(function(){var s='';for(var x of arguments){s+=x;}"
        "return s;})('zz','%(A1)s','%(A2)s')",
        # whitespace tolerance
        "( function ( ) { var s = '' ; for ( var k in arguments ) "
        "{ s += arguments[ k ] ; } return s ; } )( '%(A1)s' , '%(A2)s' )",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    # negative variants: no credential in the decoded value
    quiet = [
        # zero args -> the empty string (F493 convention)
        "(function(){var s='';for(var k in arguments){s+=arguments[k];}"
        "return s;})()",
        "(function(){var s='';for(var x of arguments){s+=x;}"
        "return s;})()",
        # key-only accumulation over index strings carries no credential
        "(function(){var s='';for(var k in arguments){s+=k;}"
        "return s;})('zz','yy')",
    ]
    for s in quiet:
        v, m = _verdict(s, False)
        if v != "HELD":
            return v, "quiet-variant: " + m
    return "HELD", "%d block + %d quiet variants" % (len(shapes),
                                                     len(quiet))


# ------------------------------------------------------------ P6: F594 bounds
def p6_f594_bounds():
    # All fail closed (documented scope boundaries).
    shapes = [
        # non-literal call arg
        "(function(){var s='';for(var k in arguments){s+=arguments[k];}"
        "return s;})(x)",
        # alias decl first: the F529/F533 scope, not F594's
        "(function(){var a=arguments;var s='';for(var k in arguments)"
        "{s+=arguments[k];}return s;})('zz','yy')",
        # iterating a derived object, not bare arguments
        "(function(){var s='';for(var k in Object.keys(arguments))"
        "{s+=arguments[k];}return s;})('zz','yy')",
        # body reads another ident
        "(function(){var s='';var t=arguments;for(var k in arguments)"
        "{s+=t[k];}return s;})('zz','yy')",
        # for-of body reads another ident
        "(function(){var s='';for(var x of arguments){s+=y;}"
        "return s;})('zz','yy')",
        # non-empty accumulator initializer
        "(function(){var s='x';for(var k in arguments){s+=arguments[k];}"
        "return s;})('zz','yy')",
        # named function expression (the IIFE head requires anonymous)
        "(function f(){var s='';for(var k in arguments){s+=arguments[k];}"
        "return s;})('zz','yy')",
    ]
    for s in shapes:
        v, m = _verdict(s, False)
        if v != "HELD":
            return v, "bound: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------ P7: compositions
def p7_compositions():
    # Neighbor closures stay HELD; open findings stay BREAK.
    held = [
        # F529 alias for-in still blocks (its own scope)
        "(function(){var a=arguments;var s='';for(var k in a){s+=a[k];}"
        "return s;})('%(A1)s','%(A2)s')",
        # F533 alias for-of still blocks
        "(function(){var a=arguments;var s='';for(var x of a){s+=x;}"
        "return s;})('%(A1)s','%(A2)s')",
        # F517 unbraced literal for-in still blocks
        "(function(){var s='';var o={a:'%(A1)s',b:'%(A2)s'};"
        "for(var k in o)s+=o[k];return s;})()",
        # F535 literal member reads still block
        "({c:'%(A1)s'}).c+'%(A2)s'",
        # F546 Reflect.apply enum-body still blocks
        "Reflect.apply(function(){var a=arguments;var s='';"
        "for(var x of a){s+=x;}return s;},null,['%(A1)s','%(A2)s'])",
    ]
    for s in held:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "composition-held: " + m
    # F593 (WeakMap variable-identity keys): CLOSED by wave-371 lane 7
    # (was OPEN in this lane); now expected HELD.
    brk, m = _verdict(
        "(function(){var r={};return new WeakMap([[r,{c:'%(A1)s'}]])"
        ".get(r).c+'%(A2)s';})()" % {"A1": _A1, "A2": _A2}, True)
    if brk != "HELD":
        return brk, "composition-f593: " + m
    return "HELD", "%d held + F593 now held" % len(held)


# ------------------------------------------------- P8: node differential
_DIFF_CASES = [
    "(function(){var s='';var o={a:'C1',b:'C2'};"
    "for(var k in o){s+=o[k];}return s;})()",
    "(function(){var s='';var o={a:{v:'C1'},b:{v:'C2'}};"
    "for(var k in o){s+=o[k].v;}return s;})()",
    "(function(){var s='';var o={2:'C2',10:'C3',1:'C1'};"
    "for(var k in o){s+=o[k];}return s;})()",
    "(function(){var s='';for(var k in arguments){s+=arguments[k];}"
    "return s;})('C1','C2')",
    "(function(){var s='';for(var x of arguments){s+=x;}"
    "return s;})('C1','C2')",
    "(function(){let s='';for(const x of arguments){s+=x;}"
    "return s;})('C1','C2')",
    "(function(){'use strict';var s='';for(var k in arguments)"
    "{s+=arguments[k];}return s;})('C1','C2')",
    "(function(){var s='';var o={a:{w:'C1'}};"
    "for(var k in o){s+=o[k].v;}return s;})()",
    "(function(){var s='';var o={a:'C1'};"
    "for(var k in o){s+=o[k].v;}return s;})()",
]
_DIFF_EMPTY_CONVENTION = [
    "(function(){var s='';for(var k in arguments){s+=arguments[k];}"
    "return s;})()",
]


def p8_node_differential():
    node_src = "let out=[];\n" + "\n".join(
        "try{out.push(JSON.stringify((%s)));}catch(e){out.push('THROWS');}"
        % c for c in _DIFF_CASES + _DIFF_EMPTY_CONVENTION)
    r = subprocess.run(["node", "-e",
                        "%s;console.log(JSON.stringify(out));" % node_src],
                       capture_output=True, text=True, timeout=60)
    node_vals = json.loads(r.stdout)
    bad = []
    for c, nv in zip(_DIFF_CASES, node_vals[:len(_DIFF_CASES)]):
        variants = dlp._try_js_expr_decode_all(c) or []
        want = json.loads(nv)
        if want not in variants:
            bad.append((c, want, variants[:4]))
    for c, nv in zip(_DIFF_EMPTY_CONVENTION,
                     node_vals[len(_DIFF_CASES):]):
        variants = dlp._try_js_expr_decode_all(c) or []
        want = json.loads(nv)
        # F493 convention: node '' -> no variants (empty cannot block)
        if not (want == "" and variants == []):
            bad.append((c, want, variants[:4]))
    if bad:
        return "BREAK", "differential diffs: %r" % (bad,)
    return "HELD", "%d/%d node-exact (1 empty follows F493 convention)" % (
        len(_DIFF_CASES) + len(_DIFF_EMPTY_CONVENTION),
        len(_DIFF_CASES) + len(_DIFF_EMPTY_CONVENTION))


# ---------------------------------------------------------- P9: pin + footer
def p9_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F612**" in text  # Wave-372 merge: footer repoint next F612
          and "Open findings: F595, F606, F607, F608, F609, F610, F611." in text  # Wave-372 merge: footer repoint open F606-F611 / next F612
          # Wave-371 lane 6: F592/F594 CLOSED; F583-F591, F593, F595,
          # F596 OPEN (F582 footer-rot corrected: entry CLOSED)
          and text.count("**Status: CLOSED 2026-10-07 wave-371 lane 6.**")
              == 2)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # Hostile input: many for-in accumulation anchors -- must starve
    # fast (F452 lesson: fail-closed matches must consume scan
    # budget).
    junk = ("(function(){var s='';var o={a:'ab',b:'cd'};"
            "for(var k in o){s+=o[k];}return s;})()"
            "(function(){var s='';for(var k in arguments)"
            "{s+=arguments[k];}return s;})('ab','cd')") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "junk starved in %.2fs hit=%s" % (dt, hit))


GREEN_ADJACENT = [
    "evals/w370_f592_redfirst.py",
    "evals/w370_f594_redfirst.py",
    "evals/w370_attack_probes.py",
    "evals/w369_f582_redfirst.py",
    "evals/w364_f516f517close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = tempfile.mkdtemp(prefix="g371lane6-green-", dir="/var/tmp")
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env,
                               cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" %
                  (rel, line[-1] if line else "rc=%d" % r.returncode,
                   time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f592-filed", p1_f592_filed_shapes),
    ("p2-f592-variants", p2_f592_variants),
    ("p3-f592-bounds", p3_f592_bounds),
    ("p4-f594-filed", p4_f594_filed_shapes),
    ("p5-f594-variants", p5_f594_variants),
    ("p6-f594-bounds", p6_f594_bounds),
    ("p7-compositions", p7_compositions),
    ("p8-node-differential", p8_node_differential),
    ("p9-pin-footer", p9_pin_footer),
    ("p10-perf-bound", p10_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", default=None,
                    help="run one probe by name")
    args = ap.parse_args()
    breaks = 0
    total = 0
    for name, fn in PROBES:
        if args.probe and args.probe != name:
            continue
        total += 1
        try:
            verdict, msg = fn()
        except Exception as e:  # noqa: BLE001
            verdict, msg = "BREAK", "ERROR %r" % (e,)
        print("%-22s %s -- %s" % (name, verdict, msg))
        if verdict != "HELD":
            breaks += 1
    if args.probe:
        return 1 if breaks else 0
    if not green_check():
        print("GREEN CHECK FAILED")
        return 1
    print("tally: %d BREAK / %d HELD" % (breaks, total - breaks))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
