#!/usr/bin/env python3
"""Wave-370 lane 6 close probes: F575 (String.raw array-like raw object),
F582 (F519-class extra call args).

F575: String.raw with a non-array raw object bypasses the bounded static
JS-expression decoder -- F493 closed the no-substitution call form with an
ARRAY raw, and F551 closed the substitution form with {raw:[...]}, but a
non-array raw object is a different receiver production:
String.raw({raw:{0:'f1',1:'f2',length:2}}) and
String.raw.call(String,{raw:{0:'f1',1:'f2',length:2}}) node-evaluate to the
exact credential (v24.20.0) with zero decoder variants. Closed by
_js_parse_raw_arraylike: ToObject(raw) + LengthOfArrayLike +
ToString(Get(raw,k)) for k in 0..length-1, node-exact -- ident/string/
numeric keys with later-wins (unquoted numerics canonicalize via
ToString(number); quoted non-canonical keys like '00' are distinct string
keys the loop never observes); missing indices contribute the literal
string "undefined" (ToString(undefined)); missing length is 0;
string-literal values and canonical-int length only, else fail closed
(documented). Parts budget charged per materialized segment (F452
lesson). Interleave with substitutions reuses F551's helper; both the
direct and .call dispatch forms covered.

F582: extra call args beyond arity bypass the decoder on F519-class arrow
targets -- F519 closed Reflect.apply((a,b)=>a+b, null, ['f1','f2']) with
exact-arity matching, but the engine fills params positionally and
IGNORES extras: Reflect.apply((a,b)=>a+b, null, ['f1','f2','junk'])
node-evaluates to the exact credential (v24.20.0) while the decoder fails
closed on the arity mismatch (zero variants). Re-filed as a new finding
(rather than silently patched into F519) per the red-first audit rule;
caught by the wave-369 lane 4 two-axis code review while closing F556,
which had the same gap and was fixed in the same lane (F556 precedent).
Closed by relaxing the arity check at the three F519-class additive-target
sites (_js_parse_reflect_apply_fn, the F544 call-indirect fallback in
_js_parse_f521_call_dispatch, _js_parse_reflect_apply_proxy for F542):
extras beyond the parameter count are dropped engine-identically
(elements[:len(params)] -- body operands are pure param indices so extras
can never enter the result); fewer args than params still fail closed
(node coerces missing params to undefined -- conservative). Enum
(F546/F568) and destructure (F558) modes never had an arity check --
extras are node-exact there already (enum joins the full arguments
exotic; destructure binds only pattern names).

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"
_A2 = "456789" + "abcdef"

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _verdict(payload, want_block):
    hit = _blocked(payload)
    ok = hit == want_block
    return ("HELD" if ok else "BREAK",
            "%s want_block=%s hit=%s" % (payload[:72], want_block, hit))


# ------------------------------------------------------------- P1: F575 filed
def p1_f575_filed_shapes():
    shapes = [
        "String.raw({raw:{0:'%(A1)s',1:'%(A2)s',length:2}})",
        "String.raw.call(String,{raw:{0:'%(A1)s',1:'%(A2)s',length:2}})",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P2: F575 variants
def p2_f575_variants():
    shapes = [
        # substitution interleave on the array-like form
        "String.raw({raw:{0:'%(A1)s',1:'%(A2)s',length:2}},'X')",
        # whitespace tolerance
        "String.raw( { raw : { 0 : '%(A1)s' , 1 : '%(A2)s' , length : 2 } } )",
        # trailing comma (valid JS)
        "String.raw({raw:{0:'%(A1)s',1:'%(A2)s',length:2,}})",
        # quoted numeric keys
        "String.raw({raw:{'0':'%(A1)s','1':'%(A2)s','length':2}})",
        # duplicate keys: later wins (node-exact)
        "String.raw({raw:{0:'zz',0:'%(A1)s',1:'%(A2)s',length:2}})",
        # .call with additive thisArg
        "String.raw.call('x'+'y',{raw:{0:'%(A1)s',1:'%(A2)s',length:2}})",
        # extra unread keys are ignored by the index loop (node-exact)
        "String.raw({raw:{foo:'zz',0:'%(A1)s',1:'%(A2)s',length:2}})",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    return "HELD", "%d variants block" % len(shapes)


# ------------------------------------------------------------ P3: F575 bounds
def p3_f575_bounds():
    # All fail closed (documented scope boundaries).
    shapes = [
        "String.raw({raw:{0:65,length:1}})",          # numeric value
        "String.raw({raw:{0:'ab',length:'2'}})",      # string length
        "String.raw({raw:{0:'ab',length:2.5}})",      # float length
        "String.raw({raw:{0:'ab',length:02}})",      # leading-zero length
        "String.raw({raw:{0:'ab',length:999999}})",  # huge length
        "String.raw({raw:{0:'ab',length:2x}})",      # bad length token
        "String.raw({raw:['ab'],x:1})",              # two-key template
        "String.raw.apply(String,[{raw:{0:'ab',length:1}}])",  # .apply
        "String.raw({raw:'ab'})",                    # non-object raw
        "String.raw('ab')",                          # non-object template
        "String.raw({raw:{0:'ab',length:2}},'x'+'y')",  # non-literal sub
        "String.raw({raw:{00001:'ab',length:2}})",  # long numeric key
        "String.raw({raw:{0:'ab',length:" + "9" * 5000 + "}})",  # digit-run DoS
    ]
    for s in shapes:
        v, m = _verdict(s, False)
        if v != "HELD":
            return v, "bound should miss: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------------- P4: F582 filed
def p4_f582_filed_shapes():
    shapes = [
        "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s','junk'])",
        "Reflect.apply(function(a,b){return a+b;},null,"
        "['%(A1)s','%(A2)s','junk','more'])",
        "Reflect.apply(function(a,b,c){return a+b;},null,"
        "['%(A1)s','%(A2)s','zz','junk'])",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P5: F582 variants
def p5_f582_variants():
    shapes = [
        # F544 spread argsArray with extras
        "Reflect.apply((a,b)=>a+b,null,[...['%(A1)s','%(A2)s','junk']])",
        # F542 proxy apply-trap with extras (delegating trap)
        "Reflect.apply(new Proxy((a,b)=>a+b,{apply:"
        "(t,u,a)=>Reflect.apply(t,u,a)}),null,"
        "['%(A1)s','%(A2)s','junk'])",
        # named function expression with extras
        "Reflect.apply(function f(a,b){return a+b;},null,"
        "['%(A1)s','%(A2)s','junk'])",
        # whitespace tolerance with extras
        "Reflect.apply( ( a , b ) => a + b , null , "
        "[ '%(A1)s' , '%(A2)s' , 'junk' ] )",
        # extras on a 1-param target
        "Reflect.apply((a)=>a,null,['%(A1)s%(A2)s','junk'])",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    return "HELD", "%d variants block" % len(shapes)


# ------------------------------------------------------------ P6: F582 bounds
def p6_f582_bounds():
    # All fail closed (documented).
    shapes = [
        # fewer args than params: node coerces to undefined -- conservative
        "Reflect.apply((a,b,c)=>a+b,null,['%(A1)s','%(A2)s'])",
        # non-literal argsArray
        "Reflect.apply((a,b)=>a+b,null,x)",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, False)
        if v != "HELD":
            return v, "bound should miss: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------- P7: compositions
def p7_compositions():
    held = [
        # F493 array-raw form still blocks
        "String.raw({raw:['%(A1)s','%(A2)s']})",
        # F551 substitution form still blocks
        "String.raw({raw:['','','%(A1)s%(A2)s']},'x','y')",
        # F519 exact-arity still blocks
        "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s'])",
        # F546 enum body still blocks
        "Reflect.apply(function(){var a=arguments;var s='';"
        "for(var x of a){s+=x;}return s;},null,['%(A1)s','%(A2)s'])",
        # F558 destructure body still blocks
        "Reflect.apply(function(){const[a,b]=arguments;return a+b;},null,"
        "['%(A1)s','%(A2)s'])",
        # F575 shape inside a larger expression
        "String.raw({raw:{0:'%(A1)s',1:'%(A2)s',length:2}})+''",
        # F575 with substitution inside a larger expression
        "('q='+String.raw({raw:{0:'%(A1)s',1:'%(A2)s',length:2}},'X'))",
        # F546 for-of enum body with extras: extras are appended
        # node-exactly (arguments exotic = full argsArray), so the
        # credential remains a substring and the payload blocks
        "Reflect.apply(function(){var a=arguments;var s='';"
        "for(var x of a){s+=x;}return s;},null,"
        "['%(A1)s','%(A2)s','junk'])",
        # F558 destructure body with extras: extras are never bound
        # (pattern names only), so the payload blocks node-exactly
        "Reflect.apply(function(){const[a,b]=arguments;return a+b;},null,"
        "['%(A1)s','%(A2)s','junk'])",
    ]
    for s in held:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "composition: " + m
    v, m = _verdict("the quick brown fox", False)
    if v != "HELD":
        return v, "junk-quiet: " + m
    return "HELD", "%d compositions hold" % (len(held) + 1)


# --------------------------------------------------- P8: node differential
_DIFF_CASES = [
    "String.raw({raw:{0:'f1',1:'f2',length:2}})",
    "String.raw.call(String,{raw:{0:'f1',1:'f2',length:2}})",
    "String.raw({raw:{0:'a',1:'b',length:2}},'X')",
    "String.raw({raw:{0:'f1',length:2}})",
    "String.raw({raw:{0:'a',0:'f1',length:1}})",
    "String.raw({raw:{0:'f1',length:1}},'X')",
    "String.raw({raw:{'00':'f1',0:'b',length:1}})",
    "String.raw({raw:{length:2}})",
    "String.raw({raw:['f1','f2']})",
    "Reflect.apply((a,b)=>a+b,null,['f1','f2','junk'])",
    "Reflect.apply(function(a,b){return a+b;},null,['f1','f2','junk','more'])",
    "Reflect.apply(function(a,b,c){return a+b;},null,['f1','f2','zz','junk'])",
    "Reflect.apply((a,b)=>a+b,null,[...['f1','f2','junk']])",
    "Reflect.apply((a,b)=>a+b,null,['f1','f2'])",
]
# Empty-string results follow the F493 no-variant convention (node '' ->
# no decoder variants, same as String.raw({raw:[]})).
_DIFF_EMPTY_CONVENTION = [
    "String.raw({raw:{0:'f1'}})",
    "String.raw({raw:{}})",
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
    return "HELD", "%d/%d node-exact (2 empty follow F493 convention)" % (
        len(_DIFF_CASES) + len(_DIFF_EMPTY_CONVENTION),
        len(_DIFF_CASES) + len(_DIFF_EMPTY_CONVENTION))


# ---------------------------------------------------------- P9: pin + footer
def p9_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: 2135 -> 2140
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F700**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-377 merge: footer repoint open F655-F660 / next F661  # Wave-377 merge: F661 FILED OPEN (merge red-first audit); footer repoint open F662-F671 / next F672
          and "**Open findings: F662, F663, F664, F665, F666, F667, F669, F670, F671.**" in text  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)
          # Wave-374 lane 2: F613 CLOSED (was stale: wave-370-era F570-F581 list)
          and text.count("**Status: CLOSED 2026-10-07 wave-370 lane 6.**")
              == 2)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # Hostile input: many String.raw anchors incl. array-like raws --
    # must starve fast (F452 lesson: fail-closed matches must consume
    # scan budget).
    junk = ("String.raw({raw:{0:'ab',1:'cd',length:2}},'ef')"
            "String.raw({raw:['ab','cd']},'ef')"
            "Reflect.apply((a,b)=>a+b,null,['ab','cd','junk'])") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "junk starved in %.2fs hit=%s" % (dt, hit))


GREEN_ADJACENT = [
    "evals/w369_f575_redfirst.py",
    "evals/w369_f582_redfirst.py",
    "evals/w369_f551f559f564close_probes.py",
    "evals/w369_f553f554f555f556close_probes.py",
    "evals/w369_f558f567f568f569close_probes.py",
    "evals/w369_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g370lane6-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
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
    ("p1-f575-filed", p1_f575_filed_shapes),
    ("p2-f575-variants", p2_f575_variants),
    ("p3-f575-bounds", p3_f575_bounds),
    ("p4-f582-filed", p4_f582_filed_shapes),
    ("p5-f582-variants", p5_f582_variants),
    ("p6-f582-bounds", p6_f582_bounds),
    ("p7-compositions", p7_compositions),
    ("p8-node-differential", p8_node_differential),
    ("p9-pin-footer", p9_pin_footer),
    ("p10-perf-bound", p10_perf_bound),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", default=None)
    args = parser.parse_args()
    breaks, held, errors = 0, 0, 0
    for name, fn in PROBES:
        if args.probe and args.probe != name:
            continue
        try:
            verdict, msg = fn()
        except Exception as e:  # noqa: BLE001
            verdict, msg = "ERROR", "%r" % e
        print("%-22s %s: %s" % (name, verdict, msg))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "ERROR":
            errors += 1
        else:
            held += 1
    green_ok = green_check()
    print("tally: %d BREAK / %d HELD / %d ERROR%s" %
          (breaks, held, errors, "" if green_ok else " GREEN-FAIL"))
    return 1 if (breaks or errors or not green_ok) else 0


if __name__ == "__main__":
    sys.exit(main())
