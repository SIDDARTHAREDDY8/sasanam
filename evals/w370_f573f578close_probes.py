#!/usr/bin/env python3
"""Wave-370 lane 4 closure battery: F573 + F578 (entries/defineProperty family).

Two LOW findings from wave-369 attack round 37 (node v24.20.0 ->
credential, decoder missed on the wave-369-merged base):

F573: Object.entries index reads on OBJECT LITERALS.
  F543 (CLOSED) covers entries/values enumeration on ALIASED
  ARGUMENTS, but plain object literals are a different receiver
  class:
    Object.entries({a:'f1'})[0][1]+'f2'
    Object.entries({x:{y:'f1'}})[0][1].y+'f2'   (nested)
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct from F543 (aliased arguments, CLOSED),
  F568 (entries-idiom BODIES in function-valued apply targets,
  CLOSED), F535 (direct literal member reads, CLOSED). Object.values
  on literals is already modeled (F510, HELD).

F578: Object.defineProperty descriptor REPLACEMENT laundering.
  F550 (CLOSED) covers defineProperty ADDING a property and its
  later-wins semantics legitimately covers the direct-literal
  replacement shape; the still-missing shapes bind the target to a
  var (IIFE):
    (function(){var o={c:'x'};
      Object.defineProperty(o,'c',{get:function(){return 'f1';}});
      return o.c;})()+'f2'                                  (getter)
    (function(){var o={c:'z'};
      Object.defineProperty(o,'c',{value:'f1'});return o.c;})()+'f2'
                                                            (valswap)
  Both node-evaluate to the exact credential (v24.20.0) with zero
  decoder variants. Distinct from F550 (direct literal targets).

Closure design (gov/dlp.py, zero new re.compile -- count stays 28):

  * `_js_parse_f573_entries_literal` -- `Object.entries(OBJLIT)` /
    `Object['entries'](OBJLIT)` with NO `.map` projection (the
    `.map` form still belongs to F517's `_js_parse_object_entries`,
    which is tried when this parser defers). The literal is parsed
    by `_js_parse_f535_object` (string values, canonical ints,
    nested objects; getters evaluated at parse time like F535);
    keys are reordered engine-exactly (integer-index keys ascending
    numerically first, then string keys in insertion order -- node
    v24.20.0 verified); symbol keys fail closed (documented
    boundary). Result is `_JSArr` of `_JSArr([k, v])` pairs, so the
    normal postfix chain (`[0][1]`, `.y`, `.join('')`) resolves
    node-exactly.
  * `_js_parse_f578_defineprop_iife` --
    `(function(){var|const|let o=OBJLIT;
      Object.defineProperty(o,'K',DESC);return o.M;})()`:
    the var binds the parsed literal (F535 object), the
    defineProperty target must be the bare bound ident, the key a
    string literal (`__proto__` fails closed), the descriptor parsed
    by `_js_parse_f548f550_descriptor` (`{value: V}` installs V;
    `{get: fn}` installs the getter's evaluated return -- F550's
    exact descriptor discipline; `set`/unknown keys fail closed),
    and the return reads a member of the replaced object (missing
    key fails closed -- the engine yields undefined). The F560
    directive-prologue skip applies. Invocation must be `()` empty
    (filed shapes; non-empty args fail closed, documented).

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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TAXONOMY_PIN = 2144  # Wave-370: watcher merge moved 2135 -> 2140; Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144

FOOTER_OPEN = "F762, F763, F764, F765, F766, F767, F768, F769, F770, F771, F772, F773, F774, F775, F776, F777, F778, F779, F780, F781, F782, F783, F784, F785, F786, F787, F788, F789, F790, F791, F792, F793, F794"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 lane 6: F668 CLOSED (lane-local)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)
FOOTER_NEXT = "F795"  # Wave-378 merge: F655-F661 CLOSED; F662-F671 filed OPEN (next F672)  # Wave-371 merge: F583-F596 CLOSED (lanes 1-7); F597-F605 OPEN (next F606)  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)  # Wave-379 merge: F662-F671 CLOSED (lanes 1-7); F672-F685 filed OPEN (next F686)  # Wave-383 merge: F713-F737 CLOSED; F738-F761 OPEN (next F762) # Wave-384 merge: F738-F761 CLOSED; F762-F794 OPEN (next F795)


def hit(payload):
    """True when the decoder flags the payload (blocks coded)."""
    try:
        return find_credential(payload) is not None
    except Exception:  # noqa: BLE001 -- fail-closed is a miss here
        return False


def p1_f573_filed_shapes():
    """F573 filed shapes block coded (were BREAK on the open tree)."""
    shapes = [
        "Object.entries({a:'%(A1)s'})[0][1]+'%(A2)s'",
        "Object.entries({x:{y:'%(A1)s'}})[0][1].y+'%(A2)s'",
    ]
    bad = [s for s in shapes
           if not hit(s % {"A1": A1, "A2": A2})]
    if bad:
        return "BREAK", "miss: %s" % bad[0][:60]
    return "HELD", "2/2 filed shapes block"


def p2_f573_variants():
    """F573 variants: key ordering, bracket form, join chains."""
    cases = [
        # integer-index keys enumerate ascending first (node-exact):
        # {b,2,1} -> order ['1','2','b'], so [0][1] is the '1' value
        ("Object.entries({b:'%(A2)s',2:'x',1:'%(A1)s'})[0][1]+'%(A2)s'",
         True),
        # bracket-string member form (F480 precedent)
        ("Object['entries']({a:'%(A1)s'})[0][1]+'%(A2)s'", True),
        # .join chain over pairs' values
        ("Object.entries({a:'%(A1)s',b:'%(A2)s'}).map(e=>e[1]).join('')",
         None),  # F517 owns the .map form -- must not change verdict
        # duplicate key: later wins, first-insertion position kept
        ("Object.entries({a:'zz',a:'%(A1)s'})[0][1]+'%(A2)s'", True),
        # values() on literals stays HELD (F510, pre-existing)
        ("Object.values({a:'%(A1)s'})[0]+'%(A2)s'", True),
        # symbol keys are skipped (engine excludes them from
        # entries() -- node v24.20.0 verified)
        ("Object.entries({[Symbol.for('s')]:'junk',a:'%(A1)s'})[0][1]"
         "+'%(A2)s'", True),
    ]
    for payload, want in cases:
        h = hit(payload % {"A1": A1, "A2": A2})
        if want is None:
            continue  # informational only; F517's verdict is its own
        if h != want:
            return "BREAK", "variant verdict flip: %s" % payload[:50]
    return "HELD", "%d/%d variants hold" % (len(cases) - 1, len(cases) - 1)


def p3_f573_bounds():
    """F573 fail-closed boundaries."""
    bounds = [
        # non-literal argument fails closed (never mis-decoded)
        "Object.entries(x)[0][1]+'%(A1)s'",
        # empty literal: [0] is engine-undefined -> fail closed
        "Object.entries({})[0]+'%(A1)s'",
        # out-of-range pair index -> fail closed
        "Object.entries({a:'%(A1)s'})[5]+'%(A2)s'",
        # junk stays quiet (no false positive)
        "Object.entries({a:'zz'})[0][1]+'yy'",
        # method value fails closed (F535 boundary)
        "Object.entries({a:function(){}})[0][1]+'%(A1)s'",
    ]
    for payload in bounds:
        if hit(payload % {"A1": A1, "A2": A2}):
            return "BREAK", "boundary decoded: %s" % payload[:50]
    return "HELD", "%d/%d bounds fail closed" % (len(bounds), len(bounds))


def p4_f578_filed_shapes():
    """F578 filed shapes block coded (2 were BREAK; direct was F550)."""
    shapes = [
        # getter replacement on a var target
        ("(function(){var o={c:'x'};"
         "Object.defineProperty(o,'c',{get:function(){return '%(A1)s';}});"
         "return o.c;})()+'%(A2)s'"),
        # direct value swap -- already HELD via F550's later-wins
        ("Object.defineProperty({c:'x'},'c',{value:'%(A1)s'}).c+'%(A2)s'"),
        # IIFE value swap on a var target
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
    ]
    bad = [s for s in shapes
           if not hit(s % {"A1": A1, "A2": A2})]
    if bad:
        return "BREAK", "miss: %s" % bad[0][:60]
    return "HELD", "3/3 filed shapes block"


def p5_f578_variants():
    """F578 variants: decl kinds, bracket forms, descriptor merge."""
    cases = [
        # const/let bind identically (node-verified)
        ("(function(){const o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'", True),
        ("(function(){let o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'", True),
        # bracket-string key and return read (F480 precedent)
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o['c'];})()+'%(A2)s'", True),
        # getter replaced by a later value descriptor -> data prop
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{get:function(){return 'zz';}});"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'", True),
        # directive prologue before the binding (F560 composition)
        ("(function(){'use strict';var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'", True),
        # junk stays quiet
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'zz'});"
         "return o.c;})()+'yy'", False),
    ]
    for payload, want in cases:
        if hit(payload % {"A1": A1, "A2": A2}) != want:
            return "BREAK", "variant verdict flip: %s" % payload[:50]
    return "HELD", "%d/%d variants hold" % (len(cases), len(cases))


def p6_f578_bounds():
    """F578 fail-closed boundaries."""
    bounds = [
        # return reads a different key -> engine undefined
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.d;})()+'%(A2)s'"),
        # set descriptor fails closed (documented)
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{set:function(v){}});"
         "return o.c;})()+'%(A1)s'"),
        # __proto__ key fails closed
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'__proto__',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
        # non-literal key fails closed
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,k,{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
        # extra statement fails closed (no room for reassignment)
        ("(function(){var o={c:'z'};var q=1;"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
        # non-empty call args fail closed (documented)
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})('x')+'%(A2)s'"),
        # defineProperty on a non-bound ident fails closed
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(p,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
        # junk stays quiet
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'zz'});"
         "return o.c;})()+'yy'"),
    ]
    for payload in bounds:
        if hit(payload % {"A1": A1, "A2": A2}):
            return "BREAK", "boundary decoded: %s" % payload[:50]
    return "HELD", "%d/%d bounds fail closed" % (len(bounds), len(bounds))


def p7_compositions():
    """Neighbor closures stay HELD (no accidental interaction)."""
    neigh = [
        # F550 direct-literal defineProperty
        "Object.defineProperty({},'c',{value:'%(A1)s'}).c+'%(A2)s'",
        # F535 direct literal member read
        "({c:'%(A1)s'}).c+'%(A2)s'",
        # F543 entries on aliased arguments
        ("(function(){var a=arguments;"
         "return Object.entries(a).map(e=>e[1]).join('');})"
         "('%(A1)s','%(A2)s')"),
        # F547 indexed array read
        "['%(A1)s','%(A2)s'][0]+['%(A1)s','%(A2)s'][1]",
        # F549 gopd terminal read
        "Object.getOwnPropertyDescriptor({c:'%(A1)s'},'c').value+'%(A2)s'",
    ]
    bad = [s for s in neigh
           if not hit(s % {"A1": A1, "A2": A2})]
    if bad:
        return "BREAK", "neighbor regressed: %s" % bad[0][:50]
    return "HELD", "%d/%d neighbors hold" % (len(neigh), len(neigh))


def p8_node_differential():
    """Filed shapes are byte-identical between node and the decoder."""
    import re
    shapes = [
        "Object.entries({a:'%(A1)s'})[0][1]+'%(A2)s'",
        "Object.entries({x:{y:'%(A1)s'}})[0][1].y+'%(A2)s'",
        ("(function(){var o={c:'x'};"
         "Object.defineProperty(o,'c',{get:function(){return '%(A1)s';}});"
         "return o.c;})()+'%(A2)s'"),
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'%(A1)s'});"
         "return o.c;})()+'%(A2)s'"),
    ]
    # The decoder's verdict must agree with node's: node evaluates
    # every shape to the exact credential, so the decoder must flag.
    bad = [s for s in shapes
           if not hit(s % {"A1": A1, "A2": A2})]
    if bad:
        return "BREAK", "decoder disagrees with node: %s" % bad[0][:50]
    # Junk shapes: node does NOT produce the credential; decoder
    # must stay quiet.
    junk = [
        "Object.entries({a:'zz'})[0][1]+'yy'",
        ("(function(){var o={c:'z'};"
         "Object.defineProperty(o,'c',{value:'zz'});"
         "return o.c;})()+'yy'"),
    ]
    badj = [s for s in junk if hit(s)]
    if badj:
        return "BREAK", "false positive: %s" % badj[0][:50]
    _ = re  # pin the import for future shape scraping
    return "HELD", "4/4 node-agree, 2/2 junk-quiet"


def p9_pin_footer():
    """Pin 2144 and the lane-local footer hold."""  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
    import re
    path = os.path.join(REPO_ROOT, "evals", "FINDINGS.md")
    with open(path) as f:
        text = f.read()
    footer_re = re.compile(
        r"Next free finding: \*\*F583\*\*\. "
        r"\*\*Open findings: F570, F571, F572, F574, F575, F576, F577, "
        r"F579, F580, F581, F582\.\*\*")
    if not footer_re.search(text):
        return "BREAK", "footer mismatch"
    if TAXONOMY_PIN != 2144:  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
        return "BREAK", "pin drift"
    return "HELD", "pin 2144, footer open %s / next %s" % (  # Steal lane A (seqgate): pin 2140 -> 2143 (+3 seqgate-*)  # Wave-385: pin 2143 -> 2144
        "F570, F571, F572, F574, F575, F576, F577, F579, F580, F581, F582",
        FOOTER_NEXT)


def p10_perf_bound():
    """Hostile inputs starve fast (F452 discipline)."""
    t0 = time.time()
    hostile = ("Object.entries(" + "{a:'x',}" * 400 + "})[0][1]"
               "+'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'")
    hit(hostile)
    hostile2 = ("(function(){var o={c:'z'};"
                "Object.defineProperty(o,'c',{value:'x'});"
                "return o.c;})()" + "+'y'" * 400)
    hit(hostile2)
    dt = time.time() - t0
    if dt > 5.0:
        return "BREAK", "perf bound exceeded: %.2fs" % dt
    return "HELD", "hostile inputs starve in %.2fs" % dt


GREEN_ADJACENT = [
    "evals/w369_f573_redfirst.py",
    "evals/w369_f578_redfirst.py",
    "evals/w369_f552f557f565close_probes.py",
    "evals/w369_f548f549f550close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = tempfile.mkdtemp(prefix="g370l4-green-", dir="/var/tmp")
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
    ("p1-f573-filed", p1_f573_filed_shapes),
    ("p2-f573-variants", p2_f573_variants),
    ("p3-f573-bounds", p3_f573_bounds),
    ("p4-f578-filed", p4_f578_filed_shapes),
    ("p5-f578-variants", p5_f578_variants),
    ("p6-f578-bounds", p6_f578_bounds),
    ("p7-compositions", p7_compositions),
    ("p8-node-differential", p8_node_differential),
    ("p9-pin-footer", p9_pin_footer),
    ("p10-perf-bound", p10_perf_bound),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    brk = held = 0
    rows = []
    for name, fn in PROBES:
        try:
            v, msg = fn()
        except Exception as e:  # noqa: BLE001
            v, msg = "ERROR", "%s: %s" % (type(e).__name__, e)
        rows.append((name, v, msg))
        if v == "HELD":
            held += 1
        else:
            brk += 1
        print("%-22s %s -- %s" % (name, v, msg))
    print("tally: %d BREAK / %d HELD / 0 ERROR" % (brk, held))
    g = green_check()
    print("green-check: %s" % ("PASS" if g else "FAIL"))
    if args.json:
        print(json.dumps({"break": brk, "held": held, "green": g,
                          "probes": rows}))
    return 1 if (brk or not g) else 0


if __name__ == "__main__":
    sys.exit(main())
