#!/usr/bin/env python3
"""Wave-370 lane 5 close probes: F574 (flat depth>1 / flatMap), F580 (sort).

F574: Array.prototype.flat at depth > 1 and flatMap on literal arrays
bypass the bounded static JS-expression decoder -- the decoder modeled
flat() at depth 1 (F466, identity) but not deeper depths or flatMap:
[[['f1']],[['f2']]].flat(Infinity).join(''),
[[['f1']],[['f2']]].flat(2).join(''), and
['f1','f2'].flatMap(x=>[x]).join('') all node-evaluate to the exact
credential (v24.20.0) with zero decoder variants. Closed by extending
the flat branch in _js_apply_method: flat(INTLIT)/flat(Infinity)
recursive-flatten nested _JSArr elements node-exactly
(_js_flatten_f574; depth 0 is the identity, node-verified); a new
flatMap branch models only the identity callback (x=>[x] and the
three F543-precedent forms -- identity flatMap is the IDENTITY on the
array in node v24.20.0: map wraps each element, flat(1) unwraps, net
no-op -- verified [1,[2,3]].flatMap(x=>[x]) === [1,[2,3]], NOT
flat(1) which would give [1,2,3]). Holes and null/undefined/boolean markers fail closed
(the F485 _JSNil marker cannot distinguish an engine-skipped hole
from an engine-kept null literal); non-literal/fractional/negative/
string depths fail closed.

F580: Array.prototype.sort with a comparator on literal arrays
bypasses the decoder -- sort was unmodeled; with a comparator it
reorders literal fragments into credential order:
['f2','f1'].sort((a,b)=>a.length-b.length).join('') node-evaluates to
the exact credential with zero decoder variants. Closed by adding
"sort" to _JS_POSTFIX_METHOD_NAMES with a node-exact branch:
no-arg default sort, and (a,b)=>a.length-b.length modeled as a stable
sort by len() (the comparator is a consistent total preorder on
lengths and V8's sort is stable -- node-verified incl. ties).
Default sort compares UTF-16 code units while Python compares code
points, so any element with an astral char (ord > 0xFFFF) fails closed
(verified divergence: node sorts ["\\uE000","\\U0001F600"] as
["\\U0001F600","\\uE000"], Python as ["\\uE000","\\U0001F600"]).
Any other comparator -- including the descending form, <-comparison
forms, and non-function args (the engine THROWS TypeError on those,
node-verified) -- fails closed. Non-str elements fail closed.

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential for engine-exactness.

Standalone: green checks ON by default; honors GOV_SKIP_GREEN.
"""
import argparse
import os
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import dlp  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
# _A1/_A2: unequal lengths for the length-comparator shapes (filed forms).
_A1 = "xoxb-" + "0123"          # len 9
_A2 = "456789" + "abcdef"       # len 12
# _A3: sorts after _A1 lexicographically, so default sort yields _A1+_A3.
_A3 = "xoxb-" + "9999"          # len 9

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


# ------------------------------------------------------------- P1: F574 filed
def p1_f574_filed_shapes():
    shapes = [
        "[[['%s']],[['%s']]].flat(Infinity).join('')" % (_A1, _A2),
        "[[['%s']],[['%s']]].flat(2).join('')" % (_A1, _A2),
        "['%s','%s'].flatMap(x=>[x]).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ------------------------------------------------------------- P2: F574 variants
def p2_f574_variants():
    shapes = [
        # deeper depth, depth 0 identity, no-arg identity (F466)
        "[[['%s']],[['%s']]].flat(3).join('')" % (_A1, _A2),
        "[[['%s']],[['%s']]].flat(0).join('')" % (_A1, _A2),
        "[[['%s']],[['%s']]].flat().join('')" % (_A1, _A2),
        # flatMap identity: the four modeled forms
        "['%s','%s'].flatMap((x)=>[x]).join('')" % (_A1, _A2),
        "['%s','%s'].flatMap(x=>{return [x];}).join('')" % (_A1, _A2),
        "['%s','%s'].flatMap(function(x){return [x];}).join('')" % (_A1, _A2),
        # bracket-string dispatch is engine-identical (F507)
        "['%s','%s']['flatMap'](x=>[x]).join('')" % (_A1, _A2),
        # ws-tolerant depth
        "[[['%s']],[['%s']]].flat( 2 ).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d variants blocked" % (len(shapes) - len(bad), len(shapes)))


# ------------------------------------------------------------- P3: F574 bounds
def p3_f574_bounds():
    bounds = [
        "['%s','%s'].flat('2').join('')" % (_A1, _A2),      # string depth
        "['%s','%s'].flat(1.5).join('')" % (_A1, _A2),      # fractional depth
        "['%s','%s'].flat(2,3).join('')" % (_A1, _A2),      # extra arg
        "[[['%s']]].flat(Infinityx).join('')" % _A1,       # Infinityx ident
        "['%s','%s'].flatMap(x=>x).join('')" % (_A1, _A2),  # non-identity cb
        "['%s','%s'].flatMap((x,i)=>[x]).join('')" % (_A1, _A2),  # 2-param cb
        "['%s','%s'].flatMap(x=>['q']).join('')" % (_A1, _A2),    # const cb
        "[,'%s'].flat(2).join('')" % _A1,                  # hole: fail closed
        "[null,'%s'].flat(2).join('')" % _A1,              # null: fail closed
        "[true,'%s'].flatMap(x=>[x]).join('')" % _A1,      # bool: fail closed
        "'%s'.flatMap(x=>[x])" % _A1,                      # non-array receiver
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad),
                                          len(bounds)))


# ------------------------------------------------------------- P4: F580 filed
def p4_f580_filed_shapes():
    shapes = [
        "['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_A2, _A1),
        "['%s','%s'].sort((a,b)=>a.length-b.length).join('')" % (_A1, _A2),
        # default sort yielding the credential (lexicographic order)
        "['%s','%s'].sort().join('')" % (_A3, _A1),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ------------------------------------------------------------- P5: F580 variants
def p5_f580_variants():
    shapes = [
        # length comparator with ties: stable, node-verified
        "['bb','aa','c'].sort((a,b)=>a.length-b.length).join(',')",
        # ws-tolerant comparator, renamed params
        "['%s','%s'].sort( (x, y) => x.length - y.length ).join('')"
        % (_A2, _A1),
        # default sort on three elements
        "['%s','%s','%s'].sort().join('')" % (_A3, _A1, "xoxb-5555"),
        # bracket-string dispatch is engine-identical (F507)
        "['%s','%s']['sort']().join('')" % (_A3, _A1),
    ]
    bad = [s for s in shapes
           if dlp._try_js_expr_decode_all(s) is None]
    # the tie shape decodes to 'c,bb,aa' (non-credential, still decoded)
    tie = "['bb','aa','c'].sort((a,b)=>a.length-b.length).join(',')"
    tie_ok = dlp._try_js_expr_decode_all(tie) == "c,bb,aa"
    ok = not bad and tie_ok
    return ("HELD" if ok else "BREAK",
            "%d/%d variants decode, tie-stable=%s"
            % (len(shapes) - len(bad), len(shapes), tie_ok))


# ------------------------------------------------------------- P6: F580 bounds
def p6_f580_bounds():
    bounds = [
        "['%s','%s'].sort((a,b)=>b.length-a.length).join('')" % (_A1, _A2),
        "['%s','%s'].sort((a,b)=>a<b?-1:1).join('')" % (_A1, _A2),
        "['%s','%s'].sort(0).join('')" % (_A1, _A2),       # engine throws
        "['%s','%s'].sort('a').join('')" % (_A1, _A2),     # engine throws
        "['\U0001F600','\U0001F600'].sort().join('')",                    # astral: fail closed
        "['\U0001F600','ab'].sort((a,b)=>a.length-b.length).join('')",  # astral len
        "[1,'%s'].sort().join('')" % _A1,                 # numeric element
        "['%s'].sort().join('')" % _A1,                   # single: no reorder
    ]
    bad = [s for s in bounds if not _misses(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad),
                                          len(bounds)))


# ------------------------------------------------------------- P7: compositions
def p7_compositions():
    # Neighbors must stay HELD; siblings' OPEN findings must still miss.
    held = [
        # F466: flat() identity still the no-arg form
        "[['%s'],['%s']].flat().join('')" % (_A1, _A2),
        # F518: reverse still modeled
        "['%s','%s'].reverse().join('')" % (_A2, _A1),
        # F547: indexed reads compose with flat results
        "[[['%s']],[['%s']]].flat(2)[0]+[[['%s']],[['%s']]].flat(2)[1]"
        % (_A1, _A2, _A1, _A2),
        # F561: toReversed still modeled
        "['%s','%s'].toReversed().join('')" % (_A2, _A1),
        # F553/F554: bound reduce/flatMap targets still modeled
        "[].reduce.bind(['%s','%s'],(a,b)=>a+b)()" % (_A1, _A2),
    ]
    missed_closed = [s for s in held if not _blocked(s)]
    still_open = [
        # F575: String.raw non-array raw object (sibling lane)
        "String.raw({raw:{0:'%s',1:'%s',length:2}})" % (_A1, _A2),
        # F579: Reflect.ownKeys terminal reads (sibling lane)
        "({c:'%s'})[Reflect.ownKeys({c:'%s'})[0]]+'%s'" % (_A1, _A1, _A2),
        # F576: URL laundering (sibling lane)
        "new URLSearchParams('a=%s').get('a')+'%s'" % (_A1, _A2),
    ]
    closed_open = [s for s in still_open if _blocked(s)]
    ok = not missed_closed and not closed_open
    return ("HELD" if ok else "BREAK",
            "neighbors held %d/%d, open stayed open %d/%d"
            % (len(held) - len(missed_closed), len(held),
               len(still_open) - len(closed_open), len(still_open)))


# ------------------------------------------------------------- P8: node differential
_NODE_CASES = [
    # (node expression with bare A1/A2 consts, payload template)
    ("[[[A1]],[[A2]]].flat(Infinity).join('')",
     "[[['%s']],[['%s']]].flat(Infinity).join('')"),
    ("[[[A1]],[[A2]]].flat(2).join('')",
     "[[['%s']],[['%s']]].flat(2).join('')"),
    ("[[[A1]],[[A2]]].flat(3).join('')",
     "[[['%s']],[['%s']]].flat(3).join('')"),
    ("[[[A1]],[[A2]]].flat(0).join('')",
     "[[['%s']],[['%s']]].flat(0).join('')"),
    ("[A1,A2].flatMap(x=>[x]).join('')",
     "['%s','%s'].flatMap(x=>[x]).join('')"),
    ("[A1,A2].flatMap(function(x){return [x];}).join('')",
     "['%s','%s'].flatMap(function(x){return [x];}).join('')"),
    # nested: identity flatMap must NOT over-flatten (node: [[A1],[A2]])
    ("[[A1],[A2]].flatMap(x=>[x]).join(',')",
     "[['%s'],['%s']].flatMap(x=>[x]).join(',')"),
    ("[A2,A1].sort().join('')",
     "['%s','%s'].sort().join('')"),
    ("[A2,A1].sort((a,b)=>a.length-b.length).join('')",
     "['%s','%s'].sort((a,b)=>a.length-b.length).join('')"),
]


def p8_node_differential():
    import json
    node_src = "const A1=%s,A2=%s;const out=[%s];console.log(JSON.stringify(out));" % (
        json.dumps(_A1), json.dumps(_A2),
        ",".join("(%s)" % node_t for node_t, _ in _NODE_CASES))
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=60, cwd=REPO_ROOT)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:200])
    node_vals = json.loads(r.stdout)
    mismatches = []
    for (node_t, pay_t), node_val in zip(_NODE_CASES, node_vals):
        js = pay_t % (_A1, _A2)
        dec = dlp._try_js_expr_decode_all(js)
        # dec is a str (or None); node_val must equal it exactly
        if dec is None or dec != node_val:
            mismatches.append(js[:72])
    if mismatches:
        return ("BREAK", "%d decoder/node mismatches: %s"
                % (len(mismatches), "; ".join(mismatches)))
    return ("HELD", "%d/%d decoder agrees with node v24.20.0"
            % (len(_NODE_CASES), len(_NODE_CASES)))


# ------------------------------------------------------------- P9: pin/footer
def p9_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F597**" in text
          and "**Open findings: F582, F583, F584, F585, F586, F587, F588, F589, F590, F591, F592, F593, F594, F595, F596.**"
              in text  # Wave-370 lane 5: F574/F580 CLOSED; rest OPEN (next F583)
          and "**Status: CLOSED 2026-10-07 wave-370 lane 5." in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # Hostile input: many flat/sort/flatMap anchors -- must starve fast
    # (F452 lesson: fail-closed matches must consume scan budget).
    junk = ("[[['ab']]].flat(999).join('')"
            "['ab','cd'].sort((a,b)=>a<b?-1:1).join('')"
            "['ab'].flatMap(x=>x).join('')") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor flat/sort/flatMap corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w369_f574_redfirst.py",
    "evals/w369_f580_redfirst.py",
    "evals/w369_f547f561f566close_probes.py",
    "evals/w369_f553f554f555f556close_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g370lane5-green-%d" % abs(hash(rel))
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
    ("p1-f574-filed", p1_f574_filed_shapes),
    ("p2-f574-variants", p2_f574_variants),
    ("p3-f574-bounds", p3_f574_bounds),
    ("p4-f580-filed", p4_f580_filed_shapes),
    ("p5-f580-variants", p5_f580_variants),
    ("p6-f580-bounds", p6_f580_bounds),
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
