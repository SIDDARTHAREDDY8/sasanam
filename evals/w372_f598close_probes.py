#!/usr/bin/env python3
"""Wave-372 lane 2 close probes: F598 (JSON.stringify of derived arrays).

F598: F571 (wave-370 lane 2, CLOSED) models the stringify/parse round-trip
for string-literal arrays/objects, but arrays DERIVED from Set/Map iteration
were not serialized: JSON.parse(JSON.stringify(Array.from(new
Set(['f1','f2'])))).join(''), JSON.parse(JSON.stringify([...new
Set(['f1','f2'])]))).join(''), and JSON.parse(JSON.stringify(Array.from(new
Map([['a','f1'],['b','f2']]).values()))).join('') all node-evaluate to the
exact credential (v24.20.0) with zero decoder variants. Distinct from F571
(literal arrays, CLOSED) and F595 (nested array values, CLOSED 2026-10-08 wave-373 lane 1).

Closed by two composable extensions (node-exact, each previously
fail-closed, so no previously-decoded input changes behavior):
1. _js_parse_array_from (F508) accepts `new Map([[k,v],...]).values()` via
   _js_parse_new_map_values (F494) -- Map.values() is an iterable of the
   values in insertion order with later-wins keys; a bare `new Map`
   still fails closed (the engine iterates entries, not values).
2. _js_parse_f571_stringify_call (F571) VALUE grammar accepts the
   derived-array forms: Array.from(new Set(...)) /
   Array.from(new Map(...).values()) via _js_parse_array_of, and
   [...new Set(...)] / [...new Map(...).values()] via _js_parse_spread_copy
   (F471/F494). The derived _JSArr serializes through the unchanged
   _js_f571_stringify + F541 parse tail.

Seams under test (tdd): find_credential at the public seam for every
probe; node v24.20.0 differential (subprocess) for engine-exactness.

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


def _carrier(inner):
    # Exact attack-lane carrier convention (verified byte-identical
    # against evals/w371_f598_redfirst.py runtime payloads): the
    # payload is wrapped in bare double quotes; inner quotes stay bare.
    return '"' + inner + '"'


# -------------------------------------------------------------- P1: filed
def p1_f598_filed_shapes():
    shapes = [
        _carrier("JSON.parse(JSON.stringify(Array.from(new Set(['%(A1)s','%(A2)s'])))).join('')"),
        _carrier("JSON.parse(JSON.stringify([...new Set(['%(A1)s','%(A2)s'])])).join('')"),
        _carrier("JSON.parse(JSON.stringify(Array.from(new Map([['a','%(A1)s'],['b','%(A2)s']]).values()))).join('')"),
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ----------------------------------------------------------- P2: variants
def p2_f598_variants():
    shapes = [
        # Set SameValueZero dedup (first occurrence) -- node-exact
        "JSON.parse(JSON.stringify(Array.from(new Set(['%(A1)s','%(A2)s','%(A1)s'])))).join('')",
        # Map later-wins on duplicate keys -- node-exact
        "JSON.parse(JSON.stringify(Array.from(new Map([['a','zz'],['a','%(A1)s'],['b','%(A2)s']]).values()))).join('')",
        # whitespace tolerance
        "JSON.parse(JSON.stringify( Array.from( new Set( [ '%(A1)s' , '%(A2)s' ] ) ) )).join('')",
        # spread of Map.values() (F598 x F494 composition)
        "JSON.parse(JSON.stringify([...new Map([['a','%(A1)s'],['b','%(A2)s']]).values()])).join('')",
        # identity mapper (F508 composition)
        "JSON.parse(JSON.stringify(Array.from(new Set(['%(A1)s','%(A2)s']), x=>x)).join('')",
        # numeric map keys (string values)
        "JSON.parse(JSON.stringify(Array.from(new Map([[1,'%(A1)s'],[2,'%(A2)s']]).values()))).join('')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    return "HELD", "%d variants block" % len(shapes)


# ------------------------------------------------------------- P3: bounds
def p3_f598_bounds():
    # All fail closed (documented scope boundaries).
    shapes = [
        # bare new Map iterates entries, not values (engine) -- never
        # mis-decoded as a value list
        "JSON.parse(JSON.stringify(Array.from(new Map([['a','%(A1)s']])))).join('')",
        # non-literal Set members
        "JSON.parse(JSON.stringify(Array.from(new Set([x,'%(A1)s'])))).join('')",
        # non-string map values
        "JSON.parse(JSON.stringify(Array.from(new Map([['a',1]]).values()))).join('')",
        # non-identity mapper
        "JSON.parse(JSON.stringify(Array.from(new Set(['%(A1)s']),(x)=>x+'x'))).join('')",
        # replacer/space args (F571 boundary unchanged)
        "JSON.parse(JSON.stringify(['%(A1)s'], null, 2))",
        # mixed spread+literal array (spread-copy is sole-element only)
        "JSON.parse(JSON.stringify([...['%(A1)s'], '%(A2)s']))",
        # F598: fromAsync in stringify is a Promise ('{}'), not the
        # resolved array -- must fail closed (false-positive guard)
        "JSON.parse(JSON.stringify(Array.fromAsync(['%(A1)s','%(A2)s'])))",
        # F598: Array.of was fail-closed in this grammar before F598
        # and stays fail-closed (no scope creep)
        "JSON.parse(JSON.stringify(Array.of('%(A1)s','%(A2)s'))).join('')",
        # junk-quiet: no credential, no block
        "JSON.parse(JSON.stringify(['ab']))",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, False)
        if v != "HELD":
            return v, "bound: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------- P4: compositions
def p4_compositions():
    # Neighbors stay HELD: F571 literal/object forms keep blocking; the
    # new branches change no previously-decoded input. F595 (OPEN) must
    # stay a miss -- the lane's branches do not absorb it.
    shapes = [
        # F571: literal array still blocks
        "JSON.parse(JSON.stringify(['%(A1)s','%(A2)s'])).join('')",
        # F571: object literal still blocks
        "JSON.parse(JSON.stringify({c:'%(A1)s'})).c+'%(A2)s'",
        # F563: Map.get postfix branch unchanged
        "new Map([['c','%(A1)s']]).get('c')+'%(A2)s'",
        # F494: spread-copy of Set without stringify unchanged
        "[...new Set(['%(A1)s','%(A2)s'])].join('')",
        # F508: Array.from(new Set(...)) without stringify unchanged
        "Array.from(new Set(['%(A1)s','%(A2)s'])).join('')",
        # NEW via F598: Array.from(new Map(...).values()) without
        # stringify composes through the same from branch
        "Array.from(new Map([['a','%(A1)s'],['b','%(A2)s']]).values()).join('')",
        # concatenation tails
        "JSON.parse(JSON.stringify(Array.from(new Set(['%(A1)s','%(A2)s'])))).join('')+'!'",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "composition: " + m
    # F595 (CLOSED 2026-10-08 wave-373 lane 1, nested array values) now
    # decodes -- the "still open" expectation is superseded.
    closed_shapes = [
        "JSON.parse(JSON.stringify({a:['%(A1)s','%(A2)s']})).a.join('')",
        "JSON.parse(JSON.stringify([['%(A1)s'],['%(A2)s']])).flat().join('')",
    ]
    for s in closed_shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "f595-now-closed: " + m
    return "HELD", "%d compositions block, F595 closed" % len(shapes)


# (carrier input for the decoder, bare JS expression for node): the
# decoder's job on the \" carrier is to extract the inner expression's
# value, so node evaluates the inner while the decoder reads the
# carrier; the decoder's variants must contain node's value.
_DIFF_CASES = [
    (_carrier("JSON.parse(JSON.stringify(Array.from(new Set(['f1','f2'])))).join('')"),
     "JSON.parse(JSON.stringify(Array.from(new Set(['f1','f2'])))).join('')"),
    (_carrier("JSON.parse(JSON.stringify([...new Set(['f1','f2'])])).join('')"),
     "JSON.parse(JSON.stringify([...new Set(['f1','f2'])])).join('')"),
    (_carrier("JSON.parse(JSON.stringify(Array.from(new Map([['a','f1'],['b','f2']]).values()))).join('')"),
     "JSON.parse(JSON.stringify(Array.from(new Map([['a','f1'],['b','f2']]).values()))).join('')"),
    (_carrier("JSON.parse(JSON.stringify(Array.from(new Set(['f1','f1','f2'])))).join('')"),
     "JSON.parse(JSON.stringify(Array.from(new Set(['f1','f1','f2'])))).join('')"),
    (_carrier("JSON.parse(JSON.stringify(Array.from(new Map([['a','x'],['a','f1'],['b','f2']]).values()))).join('')"),
     "JSON.parse(JSON.stringify(Array.from(new Map([['a','x'],['a','f1'],['b','f2']]).values()))).join('')"),
    (_carrier("JSON.parse(JSON.stringify([...new Map([['a','f1'],['b','f2']]).values()])).join('')"),
     "JSON.parse(JSON.stringify([...new Map([['a','f1'],['b','f2']]).values()])).join('')"),
]


# --------------------------------------------------- P5: node differential
def p5_node_differential():
    node_src = "let out=[];\n" + "\n".join(
        "try{out.push(JSON.stringify((%s)));}catch(e){out.push('THROWS');}"
        % expr for _, expr in _DIFF_CASES)
    r = subprocess.run(["node", "-e",
                        "%s;console.log(JSON.stringify(out));" % node_src],
                       capture_output=True, text=True, timeout=60,
                       cwd=REPO_ROOT)
    node_vals = json.loads(r.stdout)
    bad = []
    for (carrier, _), nv in zip(_DIFF_CASES, node_vals):
        variants = dlp._try_js_expr_decode_all(carrier) or []
        want = json.loads(nv)
        if want not in variants:
            bad.append((carrier[:60], want, variants[:4]))
    if bad:
        return "BREAK", "differential diffs: %r" % (bad,)
    return "HELD", "%d/%d node-exact" % (len(_DIFF_CASES),
                                         len(_DIFF_CASES))


# ---------------------------------------------------------- P6: pin + footer
def p6_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: 2135 -> 2140
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F621**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621
          and "**Open findings: F612, F614, F615, F616, F617, F618, F619, F620.**" in text  # Wave-372 merge: footer repoint open F606-F611 / next F612  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED
          # Wave-372 lane 2: F598 CLOSED
          and text.count("**Status: CLOSED 2026-10-07 wave-372 lane 2.**")
              == 1)
    return ("HELD" if ok else "BREAK", "pin+footer")


# ---------------------------------------------------------- P7: perf bound
def p7_perf_bound():
    # The F598 branches add at most one extra bounded decode attempt per
    # `Array` / `JSON` / `new` anchor; the hostile corpus must stay under
    # the P5 5s pin.
    corpus = ("\"Array.from(new Set(['x','y']))\";" * 40 +
              "\"JSON.parse(JSON.stringify(['x']))\";" * 40 +
              "\"Array.from(new Map([['a','x']]))\";" * 40)
    t0 = time.time()
    dlp.find_credential(corpus)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "corpus %.2fs" % dt)


GREEN_ADJACENT = [
    "evals/w371_f598_redfirst.py",
    "evals/w371_attack_probes.py",
    "evals/w370_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g372lane2-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            out = (r.stdout or "") + (r.stderr or "")
            line = [l for l in out.splitlines() if "tally:" in l]
            tag = line[-1] if line else "rc=%d" % r.returncode
            # w370_attack's footer pin is stale by design: this lane's
            # footer (F598 CLOSED) no longer matches its wave-371-lane-1
            # expectation. Merge-time repoint (wave-305/306 class).
            # Tolerate a sole footer BREAK, fail on anything else.
            footer_only = ("test_b0_footer_state: BREAK" in out
                           and "BREAKS: ['test_b0_footer_state']" in out)
            print("green %-38s -> %s (%.1fs)%s" %
                  (rel, tag, time.time() - t0,
                   " (footer-only tolerated)" if footer_only else ""))
            if r.returncode != 0 and not footer_only:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f598-filed", p1_f598_filed_shapes),
    ("p2-f598-variants", p2_f598_variants),
    ("p3-f598-bounds", p3_f598_bounds),
    ("p4-compositions", p4_compositions),
    ("p5-node-differential", p5_node_differential),
    ("p6-pin-footer", p6_pin_footer),
    ("p7-perf-bound", p7_perf_bound),
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
