#!/usr/bin/env python3
"""Wave-372 lane 1 close battery: F597 flatMap scalar-returning callbacks.

F597 (LOW, filed wave-371 lane 8): flatMap with non-array-returning
callbacks bypasses the bounded static JS-expression decoder -- F574
(wave-370 lane 5) modeled only the identity callback `x=>[x]`.
This lane extends the flatMap branch with scalar-returning callbacks
(node-verified, v24.20.0): identity-scalar `(x)=>x` (bare/(x)/
block/function twins) and conditional-scalar
`(c)=>c==='lit'?'a':c|'b'` (+ twins); flatMap is map + flat(1), so
the mapped list is flattened one level. The F574 `x=>[x]` grammar is
tried first (disjoint: `[` vs scalar after the return); non-`===`
comparisons, extra params, and template literals fail closed.

All probes print HELD on the closed tree (green), BREAK on the open
tree for the filed shapes. Node differential shells to node v24.20.0
at runtime. No paid API calls (grep-verified $0).
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

# Concatenated: the write path redacts credential literals.
_A1 = "xoxb-" + "0123"          # len 9
_A2 = "456789" + "abcdef"       # len 12

TAXONOMY_PIN = 2140  # Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ------------------------------------------------------------- P1: filed
def p1_f597_filed_shapes():
    shapes = [
        "[['%s'],['%s']].flatMap((x)=>x).join('')" % (_A1, _A2),
        "['%s','%s'].flatMap((x)=>x).join('')" % (_A1, _A2),
        "['%s','%s'].flatMap((c)=>c==='x'?'x':c).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ------------------------------------------------------------- P2: variants
def p2_f597_variants():
    shapes = [
        # bare-param identity
        "['%s','%s'].flatMap(x=>x).join('')" % (_A1, _A2),
        # block-body identity twin
        "['%s','%s'].flatMap((x)=>{return x;}).join('')" % (_A1, _A2),
        # function-form identity twin (named)
        "['%s','%s'].flatMap(function f(x){return x;}).join('')"
        % (_A1, _A2),
        # ws-tolerant
        "['%s','%s'].flatMap(( x ) => x ).join('')" % (_A1, _A2),
        # nested receiver: map keeps arrays, flat(1) flattens
        "[['%s'],['%s']].flatMap(x=>x).join('')" % (_A1, _A2),
        # conditional block twin
        "['%s','%s'].flatMap((c)=>{return c==='x'?'x':c;}).join('')"
        % (_A1, _A2),
        # conditional function twin
        "['%s','%s'].flatMap(function(c){return c==='x'?'x':c;}).join('')"
        % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    # conditional shapes that decode to non-credential values: assert
    # exact node values to prove the condition ran.
    exact1 = "['%s','%s'].flatMap((c)=>c==='%s'?'Q':'Z').join('')" \
        % (_A1, _A2, "nope-never-matches")
    exact2 = "['%s','%s'].flatMap((c)=>c==='%s'?'Q':c).join('')" \
        % (_A2, _A1, _A2)
    exact_ok = _decode(exact1) == "ZZ" and _decode(exact2) == "Q" + _A1
    ok = not bad and exact_ok
    return ("HELD" if ok else "BREAK",
            "%d/%d variants blocked, exact-cond=%s"
            % (len(shapes) - len(bad), len(shapes), exact_ok))


# ------------------------------------------------------------- P3: bounds
def p3_f597_bounds():
    bounds = [
        # additive return: not ident/cond -- fail closed
        "['%s','%s'].flatMap((x)=>x+x).join('')" % (_A1, _A2),
        # extra callback param -- fail closed
        "['%s','%s'].flatMap((x,i)=>x).join('')" % (_A1, _A2),
        # non-strict comparison -- fail closed
        "['%s','%s'].flatMap((c)=>c=='x'?'x':c).join('')" % (_A1, _A2),
        # template literal in then -- fail closed
        "['%s','%s'].flatMap((c)=>c==='x'?`x`:c).join('')" % (_A1, _A2),
        # hole: engine skips, decoder cannot -- fail closed
        "[,'%s'].flatMap((x)=>x).join('')" % _A1,
        # null marker: fail closed (F574 precedent)
        "[null,'%s'].flatMap((x)=>x).join('')" % _A1,
        # non-array receiver -- fail closed
        "'%s'.flatMap((x)=>x)" % _A1,
        # wrong-param return -- fail closed
        "['%s','%s'].flatMap((x)=>y).join('')" % (_A1, _A2),
    ]
    bad = [s for s in bounds if not _misses(s)]
    # _JSNumStr is never === a string literal (node: 5 !== '5');
    # the decoder must agree exactly, not just fail closed.
    num = "[5].flatMap((c)=>c==='5'?'A':'B').join('')"
    num_ok = _decode(num) == "B"
    ok = not bad and num_ok
    return ("HELD" if ok else "BREAK",
            "%d/%d bounds fail closed, numstr-exact=%s"
            % (len(bounds) - len(bad), len(bounds), num_ok))


# ------------------------------------------------------------- P4: compositions
def p4_compositions():
    held = [
        # F574: flat depth>1 still modeled
        "[['%s'],['%s']].flat(1).join('')" % (_A1, _A2),
        # F553: bound reduce still modeled (F554 bound-flatMap
        # misses on the base tree -- pre-existing scope, not F597)
        "[].reduce.bind(['%s','%s'],(a,b)=>a+b)()" % (_A1, _A2),
    ]
    bad = [s for s in held if not _blocked(s)]
    # F574: [x]=>[x] identity still the IDENTITY on nested arrays
    # (must NOT over-flatten: '1,2,3', not '12,3').
    ident = "[1,[2,3]].flatMap(x=>[x]).join(',')"
    ident_ok = _decode(ident) == "1,2,3"
    # F597 result chains: scalar flatMap then flat
    chain = "[['%s'],['%s']].flatMap((x)=>x).flat(0).join('')" % (_A1, _A2)
    chain_ok = _blocked(chain)
    ok = not bad and ident_ok and chain_ok
    return ("HELD" if ok else "BREAK",
            "neighbors blocked %d/%d, f574-ident=%s, chain=%s"
            % (len(held) - len(bad), len(held), ident_ok, chain_ok))


# ------------------------------------------------------------- P5: node differential
_NODE_CASES = [
    ("[A1,A2].flatMap((x)=>x).join('')",
     "['%s','%s'].flatMap((x)=>x).join('')", (_A1, _A2)),
    ("[[A1],[A2]].flatMap((x)=>x).join('')",
     "[['%s'],['%s']].flatMap((x)=>x).join('')", (_A1, _A2)),
    ("[A1,A2].flatMap((c)=>c==='x'?'x':c).join('')",
     "['%s','%s'].flatMap((c)=>c==='x'?'x':c).join('')", (_A1, _A2)),
    ("[A1,A2].flatMap(x=>x).join('')",
     "['%s','%s'].flatMap(x=>x).join('')", (_A1, _A2)),
    ("[A1,A2].flatMap((x)=>{return x;}).join('')",
     "['%s','%s'].flatMap((x)=>{return x;}).join('')", (_A1, _A2)),
    ("[A1,A2].flatMap(function(x){return x;}).join('')",
     "['%s','%s'].flatMap(function(x){return x;}).join('')", (_A1, _A2)),
    ("[A2,A1].flatMap((c)=>c===A2?'Q':c).join('')",
     "['%s','%s'].flatMap((c)=>c==='%s'?'Q':c).join('')",
     (_A2, _A1, _A2)),
    ("[5].flatMap((c)=>c==='5'?'A':'B').join('')",
     "[5].flatMap((c)=>c==='5'?'A':'B').join('')", ()),
    ("[[A1],[A2]].flatMap((c)=>c==='x'?'x':c).join('')",
     "[['%s'],['%s']].flatMap((c)=>c==='x'?'x':c).join('')", (_A1, _A2)),
]


def p5_node_differential():
    node_src = "const A1=%s,A2=%s;const out=[%s];console.log(JSON.stringify(out));" % (
        json.dumps(_A1), json.dumps(_A2),
        ",".join("(%s)" % node_t for node_t, _, _ in _NODE_CASES))
    r = subprocess.run(["node", "-e", node_src], capture_output=True,
                       text=True, timeout=60, cwd=REPO_ROOT)
    if r.returncode != 0:
        return ("ERROR", "node failed: %s" % r.stderr[:200])
    node_vals = json.loads(r.stdout)
    mismatches = []
    for (node_t, pay_t, args), node_val in zip(_NODE_CASES, node_vals):
        payload = pay_t % args if args else pay_t
        got = _decode(payload)
        if got != node_val:
            mismatches.append("%s: node=%r got=%r" % (node_t, node_val, got))
    if mismatches:
        return ("BREAK", "%d decoder/node mismatches: %s"
                % (len(mismatches), "; ".join(mismatches)))
    return ("HELD", "%d/%d decoder agrees with node v24.20.0"
            % (len(_NODE_CASES), len(_NODE_CASES)))


# ------------------------------------------------------------- P6: pin/footer
def p6_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F655**" in text  # Wave-372 merge: footer repoint next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
          and "**Open findings: F644, F645, F646, F647, F648, F649, F650, F651, F652, F653, F654.**"  # Wave-372 merge: footer repoint  # Wave-373 lane 4: F608 CLOSED  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 2: F613 CLOSED  # Wave-374 merge: footer repoint open F621-F635 / next F636  # Wave-374 merge: footer repoint open F621-F639 / next F640 # Wave-376 merge: F640-F643 CLOSED; F644-F654 OPEN (next F655)
              in text
          and "**Status: CLOSED 2026-10-07 wave-372 lane 1." in text)
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P7: perf bound
def p7_perf_bound():
    # Hostile input: many scalar flatMap anchors -- must starve fast
    # (F452 lesson: fail-closed matches must consume scan budget).
    junk = ("['ab','cd'].flatMap((x)=>x).join('')"
            "['ab'].flatMap((c)=>c==='q'?'q':c).join('')"
            "['ab'].flatMap((x)=>x+x).join('')") * 700
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2100-anchor scalar-flatMap corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w371_f597_redfirst.py",
    "evals/w370_f574f580close_probes.py",
    "evals/w369_f574_redfirst.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g372l1-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=600, env=env, cwd=REPO_ROOT)
            line = [l for l in r.stdout.splitlines() if "tally:" in l]
            print("green %-38s -> %s (%.1fs)" % (rel,
                                                 line[-1] if line else "rc=%d" % r.returncode,
                                                 time.time() - t0))
            if r.returncode != 0:
                ok = False
        except Exception as e:  # noqa: BLE001
            print("green %-38s -> ERROR %s" % (rel, e))
            ok = False
    return ok


PROBES = [
    ("p1-f597-filed", p1_f597_filed_shapes),
    ("p2-f597-variants", p2_f597_variants),
    ("p3-f597-bounds", p3_f597_bounds),
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
        if args.probe and name != args.probe:
            continue
        try:
            verdict, msg = fn()
        except Exception as e:  # noqa: BLE001
            verdict, msg = "ERROR", "%s: %s" % (type(e).__name__, e)
        print("%-22s %s: %s" % (name, verdict, msg))
        if verdict == "BREAK":
            breaks += 1
        elif verdict == "HELD":
            held += 1
        else:
            errors += 1
    if args.probe is None:
        print("green checks:")
        gok = green_check()
        print("tally: %d BREAK / %d HELD / %d ERROR" % (breaks, held, errors))
        if breaks or errors or not gok:
            sys.exit(1)


if __name__ == "__main__":
    main()
