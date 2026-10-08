#!/usr/bin/env python3
"""Wave-373 lane 3 close battery: F607 filter with non-trivial predicates.

F607 (LOW, filed wave-372 lane 7 as F606, renumbered per wave-272):
Array.prototype.filter with predicate-shaped callbacks bypasses the
bounded static JS-expression decoder -- the decoder modeled filter
only with truthiness/identity predicates (F437/F447/F467/F470/F459).
This lane adds, node-verified (v24.20.0):
  - x!==LIT (non-empty literal) -> spec ("neq", lit): keep every
    element that is not exactly the literal.
  - x.length OP K (F537 grammar, <,<=,>,>=, literal bound) -> spec
    ("plencmp", op, k): keep elements whose UTF-16 .length satisfies
    the comparison.
Both fail closed on mixed-type arrays (F475/F479): node keeps numbers
under !== against a string (1!=='1' is true) and (1).length is
undefined, which the str model cannot reproduce -- never decode.

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

TAXONOMY_PIN = 2140  # Wave-372 merge: pin 2140


def _blocked(payload):
    return dlp.find_credential(payload) is not None


def _misses(payload):
    return dlp.find_credential(payload) is None


def _decode(payload):
    return dlp._try_js_expr_decode_all(payload)


# ------------------------------------------------------------- P1: filed
def p1_f607_filed_shapes():
    shapes = [
        "['%s','%s','xx'].filter(x=>x!=='xx').join('')" % (_A1, _A2),
        "['%s','xx','%s'].filter(function(x){return x!=='xx';}).join('')"
        % (_A1, _A2),
        "['%s','%s',''].filter(x=>x.length>2).join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    return ("HELD" if not bad else "BREAK",
            "%d/%d filed shapes blocked" % (len(shapes) - len(bad),
                                            len(shapes)))


# ------------------------------------------------------------- P2: variants
def p2_f607_variants():
    shapes = [
        # ws-tolerant neq
        "['%s','%s','xx'].filter( x => x !== 'xx' ).join('')" % (_A1, _A2),
        # paren-param neq
        "['%s','%s','xx'].filter((x)=>x!=='xx').join('')" % (_A1, _A2),
        # double-quote literal
        "['%s','%s','xx'].filter(x=>x!==\"xx\").join('')" % (_A1, _A2),
        # function-form ws twin
        "['%s','xx','%s'].filter(function ( x ) { return x !== 'xx' ; })"
        ".join('')" % (_A1, _A2),
        # length >= bound
        "['%s','%s','xx'].filter(x=>x.length>=3).join('')" % (_A1, _A2),
        # paren-param length
        "['%s','%s',''].filter((x)=>x.length>2).join('')" % (_A1, _A2),
        # escaped literal parses node-exactly
        "['%s','%s','xx'].filter(x=>x!=='x\\x78').join('')" % (_A1, _A2),
    ]
    bad = [s for s in shapes if not _blocked(s)]
    # exact-value pins prove the predicate ran (not just "blocked"):
    # length<3 keeps only 'xx' (not a credential -- exact check, not
    # _blocked); neq keeps both fragments; length>2 drops ''.
    exact = (_decode("['%s','%s','xx'].filter(x=>x.length<3).join('')"
                     % (_A1, _A2)) == "xx"
             and _decode("['f1','f2'].filter(x=>x!=='zz').join('')")
             == "f1f2"
             and _decode("['abc',''].filter(x=>x.length>2).join('')")
             == "abc")
    ok = not bad and exact
    return ("HELD" if ok else "BREAK",
            "%d/%d variants blocked, exact=%s"
            % (len(shapes) - len(bad), len(shapes), exact))


# ------------------------------------------------------------- P3: bounds
def p3_f607_bounds():
    bounds = [
        # loose != against a literal -- fail closed (documented)
        "['%s','%s','xx'].filter(x=>x!='xx').join('')" % (_A1, _A2),
        # length loose != -- fail closed
        "['%s','%s',''].filter(x=>x.length!=0).join('')" % (_A1, _A2),
        # fractional bound -- fail closed
        "['%s','%s',''].filter(x=>x.length>2.5).join('')" % (_A1, _A2),
        # non-literal bound -- fail closed
        "['%s','%s',''].filter(x=>x.length>k).join('')" % (_A1, _A2),
        # missing bound -- fail closed
        "['%s','%s',''].filter(x=>x.length>).join('')" % (_A1, _A2),
        # block-body arrow -- fail closed (documented scope)
        "['%s','%s','xx'].filter(x=>{return x!=='xx';}).join('')"
        % (_A1, _A2),
        # three-param arrow -- fail closed
        "['%s','%s','xx'].filter((x,i,a)=>x!=='xx').join('')" % (_A1, _A2),
        # named function -- fail closed (filter grammar, F537 only)
        "['%s','xx','%s'].filter(function f(x){return x!=='xx';}).join('')"
        % (_A1, _A2),
        # mixed-type array under neq: node keeps the number
        # (1!=='zz' is true) -- undecidable, fail closed
        "[1,'%s'].filter(x=>x!=='zz').join('')" % _A1,
        # mixed-type array under plencmp: (1).length is undefined --
        # fail closed
        "[1,'%s'].filter(x=>x.length>0).join('')" % _A1,
        # == comparison -- fail closed
        "['%s','%s','xx'].filter(x=>x=='xx').join('')" % (_A1, _A2),
    ]
    bad = [s for s in bounds if not _misses(s)]
    ok = not bad
    return ("HELD" if ok else "BREAK",
            "%d/%d bounds fail closed" % (len(bounds) - len(bad),
                                          len(bounds)))


# ------------------------------------------------------------- P4: compositions
def p4_compositions():
    held = [
        # F447: empty-literal neq still truthiness
        "['%s','%s',''].filter(x=>x!=='').join('')" % (_A1, _A2),
        # F447: length>0 legacy spec
        "['%s','%s',''].filter(x=>x.length>0).join('')" % (_A1, _A2),
        # F467: null comparisons still constant-true
        "['%s','%s'].filter(x=>x!==null).join('')" % (_A1, _A2),
        # F459: positional predicates still modeled
        "['%s','%s','zz'].filter((x,i)=>i<2).join('')" % (_A1, _A2),
        # F470: match predicate still modeled (both fragments kept)
        "['%s','%s'].filter(x=>x.match(/[a-z]/)).join('')" % (_A1, _A2),
        # F537: bound-filter length-cmp still modeled (shared grammar)
        "Reflect.apply([].filter.bind(['%s','%s','zz'],"
        "function(e){return e.length>2;}),null,[]).join('')" % (_A1, _A2),
        # F607 chains: filtered result feeds join then concat
        "['%s','xx','%s'].filter(x=>x!=='xx').join('').concat('')"
        % (_A1, _A2),
    ]
    bad = [s for s in held if not _blocked(s)]
    # F447 legacy spec-split pin: x.length>0 still ("plen",)
    s1, _ = dlp._js_parse_truthy_body("x.length>0", 0, "x")
    plen_ok = s1[0] == "plen"
    ok = not bad and plen_ok
    return ("HELD" if ok else "BREAK",
            "neighbors blocked %d/%d, plen-legacy=%s"
            % (len(held) - len(bad), len(held), plen_ok))


# ------------------------------------------------------------- P5: node differential
_NODE_CASES = [
    ("[A1,A2,'xx'].filter(x=>x!=='xx').join('')",
     "['%s','%s','xx'].filter(x=>x!=='xx').join('')", (_A1, _A2)),
    ("[A1,'xx',A2].filter(function(x){return x!=='xx';}).join('')",
     "['%s','xx','%s'].filter(function(x){return x!=='xx';}).join('')",
     (_A1, _A2)),
    ("[A1,A2,''].filter(x=>x.length>2).join('')",
     "['%s','%s',''].filter(x=>x.length>2).join('')", (_A1, _A2)),
    ("[A1,A2,'xx'].filter(x=>x.length>=3).join('')",
     "['%s','%s','xx'].filter(x=>x.length>=3).join('')", (_A1, _A2)),
    ("['ab','cd','e'].filter(x=>x.length<2).join('')",
     "['ab','cd','e'].filter(x=>x.length<2).join('')", ()),
    ("['abc',''].filter(x=>x.length>2).join('')",
     "['abc',''].filter(x=>x.length>2).join('')", ()),
    ("['f1','f2'].filter(x=>x!=='zz').join('')",
     "['f1','f2'].filter(x=>x!=='zz').join('')", ()),
    ("[A1,A2].filter(x=>x!=='').join('')",
     "['%s','%s'].filter(x=>x!=='').join('')", (_A1, _A2)),
    ("[A1,'',A2].filter(x=>x.length>0).join('')",
     "['%s','','%s'].filter(x=>x.length>0).join('')", (_A1, _A2)),
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
    ok = ("Next free finding: **F621**" in text  # Wave-373 lane 3: footer next F612  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 7: F620 CLOSED
          and "Open findings: F612, F613, F614, F615, F616, F617, F618, F619." in text  # Wave-373 lane 3: F607 closed  # Wave-373 merge: footer repoint open F612-F620 / next F621  # Wave-374 lane 7: F620 CLOSED
          and "**Status: CLOSED 2026-10-08 wave-373 lane 3." in text)  # Wave-373 lane 3: F607 entry
    return ("HELD" if ok else "BREAK",
            "pin=%s footer=%s" % (TAXONOMY_PIN, ok))


# ------------------------------------------------------------- P7: perf bound
def p7_perf_bound():
    # Hostile input: many filter anchors incl. fail-closed forms --
    # must starve fast (F452 lesson: fail-closed matches must consume
    # scan budget).
    junk = ("['ab','cd'].filter(x=>x!=='zz').join('')"
            "['ab'].filter(x=>x.length>2).join('')"
            "['ab'].filter(x=>x!='zz').join('')"
            "['ab'].filter((x,i,a)=>x!=='zz').join('')") * 500
    t0 = time.monotonic()
    hit = dlp.find_credential(junk)
    dt = time.monotonic() - t0
    ok = (hit is None) and dt < 2.0
    return ("HELD" if ok else "BREAK",
            "2000-anchor filter corpus: hit=%s %.2fs"
            % (hit is not None, dt))


GREEN_ADJACENT = [
    "evals/w372_f607_redfirst.py",
    "evals/w350_f447f448close_probes.py",
    "evals/w353_f467f468close_probes.py",
    "evals/w355_f475close_probes.py",
    "evals/w368_f537f538f542close_probes.py",
    "evals/w372_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g373l3-green-%d" % abs(hash(rel))
        os.makedirs(tmpd, exist_ok=True)
        env = dict(os.environ, TMPDIR=tmpd, GOV_SKIP_GREEN="1")
        t0 = time.time()
        try:
            r = subprocess.run([sys.executable, path], capture_output=True,
                               text=True, timeout=900, env=env, cwd=REPO_ROOT)
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
    ("p1-f607-filed", p1_f607_filed_shapes),
    ("p2-f607-variants", p2_f607_variants),
    ("p3-f607-bounds", p3_f607_bounds),
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
