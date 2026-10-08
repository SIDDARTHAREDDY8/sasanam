#!/usr/bin/env python3
"""Wave-371 lane 3 close probes: F585 (structuredClone of Map objects),
F586 (parenthesized new-expression receivers).

F585: F536 closed structuredClone laundering for plain objects/arrays,
but a cloned Map is still a Map: structuredClone(new Map([['c','f1']]))
.get('c')+'f2' and the two-entry variant node-evaluate to the exact
credential (v24.20.0) with zero decoder variants. Closed by threading
the F563 literal-Map parse through the structuredClone branch: the
result is a fresh _JSMap (dict-copied, no aliasing; string values in
the F563 grammar make the copy a true deep copy) resolved by the F563
.get postfix branch. The parenthesized-argument spelling
structuredClone((new Map(...))) composes with F586. Every other arg
class (Set, array, non-literal, WeakRef -- the engine throws
DataCloneError) fails closed (documented).

F586: the decoder modeled `new Map(...)` and `new WeakRef(...)`
receivers only unparenthesized: (new Map([['c','f1']])).get('c')+'f2'
and (new WeakRef({c:'f1'})).deref().c+'f2' node-evaluate to the exact
credential (v24.20.0) with zero decoder variants. Closed by
_js_parse_f586_grouped_new: the parenthesized new-expression is
engine-identical to the bare form, so the inner F563/F539 parse runs
unchanged and the member chain resolves through the existing postfix
branches. The whole-text scan retries at the grouping paren
(_try_js_expr_decode_f586) only where the plain decode failed closed,
so no previously-decodable input changes its variant. Grouping-paren
guard (F535 precedent, whitespace-tolerant): a `(` preceded past
whitespace by an identifier char, `)`, or `]` is a call's argument
paren -- fn(new Map(...)).get('c') keeps failing closed, because the
.get reads the CALL's unknown result. Nested parens ((new Map(...)))
recurse depth-bounded; the WeakRef .deref() sits outside the grouping
paren in the filed shape and is consumed after the outermost close.

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


# ------------------------------------------------------------- P1: F585 filed
def p1_f585_filed_shapes():
    shapes = [
        "structuredClone(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        "structuredClone(new Map([['a','%(A1)s'],['b','%(A2)s']])).get('a')"
        "+structuredClone(new Map([['a','%(A1)s'],['b','%(A2)s']])).get('b')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P2: F585 variants
def p2_f585_variants():
    shapes = [
        # parenthesized argument (F585 x F586 composition)
        "structuredClone((new Map([['c','%(A1)s']]))).get('c')+'%(A2)s'",
        # whitespace tolerance
        "structuredClone( new Map( [ [ 'c' , '%(A1)s' ] ] ) ).get( 'c' )"
        "+'%(A2)s'",
        # duplicate keys: later wins (node-exact, F563 grammar)
        "structuredClone(new Map([['c','zz'],['c','%(A1)s']])).get('c')"
        "+'%(A2)s'",
        # numeric keys stay distinct from string keys (SameValueZero)
        "structuredClone(new Map([[1,'%(A1)s']])).get(1)+'%(A2)s'",
        # empty map then missing key fails closed, but the two-entry
        # map with both keys read blocks (A1+A2 order for the rule)
        "structuredClone(new Map([['c','%(A1)s'],['d','%(A2)s']])).get('c')"
        "+structuredClone(new Map([['c','%(A1)s'],['d','%(A2)s']])).get('d')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    return "HELD", "%d variants block" % len(shapes)


# ------------------------------------------------------------ P3: F585 bounds
def p3_f585_bounds():
    # All fail closed (documented scope boundaries).
    shapes = [
        # Set is not a modeled clone target
        "structuredClone(new Set(['%(A1)s']))",
        # array arg still fails closed (F536 boundary unchanged)
        "structuredClone(['%(A1)s'])",
        # non-literal map entries fail closed
        "structuredClone(new Map([[x,'%(A1)s']])).get('c')+'%(A2)s'",
        # WeakRef: the engine throws DataCloneError (node-verified)
        "structuredClone(new WeakRef({c:'%(A1)s'}))",
        # missing key: the engine yields undefined (never decoded)
        "structuredClone(new Map([['c','%(A1)s']])).get('zz')+'%(A2)s'",
        # empty map: nothing to resolve
        "structuredClone(new Map()).get('c')+'%(A2)s'",
        # junk-quiet: no credential, no block
        "structuredClone(new Map([['c','ab']])).get('c')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, False)
        if v != "HELD":
            return v, "bound: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------------- P4: F586 filed
def p4_f586_filed_shapes():
    shapes = [
        "(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        "(new WeakRef({c:'%(A1)s'})).deref().c+'%(A2)s'",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "filed: " + m
    return "HELD", "%d filed shapes block" % len(shapes)


# ---------------------------------------------------------- P5: F586 variants
def p5_f586_variants():
    shapes = [
        # doubly-grouped parens (engine-identical)
        "((new Map([['c','%(A1)s']]))).get('c')+'%(A2)s'",
        "((new WeakRef({c:'%(A1)s'}))).deref().c+'%(A2)s'",
        # whitespace tolerance
        "( new Map( [ [ 'c' , '%(A1)s' ] ] ) ).get( 'c' )+'%(A2)s'",
        # grouping paren after an operator
        "x=(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        # two-entry map, second key
        "(new Map([['a','zz'],['b','%(A1)s']])).get('b')+'%(A2)s'",
        # numeric key through the grouped form
        "(new Map([[1,'%(A1)s']])).get(1)+'%(A2)s'",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "variant: " + m
    return "HELD", "%d variants block" % len(shapes)


# ------------------------------------------------------------ P6: F586 bounds
def p6_f586_bounds():
    # All fail closed (documented scope boundaries).
    shapes = [
        # call-argument paren: the .get reads the CALL's unknown result
        "fn(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        # whitespace between callee and paren is still a call (engine)
        "fn (new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        "x(new WeakRef({c:'%(A1)s'})).deref().c+'%(A2)s'",
        # new Proxy keeps its F535 shape (disjoint ownership)
        "(new Proxy({c:'%(A1)s'},{}))",
        # bare grouped map is not obfuscation-shaped (no member read)
        "(new Map([['c','%(A1)s']]))",
        # grouped WeakRef without .deref() is not a decodable value
        "(new WeakRef({c:'%(A1)s'}))",
        # misspelled deref
        "(new WeakRef({c:'%(A1)s'})).deref2().c+'%(A2)s'",
        # missing key: the engine yields undefined (never decoded)
        "(new Map([['c','%(A1)s']])).get('zz')+'%(A2)s'",
        # missing the Map's OWN close paren: genuinely undecodable
        # (the inner new-expression never parses; the scanner's inner
        # anchors yield no credential variant)
        "(new Map([['c','%(A1)s']].get('c')+'%(A2)s'",
        # junk-quiet: no credential, no block
        "(new Map([['c','ab']])).get('c')",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, False)
        if v != "HELD":
            return v, "bound: " + m
    return "HELD", "%d bounds fail closed" % len(shapes)


# ------------------------------------------------------- P7: compositions
def p7_compositions():
    # Neighbors stay HELD: the unparenthesized forms and F536 keep
    # blocking; the new branches change no previously-decoded input.
    shapes = [
        # F536: plain-object structuredClone still blocks
        "structuredClone({c:'%(A1)s'}).c+'%(A2)s'",
        # F563: unparenthesized Map still blocks
        "new Map([['c','%(A1)s']]).get('c')+'%(A2)s'",
        # F539: unparenthesized WeakRef still blocks
        "new WeakRef({c:'%(A1)s'}).deref().c+'%(A2)s'",
        # pre-existing decodes are byte-identical: a grouped map in a
        # larger concatenation decodes exactly like the unparen form
        "'x'+(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'",
        # structuredClone of a Map composes with concatenation tails
        "structuredClone(new Map([['c','%(A1)s']])).get('c')+'%(A2)s'+'!'",
    ]
    for s in shapes:
        v, m = _verdict(s % {"A1": _A1, "A2": _A2}, True)
        if v != "HELD":
            return v, "composition: " + m
    return "HELD", "%d compositions block" % len(shapes)


_DIFF_CASES = [
    "structuredClone(new Map([['c','f1']])).get('c')+'f2'",
    "structuredClone(new Map([['a','f1'],['b','f2']])).get('b')+'!'",
    "structuredClone((new Map([['c','f1']]))).get('c')+'f2'",
    "(new Map([['c','f1']])).get('c')+'f2'",
    "((new Map([['c','f1']]))).get('c')+'f2'",
    "(new WeakRef({c:'f1'})).deref().c+'f2'",
    "((new WeakRef({c:'f1'}))).deref().c+'f2'",
    "'x'+(new Map([['c','f1']])).get('c')+'f2'",
]


# --------------------------------------------------- P8: node differential
def p8_node_differential():
    node_src = "let out=[];\n" + "\n".join(
        "try{out.push(JSON.stringify((%s)));}catch(e){out.push('THROWS');}"
        % c for c in _DIFF_CASES)
    r = subprocess.run(["node", "-e",
                        "%s;console.log(JSON.stringify(out));" % node_src],
                       capture_output=True, text=True, timeout=60,
                       cwd=REPO_ROOT)
    node_vals = json.loads(r.stdout)
    bad = []
    for c, nv in zip(_DIFF_CASES, node_vals):
        variants = dlp._try_js_expr_decode_all(c) or []
        want = json.loads(nv)
        if want not in variants:
            bad.append((c, want, variants[:4]))
    if bad:
        return "BREAK", "differential diffs: %r" % (bad,)
    return "HELD", "%d/%d node-exact" % (len(_DIFF_CASES),
                                         len(_DIFF_CASES))


# ---------------------------------------------------------- P9: pin + footer
def p9_pin_footer():
    assert TAXONOMY_PIN == 2140, "pin moved"  # Watcher v1 merge: 2135 -> 2140
    from gov import guac_graph  # noqa: E402
    assert guac_graph.TAXONOMY_PIN == 2140, \
        "guac_graph.TAXONOMY_PIN=%r want 2140" % (guac_graph.TAXONOMY_PIN,)
    text = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("Next free finding: **F612**" in text  # Wave-372 merge: footer repoint next F612
          and "**Open findings: F606, F607, F608, F609, F610, F611.**" in text  # Wave-372 merge: footer repoint open F606-F611 / next F612
          # Wave-371 lane 3: F585/F586 CLOSED; F583/F584/F587-F596 OPEN
          and text.count("**Status: CLOSED 2026-10-07 wave-371 lane 3.**")
              == 2)
    return ("HELD" if ok else "BREAK", "pin+footer")


# ---------------------------------------------------------- P10: perf bound
def p10_perf_bound():
    # The F586 shift adds at most one extra bounded decode attempt per
    # `new` anchor; the hostile corpus must stay under the P5 5s pin.
    corpus = ("\"fn(new Map([['c','x']])).get('c')\";" * 40 +
              "\"(new Map([['c','x']])).get('c')\";" * 40)
    t0 = time.time()
    dlp.find_credential(corpus)
    dt = time.time() - t0
    ok = dt < 5.0
    return ("HELD" if ok else "BREAK", "corpus %.2fs" % dt)


GREEN_ADJACENT = [
    "evals/w370_f585_redfirst.py",
    "evals/w370_f586_redfirst.py",
    "evals/w370_attack_probes.py",
]


def green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for rel in GREEN_ADJACENT:
        path = os.path.join(REPO_ROOT, rel)
        tmpd = "/var/tmp/g371lane3-green-%d" % abs(hash(rel))
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
    ("p1-f585-filed", p1_f585_filed_shapes),
    ("p2-f585-variants", p2_f585_variants),
    ("p3-f585-bounds", p3_f585_bounds),
    ("p4-f586-filed", p4_f586_filed_shapes),
    ("p5-f586-variants", p5_f586_variants),
    ("p6-f586-bounds", p6_f586_bounds),
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
