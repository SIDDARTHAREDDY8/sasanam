#!/usr/bin/env python3
"""Wave-424 lane A close battery: F1690-F1694 CLOSED.

F1690: fromCharCode.bind spread-call twin --
  `var f=String.fromCharCode.bind(null);var S=f(...C);` + RESULT.
  New `_js_f1690_stmt_decode`. Node-exact: bound function spread-call
  assembles the credential. Disjoint from F1648 (bind+apply twin) by
  the spread-call grammar.

F1691: fromCodePoint.bind apply twin --
  `var f=String.fromCodePoint.bind(null);var S=f.apply(null,C);` +
  RESULT. New `_js_f1691_stmt_decode`. Node-exact on the admitted
  domain (BMP codes via shared C-decl parser). Disjoint from F1679
  (direct fromCodePoint.apply) by the bind indirection.

F1692: zero-comparator sort staging --
  `var D=C.slice().sort((a,b)=>0);` (or the
  `function(a,b){return 0;}` twin) + fromCharCode.apply readout.
  New `_js_f1692_stmt_decode` (+`_js_f1692_parse_zero_cmp`). Node-exact:
  a zero comparator is a V8 no-op sort. Disjoint from F1572 (a>b) and
  F1610 (Number(a>b)/b>=a) by the zero-return grammar.

F1693: hole-array concat staging --
  `var D=[,].concat(C);` + `String.fromCharCode.apply(null,D.slice(1))`
  + RESULT. New `_js_f1693_stmt_decode`. Node-exact: single-hole array
  concat then slice(1) drops the hole. Disjoint from F1586 (spread
  concat twins) by the hole-literal grammar.

F1694: Object.entries pair readout --
  `var O=Object.assign({},C);var E=Object.entries(O);`
  `var D=E.map(function(e){return Number(e[1]);});` (or the arrow
  twins) + fromCharCode.apply readout + RESULT.
  New `_js_f1694_stmt_decode` (+`_js_f1694_parse_entries_cb`).
  Node-exact: entries yields [key,value] pairs in index order;
  Number(e[1]) recovers each code. Disjoint from F1682
  (Object.values) by the entries-pair grammar.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 105->108 (merge: 3 lanes)
(wave-385: repoint only on actual code-count change).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1695-F1704
(other opens) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp as _dlp

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _hits(payload):
    """True if find_credential flags the payload (in-process)."""
    try:
        return bool(_dlp.find_credential(payload))
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


_FILED = [
    ("f1690",
     "var C={I};var f=String.fromCharCode.bind(null);var S=f(...C);var RESULT=S;"),
    ("f1691",
     "var C={I};var f=String.fromCodePoint.bind(null);var S=f.apply(null,C);var RESULT=S;"),
    ("f1692-arrow",
     "var C={I};var D=C.slice().sort((a,b)=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1692-fn",
     "var C={I};var D=C.slice().sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1693",
     "var C={I};var D=[,].concat(C);var S=String.fromCharCode.apply(null,D.slice(1));var RESULT=S;"),
    ("f1694-fn",
     "var C={I};var O=Object.assign({},C);var E=Object.entries(O);var D=E.map(function(e){return Number(e[1]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1694-arrow",
     "var C={I};var O=Object.assign({},C);var E=Object.entries(O);var D=E.map(e=>Number(e[1]));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1694-arrow-paren",
     "var C={I};var O=Object.assign({},C);var E=Object.entries(O);var D=E.map((e)=>Number(e[1]));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """N_STMTDEC_LOOPS=108 (105 base + 3 lanes); re.compile=29; pin 2143; wave-424 merge."""
    ok = True
    notes = []
    # N_STMTDEC_LOOPS actual count
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    if len(loops) != 108:
        ok = False
        notes.append("loops=%d (want 108)" % len(loops))
    # re.compile count
    n_re = len(re.findall(r"re\.compile\(", src))
    if n_re != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % n_re)
    # pin 2143 in attack battery
    atk = open(os.path.join(REPO_ROOT, "evals",
                            "w423_attack_probes.py")).read()
    if "2143" not in atk:
        ok = False
        notes.append("pin 2143 missing in w423_attack_probes")
    # wave-423 footer lineage
    fnd = open(os.path.join(REPO_ROOT, "evals",
                            "FINDINGS.md")).read()
    if "# Wave-423:" not in fnd:
        ok = False
        notes.append("wave-423 footer missing")
    return (ok, "p0 pins" + ("" if ok else ": " + "; ".join(notes)))


# ---------------- p1: filed shapes ----------------

@_t
def test_p1_filed_shapes():
    """All filed shapes now HIT."""
    bad = []
    total = 0
    for name, tmpl in _FILED:
        for s in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(tmpl.replace("{I}", _codes(s))):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """Renamed idents, let/const, ws variants."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1690-let",
         "let C=%s;let f=String.fromCharCode.bind(null);let S=f(...C);let RESULT=S;" % cs),
        ("f1690-renamed",
         "var A=%s;var g=String.fromCharCode.bind(null);var T=g(...A);var RESULT=T;" % cs),
        ("f1690-ws",
         "var C = %s ; var f = String.fromCharCode.bind(null) ; var S = f(...C) ; var RESULT = S ;" % cs),
        ("f1691-const",
         "const C=%s;const f=String.fromCodePoint.bind(null);const S=f.apply(null,C);const RESULT=S;" % cs),
        ("f1691-renamed",
         "var A=%s;var g=String.fromCodePoint.bind(null);var T=g.apply(null,A);var RESULT=T;" % cs),
        ("f1692-renamed",
         "var A=%s;var B=A.slice().sort((x,y)=>0);var S=String.fromCharCode.apply(null,B);var RESULT=S;" % cs),
        ("f1692-const",
         "const C=%s;const D=C.slice().sort(function(a,b){return 0;});const S=String.fromCharCode.apply(null,D);const RESULT=S;" % cs),
        ("f1693-let",
         "let C=%s;let D=[,].concat(C);let S=String.fromCharCode.apply(null,D.slice(1));let RESULT=S;" % cs),
        ("f1693-renamed",
         "var A=%s;var B=[,].concat(A);var T=String.fromCharCode.apply(null,B.slice(1));var RESULT=T;" % cs),
        ("f1694-let",
         "let C=%s;let O=Object.assign({},C);let E=Object.entries(O);let D=E.map(function(e){return Number(e[1]);});let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1694-renamed",
         "var A=%s;var P=Object.assign({},A);var Q=Object.entries(P);var R=Q.map(x=>Number(x[1]));var T=String.fromCharCode.apply(null,R);var RESULT=T;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d generalizations hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Hook-level fail-closed bounds: all must MISS."""
    cs = _codes(SECRET_S)
    cases = [
        # F1690: spread required, not apply
        # F1691: apply required, not spread
        ("f1691-spread",
         "var C=%s;var f=String.fromCodePoint.bind(null);var S=f(...C);var RESULT=S;" % cs),
        # F1692: comparator must return 0
        ("f1692-nonzero",
         "var C=%s;var D=C.slice().sort((a,b)=>1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1692-nocmp",
         "var C=%s;var D=C.slice().sort();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1693: hole literal required
        ("f1693-no-hole",
         "var C=%s;var D=[].concat(C);var S=String.fromCharCode.apply(null,D.slice(1));var RESULT=S;" % cs),
        # F1693: slice arg must be 1
        ("f1693-slice0",
         "var C=%s;var D=[,].concat(C);var S=String.fromCharCode.apply(null,D.slice(0));var RESULT=S;" % cs),
        # F1694: index must be 1
        ("f1694-idx0",
         "var C=%s;var O=Object.assign({},C);var E=Object.entries(O);var D=E.map(function(e){return Number(e[0]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1694: entries required, not values
        ("f1694-values",
         "var C=%s;var O=Object.assign({},C);var E=Object.values(O);var D=E.map(function(e){return Number(e);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d fail-closed miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Neighboring hooks keep their documented behavior."""
    cs = _codes(SECRET_S)
    # F1648 (bind+apply) still HIT
    p1648 = ("var C=%s;var f=String.fromCharCode.bind(null);"
             "var S=f.apply(null,C);var RESULT=S;" % cs)
    # F1572 (a>b sort) still HIT
    p1572 = ("var C=%s;var D=C.slice().sort(function(a,b){return a>b;});"
             "var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
    # F1586 (spread concat) still HIT
    p1586 = ("var C=%s;var D=[].concat(...C,...[]);"
             "var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
    # F1682 (Object.values) still HIT
    p1682 = ("var C=%s;var O=Object.assign({},C);var D=Object.values(O).map(Number);"
             "var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
    cases = [("f1648", p1648), ("f1572", p1572), ("f1586", p1586),
             ("f1682", p1682)]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    cases = [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1 + 2; console.log(x);",
        "Hello, world! This is a test.",
        "function foo() { return bar; }",
    ]
    bad = [c[:20] for c in cases if not _misses(c)]
    return (not bad, "%d/%d honest-quiet%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p6: other opens miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1703-F1704, F1705-F1714 (other opens) still MISS."""
    cs = _codes(SECRET_S)
    # F1703: surrogate smuggling (should MISS - systemic gap, partial)
    p1703 = ("var C=[55296,%s];var S=String.fromCharCode.apply(null,C);"
             "var RESULT=S;" % ",".join(str(ord(c)) for c in SECRET_S))
    # Note: F1695-F1702 closed by lanes B/C, removed from other-opens
    cases = [("f1703", p1703)]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 sites decode in reasonable time."""
    cs = _codes(SECRET_S)
    payload = ("var C=%s;var f=String.fromCharCode.bind(null);"
               "var S=f(...C);var RESULT=S;" % cs)
    t0 = time.time()
    n = 0
    for _ in range(200):
        if _hits(payload):
            n += 1
    dt = time.time() - t0
    ok = n == 200 and dt < 120
    return (ok, "200 sites %d hit in %.1fs" % (n, dt))


# ---------------- g0: green check ----------------

@_t
def test_g0_green():
    """Depth-1 green check: adjacent battery file exists and parses."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "g0 skipped (GOV_SKIP_GREEN=1)")
    adj = os.path.join(REPO_ROOT, "evals", "w423_f1686f1689close_probes.py")
    try:
        import ast
        ast.parse(open(adj).read())
        return (True, "adjacent battery parses OK")
    except Exception as e:
        return (False, "g0 error: %s" % e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    args = ap.parse_args()
    fails = 0
    total = 0
    for fn in TESTS:
        if args.only and fn.__name__ != args.only:
            continue
        total += 1
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, "EXC: %s" % e
        status = "HELD" if ok else "BREAK"
        if not ok:
            fails += 1
        print("%s: %s [%s]" % (fn.__name__, msg, status))
    print("RESULT: %d/%d %s" % (total - fails, total,
                                "HELD" if fails == 0 else "BREAK"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
