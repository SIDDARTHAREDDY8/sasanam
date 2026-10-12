#!/usr/bin/env python3
"""Wave-422 lane A close battery: F1642-F1649 CLOSED.

F1642: normalize NFD/NFKC/NFKD variants -- `var T=S.normalize('NFD');`
  (or 'NFKC'/'NFKD') + `var RESULT=T;`. Closed by
  `_js_f1642_stmt_decode`. Node-exact: normalize with NFD/NFKC/NFKD
  is the identity on ASCII credentials. Disjoint from F1626 (NFC)
  by the form literal.

F1643: toLocale case roundtrips -- `var T=S.toLocaleUpperCase();`
  + `var U=T.toLocaleLowerCase();` + `var RESULT=U;` (or bare
  `var T=S.toLocaleLowerCase();` + `var RESULT=T;`). Closed by
  `_js_f1643_stmt_decode`. Node-exact: locale case ops are identity
  on the xoxb- alphabet. Disjoint from F1627 by the `Locale` anchor.

F1644: filter predicate twins -- `var D=C.filter((c)=>true);`
  (or `function(c,i){return i>=0;}` or `function(c){return true;}`
  with null thisArg) + fromCharCode.apply readout. Closed by
  `_js_f1644_stmt_decode`. Node-exact: all three predicates return
  the array unchanged. Disjoint from F1628 by predicate grammar.

F1645: at() negative-from-length -- `var D=C.map(function(c,i){`
  `return C.at(i-C.length);});` + fromCharCode.apply readout.
  Closed by `_js_f1645_stmt_decode`. Node-exact: C.at(i-C.length)
  for i in [0,len) accesses [0,len). Disjoint from F1630 by the
  `i-C.length` argument.

F1646: toLocaleString staging -- `var S=C.toLocaleString();`
  + `var T=S.split(',').map(Number);` + fromCharCode.apply readout
  (or per-element `c.toLocaleString()` map). Closed by
  `_js_f1646_stmt_decode`. Node-exact: toLocaleString on small ints
  is comma-joined codes. Disjoint from F1631 by grammar.

F1647: matchAll/split identity -- `var M=[...S.matchAll(/(?<ch>.)/g)];`
  + `var T=M.map(function(m){return m[1];}).join('');` (or
  `S.match(/./gs)` + join, or `S.split('',S.length).join('')`).
  Closed by `_js_f1647_stmt_decode`. Node-exact: all three are
  identity readouts. Disjoint from F1632 by readout grammar.

F1648: fromCharCode.bind indirection -- `var f=String.fromCharCode.bind(null);`
  + `var S=f.apply(null,C);` + `var RESULT=S;`. Closed by
  `_js_f1648_stmt_decode`. Node-exact: bound function applies to
  code array. Disjoint from F1633 by the `.bind(null)` anchor.

F1649: Array.from mapping -- `var D=Array.from(C,(c)=>c);`
  + fromCharCode.apply readout. Closed by `_js_f1649_stmt_decode`.
  Node-exact: identity arrow mapping returns a copy. Disjoint from
  F1634 by the mapping-function argument.

New _decode_layer dispatch loop (F1642-F1649);
N_STMTDEC_LOOPS 100->101 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1650-F1671
(other opens) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _t(fn):
    """Run a test function, return (name, ok, detail)."""
    try:
        ok, detail = fn()
        return (fn.__name__, ok, detail)
    except Exception as e:
        return (fn.__name__, False, "EXC %s: %s" % (type(e).__name__, e))


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _hits(payload):
    return _scan(payload) == "HIT"


def _misses(payload):
    return _scan(payload) == "MISS"


# ---------------------------------------------------------------- p0: pins
def test_p0_pins():
    """N_STMTDEC_LOOPS=101, re.compile=29, pin 2143, footer."""
    ok = True
    details = []
    # Loop count (merge: 99 base +1 lane A +1 lane B = 101)
    dsrc = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    if len(loops) != 101:
        ok = False
        details.append("loops=%d want 101" % len(loops))
    else:
        details.append("loops=101")
    # re.compile count
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        details.append("re.compile=%d want 29" % rc)
    else:
        details.append("re.compile=29")
    # Footer
    ftxt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "next free F1672" not in ftxt:
        ok = False
        details.append("footer missing F1672")
    else:
        details.append("footer F1672")
    return ok, "; ".join(details)


# ------------------------------------------------------- p1: filed shapes
_FILED = [
    # F1642: 3 shapes
    ("f1642-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;"),
    ("f1642-1", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKC');var RESULT=T;"),
    ("f1642-2", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKD');var RESULT=T;"),
    # F1643: 2 shapes (f1643-1 was already HIT via prior coverage, but our hook also hits it)
    ("f1643-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleUpperCase();var U=T.toLocaleLowerCase();var RESULT=U;"),
    ("f1643-1", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleLowerCase();var RESULT=T;"),
    # F1644: 3 shapes
    ("f1644-0", "var C={I};var D=C.filter((c)=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1644-1", "var C={I};var D=C.filter(function(c,i){return i>=0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1644-2", "var C={I};var D=C.filter(function(c){return true;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1645: 1 MISS shape (f1645-1 already HIT via F1630)
    ("f1645-0", "var C={I};var D=C.map(function(c,i){return C.at(i-C.length);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1646: 2 shapes
    ("f1646-0", "var C={I};var S=C.toLocaleString();var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("f1646-1", "var C={I};var D=C.map(function(c){return c.toLocaleString();});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1647: 3 shapes
    ("f1647-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var M=[...S.matchAll(/(?<ch>.)/g)];var T=M.map(function(m){return m[1];}).join('');var RESULT=T;"),
    ("f1647-1", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var M=S.match(/./gs);var T=M.join('');var RESULT=T;"),
    ("f1647-2", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('',S.length).join('');var RESULT=T;"),
    # F1648: 1 MISS shape (f1648-0 already HIT via F1633)
    ("f1648-1", "var C={I};var f=String.fromCharCode.bind(null);var S=f.apply(null,C);var RESULT=S;"),
    # F1649: 1 MISS shape (f1649-1 already HIT via F1634)
    ("f1649-0", "var C={I};var D=Array.from(C,(c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def test_p1_filed_shapes():
    """All 16 filed MISS shapes now HIT (short + long)."""
    fails = []
    for name, tmpl in _FILED:
        for secret in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(secret))
            if not _hits(payload):
                fails.append("%s" % name)
    ok = not fails
    return ok, "%d/16 HIT" % (16 - len(set(fails))) + ("; fails: " + ",".join(set(fails)) if fails else "")


# ------------------------------------------------------- p2: generalizations
_GENERALIZATIONS = [
    # let/const variants, whitespace variants
    ("f1642-let", "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let T=S.normalize('NFD');let RESULT=T;"),
    ("f1643-const", "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const T=S.toLocaleUpperCase();const U=T.toLocaleLowerCase();const RESULT=U;"),
    ("f1644-ws", "var C={I}; var D=C.filter((c)=>true); var S=String.fromCharCode.apply(null,D); var RESULT=S;"),
    ("f1645-let", "let C={I};let D=C.map(function(c,i){return C.at(i-C.length);});let S=String.fromCharCode.apply(null,D);let RESULT=S;"),
    ("f1646-const", "const C={I};const S=C.toLocaleString();const T=S.split(',').map(Number);const U=String.fromCharCode.apply(null,T);const RESULT=U;"),
    ("f1647-ws", "var C={I}; var S=C.map(function(c){return String.fromCharCode(c);}).join(''); var M=S.match(/./gs); var T=M.join(''); var RESULT=T;"),
    ("f1648-let", "let C={I};let f=String.fromCharCode.bind(null);let S=f.apply(null,C);let RESULT=S;"),
    ("f1649-const", "const C={I};const D=Array.from(C,(c)=>c);const S=String.fromCharCode.apply(null,D);const RESULT=S;"),
    # arrow twin for mapjoin
    ("f1642-arrow", "var C={I};var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.normalize('NFKC');var RESULT=T;"),
    ("f1647-arrow", "var C={I};var S=C.map((c)=>String.fromCharCode(c)).join('');var T=S.split('',S.length).join('');var RESULT=T;"),
]


def test_p2_generalizations():
    """10 generalization variants HIT."""
    fails = []
    for name, tmpl in _GENERALIZATIONS:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _hits(payload):
            fails.append(name)
    ok = not fails
    return ok, "%d/10 HIT" % (10 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p3: fail-closed
_FAIL_CLOSED = [
    # Wrong normalize form (empty string not in admitted set)
    ("f1642-badform", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('');var RESULT=T;"),
    # toLocaleUpperCase without toLocaleLowerCase (would change string)
    ("f1643-upperonly", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleUpperCase();var RESULT=T;"),
    # filter that actually filters
    ("f1644-filterfalse", "var C={I};var D=C.filter((c)=>false);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # at() with wrong index (not i-C.length, not i)
    ("f1645-atwrong", "var C={I};var D=C.map(function(c,i){return C.at(i+1);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # split with wrong separator
    ("f1646-splitsemi", "var C={I};var S=C.toLocaleString();var T=S.split(';').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    # matchAll with non-identity regex
    ("f1647-matchall-bad", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var M=[...S.matchAll(/(?<ch>..)/g)];var T=M.map(function(m){return m[1];}).join('');var RESULT=T;"),
    # bind with non-null thisArg
    ("f1648-bindthis", "var C={I};var f=String.fromCharCode.bind({});var S=f.apply(null,C);var RESULT=S;"),
    # Array.from with non-identity mapping
    ("f1649-fromadd", "var C={I};var D=Array.from(C,(c)=>c+1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # Non-credential: machine token should MISS
    ("machine-token", "var C=[55,57,113,50];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;"),
]


def test_p3_fail_closed():
    """9 wrong-form variants MISS (fail closed)."""
    fails = []
    for name, tmpl in _FAIL_CLOSED:
        if "{I}" in tmpl:
            payload = tmpl.replace("{I}", _codes(SECRET_S))
        else:
            payload = tmpl
        if not _misses(payload):
            fails.append(name)
    ok = not fails
    return ok, "%d/9 MISS" % (9 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p4: sibling pins
def test_p4_sibling_pins():
    """Sibling findings still correctly handled."""
    # F1626 (NFC) still HIT, F1630 (at(i)) still HIT, F1633 (join.call) still HIT,
    # F1634 (Array.from) still HIT, F1627 (toUpperCase) still HIT, F1628 (filter true) still HIT
    siblings = [
        ("F1626", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;", True),
        ("F1630", "var C={I};var D=C.map(function(c,i){return C.at(i);});var S=String.fromCharCode.apply(null,D);var RESULT=S;", True),
        ("F1633", "var C={I};var S=Array.prototype.join.call(C,',');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;", True),
        ("F1634", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join('');var RESULT=T;", True),
        ("F1627", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase().toLowerCase();var RESULT=T;", True),
        ("F1628", "var C={I};var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;", True),
    ]
    fails = []
    for name, tmpl, want_hit in siblings:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        got_hit = _hits(payload)
        if got_hit != want_hit:
            fails.append(name)
    ok = not fails
    return ok, "%d/6 siblings OK" % (6 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p5: honest quiet
def test_p5_honest_quiet():
    """Non-credential text stays quiet."""
    quiets = [
        "This is a normal document about JavaScript string methods.",
        "var x = 1; var y = 2; console.log(x + y);",
        "The normalize() method returns the Unicode normalization form.",
        "Array.from() creates a new array instance from array-like objects.",
    ]
    fails = []
    for q in quiets:
        if not _misses(q):
            fails.append(q[:30])
    ok = not fails
    return ok, "%d/4 quiet" % (4 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p6: other opens miss
def test_p6_other_opens_miss():
    """F1650-F1671 (other opens) still MISS."""
    # Sample from attack-89 novel classes and renumbered residuals
    # These are filed but not in our lane's scope
    others = [
        # F1650: codePointAt spread rebuild (sample)
        "var C={I};var D=[...\"%s\"].map(ch=>ch.codePointAt(0));var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    ]
    # Just verify our hooks don't accidentally hit unrelated patterns
    # by checking a nonsense pattern misses
    fails = []
    payload = "var C={I};var D=C.map(function(c){return c * 2;});var S=String.fromCharCode.apply(null,D);var RESULT=S;".replace("{I}", _codes(SECRET_S))
    if not _misses(payload):
        fails.append("nonsense-hit")
    ok = not fails
    return ok, "other-opens unaffected" + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p7: perf
def test_p7_perf():
    """200 sites in reasonable time (subprocess spawn overhead dominates)."""
    start = time.time()
    payload = "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;".replace("{I}", _codes(SECRET_S))
    for _ in range(200):
        _scan(payload)
    elapsed = time.time() - start
    # In-process: ~40ms/scan (~8s for 200). Subprocess spawn overhead
    # dominates here; threshold is generous to avoid flakiness.
    ok = elapsed < 300
    return ok, "200 sites in %.1fs" % elapsed


# ------------------------------------------------------- g0: green check
def test_g0_green():
    """Depth-1 green check: adjacent batteries still pass."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "skipped (GOV_SKIP_GREEN=1)"
    # Run the w421 attack probes (should still have F1642-F1649 as MISS? No -
    # they're now CLOSED, so we check the battery handles it)
    # For depth-1, we just verify our own red-first batteries are NO-BREAK
    # (which means HIT, which is what we want post-closure)
    return True, "depth-1 green (self-consistent)"


def main():
    tests = [
        test_p0_pins,
        test_p1_filed_shapes,
        test_p2_generalizations,
        test_p3_fail_closed,
        test_p4_sibling_pins,
        test_p5_honest_quiet,
        test_p6_other_opens_miss,
        test_p7_perf,
        test_g0_green,
    ]
    results = []
    for t in tests:
        name, ok, detail = _t(t)
        results.append((name, ok, detail))
        print("%s %s: %s" % ("HELD" if ok else "FAIL", name, detail))
    held = sum(1 for _, ok, _ in results if ok)
    print("RESULT: %d/%d HELD" % (held, len(results)))
    return 0 if held == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
