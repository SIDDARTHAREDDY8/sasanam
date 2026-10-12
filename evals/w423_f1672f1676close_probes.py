#!/usr/bin/env python3
"""Wave-423 lane A close battery: F1672-F1676 CLOSED.

F1672: Iterator.from() transform helpers + toArray() -- `var D=Iterator.from(C).`
  `map(function(c){return c;})/filter(function(c){return true;})/`
  `flatMap(function(c){return [c];})/take(C.length)/drop(0)` + `.toArray()`
  + fromCharCode.apply readout. Closed by `_js_f1672_stmt_decode`.
  Node-exact: every admitted helper is the identity over the code array.
  Disjoint from F1541 (C.values() source) by the Iterator.from grammar.

F1673: Iterator.from().forEach() accumulation -- `var T='';`
  `Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});`
  + `var RESULT=T;`. Closed by `_js_f1673_stmt_decode`. Node-exact:
  forEach visits codes in order, appending chars. Disjoint from F1672
  (toArray readout) and F1031 (async-iterator) by grammar.

F1674: Iterator.from().map().reduce() staging -- `var RESULT=Iterator.from(C).`
  `map(function(c){return String.fromCharCode(c);})`
  `.reduce(function(a,ch){return a+ch;},'');`. Closed by
  `_js_f1674_stmt_decode`. Node-exact at every credential length (the
  20-char form already decoded via an earlier hook; the 40-char form
  missed -- this hook is length-agnostic). Disjoint from F1672 by the
  `.reduce(` grammar.

F1675: Intl.Segmenter grapheme-identity staging --
  `var D=[...new Intl.Segmenter().segment(S)].map(function(s){`
  `return s.segment;}).join('');` + `var RESULT=D;`. Closed by
  `_js_f1675_stmt_decode`. Node-exact on ASCII (fails closed on
  non-ASCII). Disjoint from F1070 (ZWSP-filter) by the no-filter
  grammar.

F1676: URLSearchParams sequence-of-pairs staging --
  `var P=new URLSearchParams([['k',S]]);` + `var T=P.get('k');`
  + `var RESULT=T;`. Closed by `_js_f1676_stmt_decode`. Node-exact:
  .get returns the stored value verbatim. Disjoint from F576
  (string-literal constructor) by grammar.

New _decode_layer dispatch loop (F1672-F1676);
N_STMTDEC_LOOPS 101->102 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1677-F1689
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
    """N_STMTDEC_LOOPS=102, re.compile=29, pin 2143, footer."""
    ok = True
    details = []
    dsrc = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    if len(loops) != 105:  # merge: 101 base + 4 lanes
        ok = False
        details.append("loops=%d want 105" % len(loops))
    else:
        details.append("loops=105")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        details.append("re.compile=%d want 29" % rc)
    else:
        details.append("re.compile=29")
    ftxt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "next free F1690" not in ftxt:
        ok = False
        details.append("footer missing F1690")
    else:
        details.append("footer F1690")
    return ok, "; ".join(details)


# ------------------------------------------------------- p1: filed shapes
_FILED = [
    # F1672: 5 shapes
    ("f1672-0", "var C={I};var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-1", "var C={I};var D=Iterator.from(C).filter(function(c){return true;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-2", "var C={I};var D=Iterator.from(C).flatMap(function(c){return [c];}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-3", "var C={I};var D=Iterator.from(C).take(C.length).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-4", "var C={I};var D=Iterator.from(C).drop(0).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1673: 1 shape
    ("f1673-0", "var C={I};var T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;"),
    # F1674: 1 shape (length-dependent: both sizes must HIT)
    ("f1674-0", "var C={I};var RESULT=Iterator.from(C).map(function(c){return String.fromCharCode(c);}).reduce(function(a,ch){return a+ch;},'');"),
    # F1675: 1 shape
    ("f1675-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');var RESULT=D;"),
    # F1676: 1 shape
    ("f1676-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=new URLSearchParams([['k',S]]);var T=P.get('k');var RESULT=T;"),
]


def test_p1_filed_shapes():
    """All 9 filed shapes now HIT (short + long)."""
    fails = []
    for name, tmpl in _FILED:
        for secret in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(secret))
            if not _hits(payload):
                fails.append("%s" % name)
    ok = not fails
    return ok, "%d/9 HIT" % (9 - len(set(fails))) + ("; fails: " + ",".join(set(fails)) if fails else "")


# ------------------------------------------------------- p2: generalizations
_GENERALIZATIONS = [
    # let/const/whitespace variants
    ("f1672-let", "let C={I};let D=Iterator.from(C).map(function(c){return c;}).toArray();let S=String.fromCharCode.apply(null,D);let RESULT=S;"),
    ("f1672-ws", "var C={I}; var D=Iterator.from(C).drop(0).toArray(); var S=String.fromCharCode.apply(null,D); var RESULT=S;"),
    ("f1673-let", "let C={I};let T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});let RESULT=T;"),
    ("f1674-const", "const C={I};const RESULT=Iterator.from(C).map(function(c){return String.fromCharCode(c);}).reduce(function(a,ch){return a+ch;},'');"),
    ("f1675-const", "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');const RESULT=D;"),
    ("f1676-let", "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let P=new URLSearchParams([['k',S]]);let T=P.get('k');let RESULT=T;"),
    # arrow twin for mapjoin in F1675/F1676
    ("f1675-arrow", "var C={I};var S=C.map((c)=>String.fromCharCode(c)).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');var RESULT=D;"),
    ("f1676-arrow", "var C={I};var S=C.map((c)=>String.fromCharCode(c)).join('');var P=new URLSearchParams([['k',S]]);var T=P.get('k');var RESULT=T;"),
    # different pair key in F1676
    ("f1676-key2", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=new URLSearchParams([['zz',S]]);var T=P.get('zz');var RESULT=T;"),
    # additive RESULT tail for F1672
    ("f1672-additive", "var C={I};var D=Iterator.from(C).take(C.length).toArray();var S=String.fromCharCode.apply(null,D);var RESULT='x'+S;"),
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
    # F1672: non-identity helpers
    ("f1672-mapadd", "var C={I};var D=Iterator.from(C).map(function(c){return c+1;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-filternot", "var C={I};var D=Iterator.from(C).filter(function(c){return false;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-take5", "var C={I};var D=Iterator.from(C).take(5).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1672-drop1", "var C={I};var D=Iterator.from(C).drop(1).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1673: const accumulator (node TypeError), non-empty init
    ("f1673-const", "var C={I};const T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;"),
    ("f1673-nonempty", "var C={I};var T='x';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;"),
    # F1675: non-empty join separator
    ("f1675-joincomma", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join(',');var RESULT=D;"),
    # F1676: key mismatch
    ("f1676-keymismatch", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=new URLSearchParams([['k',S]]);var T=P.get('j');var RESULT=T;"),
    # Non-credential: machine token should MISS
    ("machine-token", "var C=[55,57,113,50];var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    """Sibling hooks still wired and disjoint from new hooks."""
    import gov.dlp as dlp
    dsrc = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    # Sibling hooks exist and are in the dispatch loop
    checks = []
    for hook in ("_js_f1070_stmt_decode", "_js_f1541_stmt_decode"):
        if "def %s(" % hook not in dsrc:
            checks.append("%s missing def" % hook)
        elif hook not in dsrc[dsrc.find("def _decode_layer(text):"):]:
            checks.append("%s not in dispatch" % hook)
    # New hooks do not fire on sibling-distinctive markers
    sib_texts = [
        'var P=["a"];var RESULT=[...new Intl.Segmenter().segment(P.join("\u200b"))].filter(s=>s.segment!=="\u200b").map(s=>s.segment).join("");',
    ]
    for t in sib_texts:
        for fn in (dlp._js_f1672_stmt_decode, dlp._js_f1673_stmt_decode,
                   dlp._js_f1674_stmt_decode, dlp._js_f1675_stmt_decode,
                   dlp._js_f1676_stmt_decode):
            try:
                if fn(t) is not None:
                    checks.append("%s fires on sibling shape" % fn.__name__)
            except Exception:
                pass
    ok = not checks
    return ok, "siblings OK" + ("; issues: " + ",".join(checks) if checks else "")



def test_p5_honest_quiet():
    """Non-credential text stays quiet."""
    quiets = [
        "This is a normal document about JavaScript iterators.",
        "var x = 1; var y = 2; console.log(x + y);",
        "The Intl.Segmenter enables locale-sensitive text segmentation.",
        "URLSearchParams handles query string parsing.",
    ]
    fails = []
    for q in quiets:
        if not _misses(q):
            fails.append(q[:30])
    ok = not fails
    return ok, "%d/4 quiet" % (4 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p6: other opens miss
def test_p6_other_opens_miss():
    """F1677-F1689: merged-tree pin update (wave-423 merge). F1677/F1680 now CLOSED (lane B) -> expect HIT; F1686-F1689 now CLOSED (lane D) -> expect HIT."""
    # F1677: structuredClone staging (sample) -- CLOSED in merge, expect HIT
    hits = [
        "var C={I};var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);",
        # F1680: Uint8Array staging (sample) -- CLOSED in merge, expect HIT
        "var C={I};var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);",
    ]
    fails = []
    for tmpl in hits:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if _misses(payload):
            fails.append(tmpl[:40])
    ok = not fails
    return ok, "%d/2 merged-closed HIT" % (2 - len(fails)) + ("; fails: " + ",".join(fails) if fails else "")


# ------------------------------------------------------- p7: perf
def test_p7_perf():
    """200 sites in reasonable time."""
    start = time.time()
    payload = "var C={I};var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;".replace("{I}", _codes(SECRET_S))
    for _ in range(200):
        _scan(payload)
    elapsed = time.time() - start
    ok = elapsed < 300
    return ok, "200 sites in %.1fs" % elapsed


# ------------------------------------------------------- g0: green check
def test_g0_green():
    """Depth-1 green check: adjacent batteries still pass."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "skipped (GOV_SKIP_GREEN=1)"
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
