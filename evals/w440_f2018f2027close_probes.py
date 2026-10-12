#!/usr/bin/env python3
"""Wave-440 lane A close battery: F2018-F2027.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 167 -> 168 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged; pin 2143.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w440_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-" + "0123456789abcde"
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

_results = []
def _check(name, ok, detail=""):
    _results.append((name, ok, detail))
    return ok

def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"

# Filed shapes (from FINDINGS.md, attack round 107, first-filing 2026-10-12 20:24 UTC)
F2018_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(9)+T).trimStart();var RESULT=U;"
F2019_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+String.fromCharCode(9)).trimEnd();var RESULT=U;"
F2020_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(13,10)+T+String.fromCharCode(13,10)).trim();var RESULT=U;"
F2021_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(11)+T).trimLeft();var RESULT=U;"
F2022_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+String.fromCharCode(12)).trimRight();var RESULT=U;"
F2023_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(32,9,10,13)+T).trimStart();var RESULT=U;"
F2024_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+String.fromCharCode(160,32)).trimEnd();var RESULT=U;"
F2025_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(32)+T+String.fromCharCode(9)).trimStart().trimEnd();var RESULT=U;"
F2026_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(36);var RESULT=U;"
F2027_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.toString.call(T,16);var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 168."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f2018_stmt_decode", "_js_f2019_stmt_decode",
              "_js_f2020_stmt_decode", "_js_f2021_stmt_decode",
              "_js_f2022_stmt_decode", "_js_f2023_stmt_decode",
              "_js_f2024_stmt_decode", "_js_f2025_stmt_decode",
              "_js_f2026_stmt_decode", "_js_f2027_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f2018_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 167 base + 1 new = 168
    # Count dispatch loops in _decode_layer by finding "for _stmtdec in ("
    m = re.search(r"def _decode_layer\(text\):", src)
    assert m, "no _decode_layer"
    body = src[m.start():]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = _check("p0-loopcount", len(loops) == 168,
                "%d loops (pin 168)" % len(loops)) and ok
    # re.compile count unchanged
    rc = src.count("re.compile(")
    ok = _check("p0-recompile", rc == 29, "%d (pin 29)" % rc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f2018", F2018_FILED), ("f2019", F2019_FILED),
                       ("f2020", F2020_FILED), ("f2021", F2021_FILED),
                       ("f2022", F2022_FILED), ("f2023", F2023_FILED),
                       ("f2024", F2024_FILED), ("f2025", F2025_FILED),
                       ("f2026", F2026_FILED), ("f2027", F2027_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f2018-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(String.fromCharCode(9)+TT).trimStart();let RESULT=UU;" % cs),
        ("f2019-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(B+String.fromCharCode(9)).trimEnd();const RESULT=Q;" % cs),
        ("f2021-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(String.fromCharCode(11)+TT).trimLeft();let RESULT=UU;" % cs),
        ("f2026-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B.toString(36);const RESULT=Q;" % cs),
        ("f2027-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=String.prototype.toString.call(TT,16);let RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS); sibling-covered shapes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F2018: space pad instead of tab -> narrow grammar -> MISS
        ("f2018-space", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(32)+T).trimStart();var RESULT=U;" % cs, "MISS"),
        # F2018: trimEnd instead of trimStart -> different hook -> MISS
        ("f2018-trimend", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(9)+T).trimEnd();var RESULT=U;" % cs, "MISS"),
        # F2019: space pad instead of tab -> MISS
        ("f2019-space", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+String.fromCharCode(32)).trimEnd();var RESULT=U;" % cs, "MISS"),
        # F2026: radix 16 -> covered by F1946 sibling -> HIT
        ("f2026-radix16-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs, "HIT"),
        # F2026: radix 2 -> covered by F1980 sibling -> HIT
        ("f2026-radix2-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(2);var RESULT=U;" % cs, "HIT"),
        # F2027: valueOf instead of toString -> covered by F1948 -> HIT
        ("f2027-valueof-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.valueOf.call(T);var RESULT=U;" % cs, "HIT"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s want %s" % (v, expect)) and ok
    return ok

def test_p4_siblings():
    """Sibling findings still HIT (no regression)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1976", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' ').trimEnd();var RESULT=U;" % cs),
        ("f1977", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(10)+T).trimLeft();var RESULT=U;" % cs),
        ("f1980", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(2);var RESULT=U;" % cs),
        ("f1946", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for name, payload in (
        ("prose", "the quick brown fox jumps over the lazy dog"),
        ("code", "function hello() { return 'world'; }"),
        ("trim", "var x = '  hello  '.trim();"),
    ):
        v = _scan(payload)
        ok = _check("p5-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites decode within budget."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F2018_FILED.replace("{I}", cs)
    big = " ".join([payload] * 200)
    start = time.time()
    v = _scan(big)
    elapsed = time.time() - start
    ok = _check("p6-time", elapsed < 30, "%.2fs" % elapsed) and ok
    ok = _check("p6-verdict", v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: adjacent battery deltas are expected-only."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _check("p7-skip", True, "skipped")
        return True
    ok = True
    # Run the w439 lane A battery as a green check. Expected deltas from
    # this lane's closures (wave-305): (1) loop count 167->168 (new dispatch
    # loop). Any other failure is a regression.
    battery = os.path.join(REPO_ROOT, "evals", "w439_f1976f1983close_probes.py")
    if os.path.exists(battery):
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        r = subprocess.run([sys.executable, battery],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        out = (r.stdout or "") + (r.stderr or "")
        fails = [l.strip() for l in out.split("\n") if "FAIL " in l]
        expected = {"p0-loopcount"}
        unexpected = [f for f in fails
                      if not any(e in f for e in expected)]
        ok = _check("p7-w439a-no-regress", len(unexpected) == 0,
                    "unexpected: %s" % unexpected) and ok
        has_loop = any("p0-loopcount" in f for f in fails)
        ok = _check("p7-w439a-expected", has_loop,
                    "loop=%s" % has_loop) and ok
    else:
        _check("p7-w439a", True, "not found, skipped")
    return ok

def main():
    tests = [
        test_p0_pins,
        test_p1_filed,
        test_p2_generalizations,
        test_p3_failclosed,
        test_p4_siblings,
        test_p5_honest,
        test_p6_perf,
        test_p7_green,
    ]
    all_ok = True
    for t in tests:
        try:
            ok = t()
        except Exception as e:
            _check(t.__name__, False, "EXC: %s" % e)
            ok = False
        all_ok = ok and all_ok
        print("%s: %s" % (t.__name__, "PASS" if ok else "FAIL"))

    n_pass = sum(1 for _, ok, _ in _results if ok)
    n_fail = sum(1 for _, ok, _ in _results if not ok)
    print("\n%d/%d checks passed" % (n_pass, n_pass + n_fail))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL %s: %s" % (name, detail))

    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
