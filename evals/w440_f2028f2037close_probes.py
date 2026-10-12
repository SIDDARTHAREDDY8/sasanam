#!/usr/bin/env python3
"""Wave-440 lane B close battery: F2028-F2037.

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
F2028_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T['toString'](2);var RESULT=U;"
F2029_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString.bind(T)(8);var RESULT=U;"
F2030_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString.apply(T,[]);var RESULT=U;"
F2031_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${''}${''}${T}`;var RESULT=U;"
F2032_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}${''}`.slice(0);var RESULT=U;"
F2033_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.padStart(T.length,' ');var RESULT=U;"
F2034_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.substr(0);var RESULT=U;"
F2035_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.substring(0);var RESULT=U;"
F2036_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.split('').join('');var RESULT=U;"
F2037_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('').concat(T);var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 168."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f2028_stmt_decode", "_js_f2029_stmt_decode",
              "_js_f2030_stmt_decode", "_js_f2031_stmt_decode",
              "_js_f2032_stmt_decode", "_js_f2033_stmt_decode",
              "_js_f2034_stmt_decode", "_js_f2035_stmt_decode",
              "_js_f2036_stmt_decode", "_js_f2037_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f2028_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 167 base + 1 new = 168
    n = src.count("for _stmtdec in")
    ok = _check("p0-loopcount", n == 168,
                "got %d, want 168" % n) and ok
    # re.compile count unchanged
    nre = src.count("re.compile(")
    ok = _check("p0-recompile", nre == 29,
                "got %d, want 29" % nre) and ok
    return ok

def test_p1_filed_shapes():
    """Filed shapes must HIT (both 20-char and 40-char credentials)."""
    ok = True
    shapes = [
        ("F2028", F2028_FILED),
        ("F2029", F2029_FILED),
        ("F2030", F2030_FILED),
        ("F2031", F2031_FILED),
        ("F2032", F2032_FILED),
        ("F2033", F2033_FILED),
        ("F2034", F2034_FILED),
        ("F2035", F2035_FILED),
        ("F2036", F2036_FILED),
        ("F2037", F2037_FILED),
    ]
    for name, tmpl in shapes:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            verdict = _scan(payload)
            ok = _check("p1-%s-%s" % (name, tag), verdict == "HIT",
                        "got %s" % verdict) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const variants must HIT."""
    ok = True
    # let variant of F2028
    payload = F2028_FILED.replace("{I}", _codes(SECRET_S)).replace("var ", "let ", 1)
    verdict = _scan(payload)
    ok = _check("p2-F2028-let", verdict == "HIT", "got %s" % verdict) and ok
    # const variant of F2037
    payload = F2037_FILED.replace("{I}", _codes(SECRET_S)).replace("var ", "const ", 1)
    verdict = _scan(payload)
    ok = _check("p2-F2037-const", verdict == "HIT", "got %s" % verdict) and ok
    return ok

def test_p3_fail_closed():
    """Fail-closed: malformed shapes must MISS (not mis-decode)."""
    ok = True
    # F2028 with wrong radix (3 instead of 2) must MISS
    payload = F2028_FILED.replace("{I}", _codes(SECRET_S)).replace("(2)", "(3)")
    verdict = _scan(payload)
    ok = _check("p3-F2028-bad-radix", verdict == "MISS",
                "got %s" % verdict) and ok
    # F2037 with non-empty first concat arg must MISS
    payload = F2037_FILED.replace("{I}", _codes(SECRET_S)).replace("''.concat('')", "'x'.concat('')")
    verdict = _scan(payload)
    ok = _check("p3-F2037-bad-arg", verdict == "MISS",
                "got %s" % verdict) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: related shapes still HIT (no regression)."""
    ok = True
    # F1980 (T.toString(2) dot-access) must still HIT
    payload = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(2);var RESULT=U;" % _codes(SECRET_S)
    verdict = _scan(payload)
    ok = _check("p4-F1980", verdict == "HIT", "got %s" % verdict) and ok
    # F1983 (T['toString']() no-arg) must still HIT
    payload = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T['toString']();var RESULT=U;" % _codes(SECRET_S)
    verdict = _scan(payload)
    ok = _check("p4-F1983", verdict == "HIT", "got %s" % verdict) and ok
    return ok

def test_p5_honest_text():
    """Honest text must MISS (no false positives)."""
    ok = True
    # Plain text without credentials
    verdict = _scan("Hello world, this is a test.")
    ok = _check("p5-plain", verdict == "MISS", "got %s" % verdict) and ok
    # Code without credential pattern
    verdict = _scan("var x = 1 + 2; console.log(x);")
    ok = _check("p5-code", verdict == "MISS", "got %s" % verdict) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites must complete quickly."""
    ok = True
    payload = F2028_FILED.replace("{I}", _codes(SECRET_S))
    big = payload * 200
    start = time.time()
    verdict = _scan(big)
    elapsed = time.time() - start
    ok = _check("p6-perf", elapsed < 30, "%.1fs" % elapsed) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    # Run the wave-439 lane A battery as a sanity check
    battery = os.path.join(REPO_ROOT, "evals", "w439_f1976f1983close_probes.py")
    if not os.path.exists(battery):
        print("GREENCHECK: adjacent battery not found, skipping")
        return True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run([sys.executable, battery], capture_output=True,
                       text=True, timeout=600, env=env, cwd=REPO_ROOT)
    ok = r.returncode == 0
    print("GREENCHECK: adjacent battery %s" % ("PASS" if ok else "FAIL"))
    return ok

def main():
    tests = [
        test_p0_pins,
        test_p1_filed_shapes,
        test_p2_generalizations,
        test_p3_fail_closed,
        test_p4_siblings,
        test_p5_honest_text,
        test_p6_perf,
    ]
    all_ok = True
    for t in tests:
        try:
            ok = t()
        except Exception as e:
            _check(t.__name__, False, "EXC: %s" % e)
            ok = False
        all_ok = all_ok and ok
    # Green check
    try:
        gc_ok = _green_check()
    except Exception as e:
        print("GREENCHECK EXC: %s" % e)
        gc_ok = False
    all_ok = all_ok and gc_ok

    n_ok = sum(1 for _, ok, _ in _results if ok)
    n_total = len(_results)
    print("\n%d/%d HELD" % (n_ok, n_total))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL %s: %s" % (name, detail))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
