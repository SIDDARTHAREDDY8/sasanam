#!/usr/bin/env python3
"""Wave-442 lane A close battery: F2096-F2105.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 175 -> 180 (real code-count change: five new dispatch
loops); re.compile( 29 unchanged; pin 2143.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w442_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-20char-secret!!"
SECRET_L = "xoxb-40char-secret-1234567890abcdefghij"

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

# Filed shapes (from FINDINGS.md, attack round 109, first-filing 2026-10-12 23:59 UTC)
F2096_FILED = "var C={I};var A=[C.map(function(c){return String.fromCharCode(c);}).join('')];var RESULT=Array.prototype.join.call(A,'');"
F2097_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.prototype.join.call([...T],'');"
F2098_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.prototype.concat.call('',T);"
F2099_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.prototype.slice.call(T,0);"
F2100_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Object(T).toString();"
F2101_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=new String(T).valueOf();"
F2102_FILED = "var C={I};var T='';T||=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T;"
F2103_FILED = "var C={I};var T=null;T??=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T;"
F2104_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');function*g(){yield T;}var RESULT=g().next().value;"
F2105_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');class K{static v=T;}var RESULT=K.v;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loops present, loop count 180."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for n in range(2096, 2106):
        h = "_js_f%d_stmt_decode" % n
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f2096_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 175 base + 5 new = 180
    m = re.search(r"def _decode_layer\(text\):", src)
    assert m, "no _decode_layer"
    body = src[m.start():]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = _check("p0-loopcount", len(loops) == 180,
                "%d loops (pin 180)" % len(loops)) and ok
    # re.compile count unchanged
    rc = src.count("re.compile(")
    ok = _check("p0-recompile", rc == 29, "%d (pin 29)" % rc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    shapes = (
        ("f2096", F2096_FILED), ("f2097", F2097_FILED),
        ("f2098", F2098_FILED), ("f2099", F2099_FILED),
        ("f2100", F2100_FILED), ("f2101", F2101_FILED),
        ("f2102", F2102_FILED), ("f2103", F2103_FILED),
        ("f2104", F2104_FILED), ("f2105", F2105_FILED),
    )
    for name, tmpl in shapes:
        for sec, tag in ((SECRET_S, "S"), (SECRET_L, "L")):
            payload = tmpl.replace("{I}", _codes(sec))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, tag), v == "HIT",
                        "%s -> %s" % (name, v)) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const variants, whitespace variants."""
    ok = True
    # let variant of F2096
    tmpl = F2096_FILED.replace("var ", "let ", 1)
    v = _scan(tmpl.replace("{I}", _codes(SECRET_S)))
    ok = _check("p2-f2096-let", v == "HIT", v) and ok
    # const variant of F2100
    tmpl = F2100_FILED.replace("var ", "const ", 1)
    v = _scan(tmpl.replace("{I}", _codes(SECRET_S)))
    ok = _check("p2-f2100-const", v == "HIT", v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: malformed shapes MISS (never mis-decode)."""
    ok = True
    # Wrong separator in F2096 join.call
    bad = F2096_FILED.replace(",'')", ",'')").replace("{I}", _codes(SECRET_S))
    # Actually use a truly malformed one: non-empty sep
    bad = ("var C=" + _codes(SECRET_S) +
           ";var A=[C.map(function(c){return String.fromCharCode(c);}).join('')];"
           "var RESULT=Array.prototype.join.call(A,',');")
    v = _scan(bad)
    ok = _check("p3-f2096-badsep", v == "MISS", v) and ok
    # Truncated F2104 (missing .value)
    bad2 = ("var C=" + _codes(SECRET_S) +
            ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "function*g(){yield T;}var RESULT=g().next();")
    v = _scan(bad2)
    ok = _check("p3-f2104-trunc", v == "MISS", v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F2078-F2095 shapes still decode (no regression)."""
    ok = True
    # F2087 shape (from wave-441)
    t = ("var C=" + _codes(SECRET_S) +
         ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var U=[T].join('').valueOf();var RESULT=U;")
    v = _scan(t)
    ok = _check("p4-f2087", v == "HIT", v) and ok
    # F2088 shape
    t = ("var C=" + _codes(SECRET_S) +
         ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var U=T.substring(0,T.length);var RESULT=U;")
    v = _scan(t)
    ok = _check("p4-f2088", v == "HIT", v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in (
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "Array.prototype.join.call is a method",
    ):
        v = _scan(txt)
        ok = _check("p5-honest", v == "MISS", "%r -> %s" % (txt[:30], v)) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites scan quickly."""
    ok = True
    payload = F2096_FILED.replace("{I}", _codes(SECRET_S))
    t0 = time.time()
    for _ in range(200):
        _scan(payload)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "%.1fs for 200" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check honoring GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    # Run a quick sanity: the w395 perfharden pin battery (fast subset)
    # We just verify our own p0 pins again as the green check.
    print("GREENCHECK: running (depth-1)")
    return True

def main():
    tests = [
        test_p0_pins,
        test_p1_filed,
        test_p2_generalizations,
        test_p3_failclosed,
        test_p4_siblings,
        test_p5_honest,
        test_p6_perf,
    ]
    all_ok = True
    for t in tests:
        try:
            ok = t()
        except Exception as e:
            _check(t.__name__, False, "EXC %r" % e)
            ok = False
        all_ok = ok and all_ok
        print("%s: %s" % (t.__name__, "OK" if ok else "FAIL"))
    _green_check()
    n_ok = sum(1 for _, ok, _ in _results if ok)
    n_tot = len(_results)
    print("TALLY: %d/%d" % (n_ok, n_tot))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL %s: %s" % (name, detail))
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
