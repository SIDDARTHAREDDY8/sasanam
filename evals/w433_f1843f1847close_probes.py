#!/usr/bin/env python3
"""Wave-433 lane D close battery: F1843, F1844, F1845, F1846, F1847.

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w433_close_")
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

# Filed shapes (from FINDINGS.md)
F1843_FILED = "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var U=D.join(''.repeat(1).slice(0,0));var RESULT=U;"
F1844_FILED = "var C={I};var D=Object.keys(C).map(function(k){return C[k];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1845_FILED = "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var D=[...M.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1846_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw`${T}`;var RESULT=U;"
F1847_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('~');var U=T.split('~'.repeat(1)).join('');var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 139."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1843_stmt_decode", "_js_f1844_stmt_decode",
              "_js_f1845_stmt_decode", "_js_f1846_stmt_decode",
              "_js_f1847_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1843_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 139, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1843", F1843_FILED), ("f1844", F1844_FILED),
                       ("f1845", F1845_FILED), ("f1846", F1846_FILED),
                       ("f1847", F1847_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const decls, renamed idents HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1843-let", "let CC=%s;let DD=CC.map(function(c){return String.fromCharCode(c);});let UU=DD.join(''.repeat(1).slice(0,0));" % cs),
        ("f1843-noresult", "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var U=D.join(''.repeat(1).slice(0,0));" % cs),
        ("f1844-let", "let CC=%s;let DD=Object.keys(CC).map(function(k){return CC[k];});let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1844-noresult", "var C=%s;var D=Object.keys(C).map(function(k){return C[k];});var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1845-let", "let CC=%s;let MM=new Map();for(let ii=0;ii<CC.length;ii++){MM.set(ii,CC[ii]);}let DD=[...MM.values()];let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1846-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=String.raw`${TT}`;" % cs),
        ("f1847-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('~');let UU=TT.split('~'.repeat(1)).join('');" % cs),
        ("f1847-noresult", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('~');var U=T.split('~'.repeat(1)).join('');" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS, never mis-decode)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1843: non-empty separator (node: joins with 'x', not credential)
        ("f1843-nonempty", "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var U=D.join('x'.repeat(1).slice(0,1));" % cs),
        # F1843: shadowed String
        ("f1843-strshadow", "var String=%s;var D=String.map(function(c){return String.fromCharCode(c);});var U=D.join(''.repeat(1).slice(0,0));" % cs),
        # F1844: wrong map body (C[0] instead of C[k])
        ("f1844-wrongbody", "var C=%s;var D=Object.keys(C).map(function(k){return C[0];});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1844: shadowed Object
        ("f1844-objshadow", "var Object=%s;var D=Object.keys(Object).map(function(k){return Object[k];});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1845: const loop counter (node throws)
        ("f1845-constctr", "var C=%s;var M=new Map();for(const i=0;i<C.length;i++){M.set(i,C[i]);}var D=[...M.values()];var S=String.fromCharCode.apply(null,D);" % cs),
        # F1845: shadowed Map
        ("f1845-mapshadow", "var Map=%s;var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var D=[...M.values()];var S=String.fromCharCode.apply(null,D);" % cs),
        # F1846: wrong template arg
        ("f1846-wrongarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw`${C}`;" % cs),
        # F1847: wrong split separator
        ("f1847-wrongsep", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('~');var U=T.split('x'.repeat(1)).join('');" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1826 (Map set/get) still HITs
        ("f1826", "var C=%s;var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1820 (Object.values) still HITs
        ("f1820", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1814 (trim) still HITs
        ("f1814", "var C=%s;var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T.trim();" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "var x = 'hello world'; var y = 42;",
        "function greet(name) { return 'Hello, ' + name; }",
        "var arr = [1,2,3]; var s = arr.join(',');",
        "var obj = {a: 1, b: 2}; var keys = Object.keys(obj);",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-honest%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time (in-process, not subprocess)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1843_FILED.replace("{I}", cs),
        F1844_FILED.replace("{I}", cs),
        F1845_FILED.replace("{I}", cs),
        F1846_FILED.replace("{I}", cs),
        F1847_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 5])
        if not r:
            ok = _check("p6-perf", False, "miss at %d" % i) and ok
            return ok
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: run adjacent battery mains with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    # Run the w432 lane-D battery as a green check (depth-1).
    # Note: w432d expects loopcount 138, but this lane adds one loop
    # (139). The pin will be repointed at merge; we verify no OTHER
    # regressions here.
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w432_f1820f1826close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    # Extract failures; allow only p0-loopcount (expected: 138->139)
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w432d", not unexpected,
                "unexpected fails: %s" % unexpected) and ok
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
            _check(t.__name__, False, "EXC %s" % e)
            ok = False
        all_ok = all_ok and ok
    fails = [n for n, ok, d in _results if not ok]
    print("\n%d/%d HELD" % (len(_results) - len(fails), len(_results)))
    if fails:
        print("FAILURES:")
        for n, ok, d in _results:
            if not ok:
                print("  %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")

if __name__ == "__main__":
    main()
