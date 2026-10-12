#!/usr/bin/env python3
"""Wave-434 lane C close battery: F1856, F1857, F1858, F1859, F1860.

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w434_close_")
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
F1856_FILED = "var C={I};var D=C.slice(C.length-C.length,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1857_FILED = "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1858_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf();var RESULT=U;"
F1859_FILED = "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries(Object.entries(O));var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1860_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(3)+T).trimStart().trimEnd();var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 143."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1856_stmt_decode", "_js_f1857_stmt_decode",
              "_js_f1858_stmt_decode", "_js_f1859_stmt_decode",
              "_js_f1860_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1856_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 146, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1856", F1856_FILED), ("f1857", F1857_FILED),
                       ("f1858", F1858_FILED), ("f1859", F1859_FILED),
                       ("f1860", F1860_FILED)):
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
        ("f1856-let", "let CC=%s;let DD=CC.slice(CC.length-CC.length,CC.length);let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1856-noresult", "var C=%s;var D=C.slice(C.length-C.length,C.length);var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1857-let", "let CC=%s;let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}let DD=Object.entries(OO).map(function(kv){return kv[1];});let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1857-noresult", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1858-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.valueOf();" % cs),
        ("f1858-noresult", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf();" % cs),
        ("f1859-let", "let CC=%s;let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}let PP=Object.fromEntries(Object.entries(OO));let DD=Object.values(PP);let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1860-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(' '.repeat(3)+TT).trimStart().trimEnd();" % cs),
        ("f1860-noresult", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(3)+T).trimStart().trimEnd();" % cs),
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
        # F1856: non-identity slice (drops first char in node)
        ("f1856-noidentity", "var C=%s;var D=C.slice(1,C.length);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1856: shadowed String
        ("f1856-strshadow", "var String=%s;var D=String.slice(String.length-String.length,String.length);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1857: wrong map index (kv[0] = keys, not values)
        ("f1857-wrongidx", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[0];});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1857: shadowed Object
        ("f1857-objshadow", "var Object=%s;var O={};for(var i=0;i<C.length;i++){O[i]=Object[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1858: valueOf on wrong base (undefined var)
        ("f1858-wrongbase", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Q.valueOf();" % cs),
        # F1859: fromEntries on wrong arg
        ("f1859-wrongarg", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries(C);var D=Object.values(P);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1860: wrong repeat count (node: 2 spaces, still trims to dstr but grammar is narrow)
        ("f1860-wrongrepeat", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(2)+T).trimStart().trimEnd();" % cs),
        # F1860: trimStart only (missing trimEnd -- different grammar)
        ("f1860-notrimend", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(3)+T).trimStart();" % cs),
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
        # F1841 (string slice computed) still HITs
        ("f1841", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.length-T.length,T.length);var RESULT=U;" % cs),
        # F1820 (Object.values) still HITs
        ("f1820", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1844 (Object.keys map-back) still HITs
        ("f1844", "var C=%s;var D=Object.keys(C).map(function(k){return C[k];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1815 (trimStart) still HITs
        ("f1815", "var C=%s;var T=' '.repeat(C.length-C.length+2)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;" % cs),
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
        "var arr = [1,2,3]; var s = arr.slice(0, arr.length);",
        "var obj = {a: 1, b: 2}; var e = Object.entries(obj);",
        "var s = '  padded  '; var t = s.trimStart().trimEnd();",
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
        F1856_FILED.replace("{I}", cs),
        F1857_FILED.replace("{I}", cs),
        F1858_FILED.replace("{I}", cs),
        F1859_FILED.replace("{I}", cs),
        F1860_FILED.replace("{I}", cs),
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
    # Run the w433 lane-D battery as a green check (depth-1).
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w433_f1843f1847close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    # Extract failures; wave-434 merge updated pins to 146, so no exceptions expected
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w433d", not unexpected,
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
                print("  FAIL %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")

if __name__ == "__main__":
    main()
