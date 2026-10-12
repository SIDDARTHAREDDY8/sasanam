#!/usr/bin/env python3
"""Wave-435 lane B close battery: F1871, F1872, F1873, F1874, F1875, F1876.

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w435_close_")
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
F1871_FILED = "var C={I};var D=C.slice();if(D.findLastIndex(function(x){return x===C[0];})>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1872_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./gd)){U+=m[0];}var RESULT=U;"
F1873_FILED = "var C={I};var D=C.toSpliced(-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1874_FILED = "var C={I};var G=Object.groupBy(C,function(c){return 0;});var D=G[0];var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1875_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(-T.length,T.length);var RESULT=U;"
F1876_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(T.length,'~'.slice(0,0));var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 147."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1871_stmt_decode", "_js_f1872_stmt_decode",
              "_js_f1873_stmt_decode", "_js_f1874_stmt_decode",
              "_js_f1875_stmt_decode", "_js_f1876_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1871_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 147, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1871", F1871_FILED), ("f1872", F1872_FILED),
                       ("f1873", F1873_FILED), ("f1874", F1874_FILED),
                       ("f1875", F1875_FILED), ("f1876", F1876_FILED)):
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
        ("f1871-let", "let CC=%s;let DD=CC.slice();if(DD.findLastIndex(function(xx){return xx===CC[0];})>=0){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        ("f1871-const", "const CC=%s;const DD=CC.slice();if(DD.findLastIndex(function(xx){return xx===CC[0];})>=0){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
        ("f1872-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU='';for(let mm of TT.matchAll(/./gd)){UU+=mm[0];}let RESULT=UU;" % cs),
        ("f1872-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU='';for(const mm of TT.matchAll(/./gd)){UU+=mm[0];}const RESULT=UU;" % cs),
        ("f1873-let", "let CC=%s;let DD=CC.toSpliced(-CC.length,0);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1874-let", "let CC=%s;let GG=Object.groupBy(CC,function(cc){return 0;});let DD=GG[0];let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1875-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(TT+TT).substr(-TT.length,TT.length);let RESULT=UU;" % cs),
        ("f1876-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.padEnd(TT.length,'~'.slice(0,0));let RESULT=UU;" % cs),
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
        # F1871: last-element predicate inline with >=0 (neither F1837 nor F1871)
        ("f1871-lastpred", "var C=%s;var D=C.slice();if(D.findLastIndex(function(x){return x===C[C.length-1];})>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1871: === guard (belongs to F1837 shape family)
        ("f1871-eqguard", "var C=%s;var D=C.slice();var I=D.findLastIndex(function(x){return x===C[0];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1872: /./g without d-flag (belongs to F1838)
        ("f1872-nodflag", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;" % cs, "HIT"),
        # F1872: wrong regex
        ("f1872-wrongre", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/x/gd)){U+=m[0];}var RESULT=U;" % cs, "MISS"),
        # F1873: zero-expr start (belongs to F1835)
        ("f1873-zeroexpr", "var C=%s;var D=C.toSpliced(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "HIT"),
        # F1873: positive start (not identity)
        ("f1873-posstart", "var C=%s;var D=C.toSpliced(1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "MISS"),
        # F1874: Map.groupBy (covered by sibling F1804 -> expect HIT)
        ("f1874-mapgb", "var C=%s;var G=Map.groupBy(C,function(c){return 0;});var D=G.get(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "HIT"),
        # F1874: non-const key
        ("f1874-nonconst", "var C=%s;var G=Object.groupBy(C,function(c){return c;});var D=G[0];var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "MISS"),
        # F1875: positive start (belongs to F1817)
        ("f1875-posstart", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(T.length,T.length);var RESULT=U;" % cs, "HIT"),
        # F1875: wrong length arg
        ("f1875-wronglen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(-T.length,1);var RESULT=U;" % cs, "MISS"),
        # F1876: computed length (belongs to F1806)
        ("f1876-complen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'x');var RESULT=U;" % cs, "HIT"),
        # F1876: non-empty pad that changes the string
        ("f1876-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(T.length+3,'~'.slice(0,0));var RESULT=U;" % cs, "MISS"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s want %s" % (v, expect)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression); my hooks don't steal siblings."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1837 (findLastIndex last-elem) still HITs
        ("f1837", "var C=%s;var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1838 (matchAll /./g) still HITs
        ("f1838", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;" % cs),
        # F1835 (toSpliced zero-expr) still HITs
        ("f1835", "var C=%s;var D=C.toSpliced(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1817 (substr positive) still HITs
        ("f1817", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(T.length,T.length);var RESULT=U;" % cs),
        # F1806 (padEnd computed) still HITs
        ("f1806", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'x');var RESULT=U;" % cs),
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
        "var t = 'abc'; var u = t.padEnd(10);",
        "var idx = arr.findLastIndex(function(x){ return x > 2; });",
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
        F1871_FILED.replace("{I}", cs),
        F1872_FILED.replace("{I}", cs),
        F1873_FILED.replace("{I}", cs),
        F1874_FILED.replace("{I}", cs),
        F1875_FILED.replace("{I}", cs),
        F1876_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 6])
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
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w434_f1861f1864close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w434d", not unexpected,
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
                print("FAIL %s: %s" % (n, d))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
