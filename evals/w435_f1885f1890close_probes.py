#!/usr/bin/env python3
"""Wave-435 lane D close battery: F1885, F1886, F1887, F1888, F1889, F1890.

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

# Filed shapes (from FINDINGS.md, attack round 102)
F1885_FILED = "var C={I};var D=C.slice();var E=D.toSorted(function(a,b){return a-a;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"
F1886_FILED = "var C={I};var D=[C];var E=D.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
F1887_FILED = "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){var k=kv[0];var v=kv[1];return v;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1888_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().valueOf();var RESULT=U;"
F1889_FILED = "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries([...Object.entries(O)]);var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1890_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var S=T;}else{var S='';}var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 147."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1885_stmt_decode", "_js_f1886_stmt_decode",
              "_js_f1887_stmt_decode", "_js_f1888_stmt_decode",
              "_js_f1889_stmt_decode", "_js_f1890_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1885_stmt_decode," in src,
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
    for name, tmpl in (("f1885", F1885_FILED), ("f1886", F1886_FILED),
                       ("f1887", F1887_FILED), ("f1888", F1888_FILED),
                       ("f1889", F1889_FILED), ("f1890", F1890_FILED)):
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
        # F1885: let/const, renamed params
        ("f1885-let", "let CC=%s;let DD=CC.slice();let EE=DD.toSorted(function(xx,yy){return xx-xx;});let SS=String.fromCharCode.apply(null,EE);let RESULT=SS;" % cs),
        ("f1885-bb", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return b-b;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1886: let, different plus operands computing to 2
        ("f1886-let", "let CC=%s;let DD=[CC];let EE=DD.flat(0+2);let SS=String.fromCharCode.apply(null,EE);let RESULT=SS;" % cs),
        # F1887: let, renamed idents
        ("f1887-let", "let CC=%s;let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}let DD=Object.entries(OO).map(function(pp){var kk=pp[0];var vv=pp[1];return vv;});let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        # F1888: const
        ("f1888-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.valueOf().valueOf();const RESULT=UU;" % cs),
        # F1889: let, renamed
        ("f1889-let", "let CC=%s;let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}let PP=Object.fromEntries([...Object.entries(OO)]);let DD=Object.values(PP);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        # F1890: let, renamed
        ("f1890-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.at(-1)===TT[TT.length-1]){let SS=TT;}else{let SS='';}let RESULT=SS;" % cs),
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
        # F1885: a-b is NOT always 0 -> must MISS
        ("f1885-notzero", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return a-b;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1885: literal 0 belongs to F1853 (sibling HIT expected)
        ("f1885-sibling", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1886: depth 1+1+1=3, not 2 -> MISS (flat(3) on [C] still flattens, but grammar is narrow)
        ("f1886-depth3", "var C=%s;var D=[C];var E=D.flat(2+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1886: minus form belongs to F1855 (sibling HIT expected)
        ("f1886-sibling", "var C=%s;var D=[C];var E=D.flat(2-1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1887: return k (the key) instead of v -> wrong, must MISS
        ("f1887-wrongret", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){var k=kv[0];var v=kv[1];return k;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1887: direct return kv[1] belongs to F1857 (sibling HIT expected)
        ("f1887-sibling", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1888: single valueOf belongs to F1858 (sibling HIT expected)
        ("f1888-sibling", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf();var RESULT=U;" % cs),
        # F1888: triple valueOf -- outside filed grammar, must MISS (narrow)
        ("f1888-triple", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().valueOf().valueOf();var RESULT=U;" % cs),
        # F1889: direct entries belongs to F1859 (sibling HIT expected)
        ("f1889-sibling", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries(Object.entries(O));var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1889: no spread but extra array wrap -> MISS
        ("f1889-nowrap", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries([Object.entries(O)]);var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1890: wrong guard comparison -> MISS
        ("f1890-wrongguard", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[0]){var S=T;}else{var S='';}var RESULT=S;" % cs),
        # F1890: array form belongs to F1840 (sibling HIT expected)
        ("f1890-sibling", "var C=%s;var D=C.slice();var L=D.at(-1);if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        if name in ("f1885-sibling", "f1886-sibling", "f1887-sibling",
                    "f1888-sibling", "f1889-sibling", "f1890-sibling"):
            # covered by siblings -> expect HIT
            ok = _check("p3-%s" % name, v == "HIT", "got %s" % v) and ok
        else:
            ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression); my hooks don't steal siblings."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1853 (toSorted literal 0) still HITs
        ("f1853", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1855 (flat 2-1) still HITs
        ("f1855", "var C=%s;var D=[C];var E=D.flat(2-1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1857 (entries direct return) still HITs
        ("f1857", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1858 (single valueOf) still HITs
        ("f1858", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf();var RESULT=U;" % cs),
        # F1859 (fromEntries direct) still HITs
        ("f1859", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries(Object.entries(O));var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1840 (array at(-1)) still HITs
        ("f1840", "var C=%s;var D=C.slice();var L=D.at(-1);if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
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
        "var arr = [1,2,3]; var sorted = arr.toSorted((a,b) => a - b);",
        "var t = 'abc'; var u = t.valueOf();",
        "var o = {a: 1}; var e = Object.entries(o);",
        "var nested = [[1,2],[3]]; var f = nested.flat(2);",
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
        F1885_FILED.replace("{I}", cs),
        F1886_FILED.replace("{I}", cs),
        F1887_FILED.replace("{I}", cs),
        F1888_FILED.replace("{I}", cs),
        F1889_FILED.replace("{I}", cs),
        F1890_FILED.replace("{I}", cs),
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
    # Run the w434 lane-D battery as a green check (depth-1).
    # Note: w434d expects loopcount 146, but this lane adds one loop
    # (147). The pin will be repointed at merge; we verify no OTHER
    # regressions here.
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
                print("  %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")

if __name__ == "__main__":
    main()
