#!/usr/bin/env python3
"""Wave-431 lane D close battery: F1800, F1801, F1802, F1803, F1804.

Pins the closures. All assertions must HOLD on the fixed tree.
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
    print(("PASS " if ok else "FAIL ") + name + (" -- " + detail if detail else ""))
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
F1800_FILED = "var C={I};var R=function(){var r={};for(var i=0;i<C.length;i++){r[i]=C[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);var RESULT=S;"
F1801_FILED = "var C={I};var D=C.slice();var t=D[0];D[0]=D[D.length-1];D[D.length-1]=t;var u=D[0];D[0]=D[D.length-1];D[D.length-1]=u;var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1802_FILED = "var C={I};var D=C.map(function(c,i){return String.fromCharCode(c);});var RESULT=D.join('');"
F1803_FILED = "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/2048);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1804_FILED = "var C={I};var G=Map.groupBy(C,function(c){return 0;});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1800_stmt_decode", "_js_f1801_stmt_decode",
              "_js_f1802_stmt_decode", "_js_f1803_stmt_decode",
              "_js_f1804_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1800_stmt_decode," in src,
                "dispatch loop present") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1800", F1800_FILED), ("f1801", F1801_FILED),
                       ("f1802", F1802_FILED), ("f1803", F1803_FILED),
                       ("f1804", F1804_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1800-let", "let CC=%s;let RR=function(){let rr={};for(let ii=0;ii<CC.length;ii++){rr[ii]=CC[ii];}rr.length=CC.length;return rr;}();let SS=String.fromCharCode.apply(null,RR);" % cs),
        ("f1801-const", "const CC=%s;const DD=CC.slice();const tt=DD[0];DD[0]=DD[DD.length-1];DD[DD.length-1]=tt;const uu=DD[0];DD[0]=DD[DD.length-1];DD[DD.length-1]=uu;const SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1802-let", "let CC=%s;let DD=CC.map(function(cc,ii){return String.fromCharCode(cc);});let RESULT=DD.join('');" % cs),
        ("f1803-let", "let CC=%s;let GG=Map.groupBy(CC,function(cc,ii){return Math.floor(ii/4096);});let DD=[];for(let kk=0;GG.has(kk);kk++){DD=DD.concat(GG.get(kk));}let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1804-const", "const CC=%s;const GG=Map.groupBy(CC,function(cc){return 0;});const DD=[];for(let kk=0;GG.has(kk);kk++){DD=DD.concat(GG.get(kk));}const SS=String.fromCharCode.apply(null,DD);" % cs),
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
        # F1800: wrong loop bound (not C.length)
        ("f1800-badbound", "var C=%s;var R=function(){var r={};for(var i=0;i<10;i++){r[i]=C[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);" % cs),
        # F1800: wrong copy source
        ("f1800-badsrc", "var C=%s;var E=[];var R=function(){var r={};for(var i=0;i<C.length;i++){r[i]=E[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);" % cs),
        # F1801: single swap (not double)
        ("f1801-single", "var C=%s;var D=C.slice();var t=D[0];D[0]=D[D.length-1];D[D.length-1]=t;var S=String.fromCharCode.apply(null,D);" % cs),
        # F1801: swap wrong indices
        ("f1801-badidx", "var C=%s;var D=C.slice();var t=D[1];D[1]=D[D.length-1];D[D.length-1]=t;var u=D[1];D[1]=D[D.length-1];D[D.length-1]=u;var S=String.fromCharCode.apply(null,D);" % cs),
        # F1802: 1-param callback (belongs to F1774 -- should HIT via F1774, not F1802)
        ("f1802-1param-hit", "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');" % cs),
        # F1802: 3-param callback (neither hook covers)
        ("f1802-3param", "var C=%s;var D=C.map(function(c,i,a){return String.fromCharCode(c);});var RESULT=D.join('');" % cs),
        # F1803: K in F1776 range (belongs to F1776 -- should HIT via F1776, not F1803)
        ("f1803-smallk-hit", "var C=%s;var G=Map.groupBy(C,function(c,i){return Math.floor(i/2);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1804: non-const key (Math.floor)
        ("f1804-floor", "var C=%s;var G=Map.groupBy(C,function(c){return Math.floor(0);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        # f1802-1param-hit and f1803-smallk-hit should HIT (via sibling hooks)
        # all others should MISS (fail closed)
        if name.endswith("-hit"):
            ok = _check("p3-%s" % name, v == "HIT", "got %s" % v) and ok
        else:
            ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling productions still work (disjointness)."""
    ok = True
    cs = _codes(SECRET_S)
    # F1774 (1-param map+join) should still HIT via its own hook
    payload = "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');" % cs
    v = _scan(payload)
    ok = _check("p4-f1774", v == "HIT", "got %s" % v) and ok
    # F1776 (K=2) should still HIT via its own hook
    payload = "var C=%s;var G=Map.groupBy(C,function(c,i){return Math.floor(i/2);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);" % cs
    v = _scan(payload)
    ok = _check("p4-f1776", v == "HIT", "got %s" % v) and ok
    # Direct apply still works
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);" % cs
    v = _scan(payload)
    ok = _check("p4-direct", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "The quarterly financial summary shows revenue growth.",
        "var x = 1; var y = 2; var z = x + y;",
        "var r = {}; r.length = 5;",
        "var d = c.slice();",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-431 opens still MISS (F1782-F1799)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1782", "var C={I};var D=[C.slice(0,10),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1785", "var C={I};var D=[];C.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1790", "var C={I};function*g(){yield*C;}var D=Array.from(g());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1796", "var C={I};var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ]
    for name, tmpl in opens:
        payload = tmpl.replace("{I}", cs)
        v = _scan(payload)
        ok = _check("p6-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1800_FILED.replace("{I}", cs),
        F1801_FILED.replace("{I}", cs),
        F1802_FILED.replace("{I}", cs),
        F1803_FILED.replace("{I}", cs),
        F1804_FILED.replace("{I}", cs),
    ]
    sites = []
    for i in range(200):
        if i % 5 < 4:
            sites.append(tmpls[i % 5])
        else:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    ok = _check("p7-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_g0_green():
    """Depth-1 green check: red-first batteries run."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for n in (1800, 1801, 1802, 1803, 1804):
        f = "evals/w431_f%d_redfirst.py" % n
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            ok = _check("g0-f%d" % n, r.returncode in (0, 1),
                        "exit %d" % r.returncode) and ok
    return ok

def main():
    tests = [
        ("p0", test_p0_pins),
        ("p1", test_p1_filed),
        ("p2", test_p2_generalizations),
        ("p3", test_p3_failclosed),
        ("p4", test_p4_siblings),
        ("p5", test_p5_quiet),
        ("p6", test_p6_other_opens),
        ("p7", test_p7_perf),
        ("g0", test_g0_green),
    ]
    all_ok = True
    for name, fn in tests:
        print("\n=== %s ===" % name)
        try:
            if not fn():
                all_ok = False
        except Exception as e:
            print("EXCEPTION in %s: %s" % (name, e))
            import traceback
            traceback.print_exc()
            all_ok = False
    print("\n" + "=" * 50)
    n_pass = sum(1 for _, ok, _ in _results if ok)
    n_total = len(_results)
    print("RESULT: %d/%d %s" % (n_pass, n_total, "HELD" if all_ok else "BROKEN"))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
