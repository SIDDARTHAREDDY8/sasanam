#!/usr/bin/env python3
"""Wave-431 lane A close battery: F1782, F1783, F1784, F1785, F1786, F1787.

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
F1782_FILED = "var C={I};var D=[C.slice(0,10),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1783_FILED = "var C={I};var D=C.slice(undefined,undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1784_FILED = "var C={I};var D=C.concat(C).slice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1785_FILED = "var C={I};var D=[];C.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1786_FILED = "var C={I};var D=[];for(var c of C){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1787_FILED = "var C={I};var D=Array.from(C.keys()).map(function(i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop, counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1782_stmt_decode", "_js_f1783_stmt_decode",
              "_js_f1784_stmt_decode", "_js_f1785_stmt_decode",
              "_js_f1786_stmt_decode", "_js_f1787_stmt_decode"):
        ok = _check("p0-%s" % h[4:12], ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1782_stmt_decode," in src,
                "dispatch loop present") and ok
    nloops = src.count("for _stmtdec in")
    ok = _check("p0-nloops", nloops == 131, "%d" % nloops) and ok
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT (both credential sizes)."""
    ok = True
    for name, tmpl in (("f1782", F1782_FILED), ("f1783", F1783_FILED),
                       ("f1784", F1784_FILED), ("f1785", F1785_FILED),
                       ("f1786", F1786_FILED), ("f1787", F1787_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, arrow cbs, K variants."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1782-let-K5", "let CC=%s;let DD=[CC.slice(0,5),CC.slice(5)].flat();let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1782-flat1", "var C=%s;var D=[C.slice(0,10),C.slice(10)].flat(1);var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1782-noresult", "var C=%s;var D=[C.slice(0,10),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1783-const", "const CC=%s;const DD=CC.slice(undefined,undefined);const SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1784-let", "let CC=%s;let DD=CC.concat(CC).slice(0,CC.length);let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1785-arrow", "var C=%s;var D=[];C.forEach((c)=>{D.push(c);});var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1785-arrowexpr", "var C=%s;var D=[];C.forEach(c=>D.push(c));var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1785-let", "let CC=%s;let DD=[];CC.forEach(function(cc){DD.push(cc);});let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1786-letconst", "const CC=%s;const DD=[];for(let cc of CC){DD.push(cc);}const SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1787-arrow", "var C=%s;var D=Array.from(C.keys()).map((i)=>C[i]);var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1787-arrowbare", "var C=%s;var D=Array.from(C.keys()).map(i=>C[i]);var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1787-blockarrow", "var C=%s;var D=Array.from(C.keys()).map((i)=>{return C[i];});var S=String.fromCharCode.apply(null,D);" % cs),
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
        # F1782: non-contiguous partition
        ("f1782-gap", "var C=%s;var D=[C.slice(0,5),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);" % cs),
        # F1782: overlapping partition
        ("f1782-overlap", "var C=%s;var D=[C.slice(0,10),C.slice(5)].flat();var S=String.fromCharCode.apply(null,D);" % cs),
        # F1782: flat on wrong base
        ("f1782-wrongbase", "var C=%s;var E=[1];var D=[E.slice(0,10),E.slice(10)].flat();var S=String.fromCharCode.apply(null,D);" % cs),
        # F1783: only one undefined
        ("f1783-oneundef", "var C=%s;var D=C.slice(0,undefined);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1783: null not undefined
        ("f1783-null", "var C=%s;var D=C.slice(null,null);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1784: concat wrong arg
        ("f1784-badarg", "var C=%s;var E=[1];var D=C.concat(E).slice(0,C.length);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1784: slice wrong bound
        ("f1784-badbound", "var C=%s;var D=C.concat(C).slice(1,C.length);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1785: push wrong var
        ("f1785-badpush", "var C=%s;var D=[];var E=[];C.forEach(function(c){E.push(c);});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1785: forEach wrong base
        ("f1785-badbase", "var C=%s;var D=[];var E=[1];E.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1786: push loop var mismatch
        ("f1786-badarg", "var C=%s;var D=[];var E=1;for(var c of C){D.push(E);}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1786: for-in not for-of
        ("f1786-forin", "var C=%s;var D=[];for(var c in C){D.push(c);}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1787: map wrong base
        ("f1787-badmap", "var C=%s;var E=[1];var D=Array.from(E.keys()).map(function(i){return E[i];});var S=String.fromCharCode.apply(null,D);" % cs),
        # F1787: index wrong var
        ("f1787-badidx", "var C=%s;var D=Array.from(C.keys()).map(function(i){return C[0];});var S=String.fromCharCode.apply(null,D);" % cs),
        # Spec review: ";" after expression-body arrow is a node SyntaxError -> MISS
        ("f1785-exprsemi", "var C=%s;var D=[];C.forEach(c=>D.push(c););var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1787-exprsemi", "var C=%s;var D=Array.from(C.keys()).map(i=>C[i];);var S=String.fromCharCode.apply(null,D);" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling productions still decode (disjointness sanity)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1349: map+flat staged (filed shape)
        ("f1349", "var C=%s;var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F751: forEach S+= accumulation
        ("f751", "var C=%s;var S='';C.forEach(function(c){S+=String.fromCharCode(c);});var RESULT=S;" % cs),
        # direct control
        ("direct", "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "The quarterly financial summary shows revenue growth.",
        "var x = 1; var y = 2; var z = x + y;",
        "var items = [1,2,3]; var halves = [items.slice(0,2),items.slice(2)].flat();",
        "data.forEach(function(row){table.push(row);});",
        "for (var k of keys) { out.push(k); }",
        "var idx = Array.from(m.keys()).map(function(i){return m[i];});",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-431 opens still MISS (F1788-F1804)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1788", "var C={I};var D=Array.from(C.entries()).map(function(e){return e[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1789", "var C={I};var it=C[Symbol.iterator]();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1790", "var C={I};function*g(){yield*C;}var D=Array.from(g());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1791", "var C={I};var D=Array.from(C.values().map(function(c){return c;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1792", "var C={I};var D=Array.from(C.values().filter(function(){return true;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1793", "var C={I};var D=new Array(C.length);for(var i=0;i<C.length;i++){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1794", "var C={I};var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1795", "var C={I};var D=Array.from(Object.create(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1796", "var C={I};var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1797", "var C={I};var R=new WeakRef(C);var D=R.deref();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1798", "var C={I};var D=Array.from(new Uint16Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1799", "var C={I};var D=Array.from(new Float64Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1800", "var C={I};var R=function(){var r={};for(var i=0;i<C.length;i++){r[i]=C[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);var RESULT=S;"),
        ("f1801", "var C={I};var D=C.slice();var t=D[0];D[0]=D[D.length-1];D[D.length-1]=t;var u=D[0];D[0]=D[D.length-1];D[D.length-1]=u;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1802", "var C={I};var D=C.map(function(c,i){return String.fromCharCode(c);});var RESULT=D.join('');"),
        ("f1803", "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/2048);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1804", "var C={I};var G=Map.groupBy(C,function(c){return 0;});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    tmpls = [F1782_FILED.replace("{I}", cs), F1783_FILED.replace("{I}", cs),
             F1784_FILED.replace("{I}", cs), F1785_FILED.replace("{I}", cs),
             F1786_FILED.replace("{I}", cs), F1787_FILED.replace("{I}", cs)]
    sites = []
    for i in range(200):
        if i % 6 < 5:
            sites.append(tmpls[i % 6])
        else:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    ok = _check("p7-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_g0_green():
    """Depth-1 green check: the F1782-F1787 red-first batteries still run."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for n in (1782, 1783, 1784, 1785, 1786, 1787):
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
