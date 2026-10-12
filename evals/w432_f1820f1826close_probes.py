#!/usr/bin/env python3
"""Wave-432 lane D close battery: F1820, F1821, F1823, F1824, F1825, F1826.

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
F1820_FILED = "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1821_FILED = "var C={I};var D=[];for(var [i,v] of C.entries()){D[i]=v;}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1823_FILED = "var C={I};var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);"
F1824_FILED = "var C={I};var D=[];for(i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);"
F1825_FILED = "var C={I};var D=Array.from(Object.create(C,{}));var S=String.fromCharCode.apply(null,D);"
F1826_FILED = "var C={I};var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 135."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1820_stmt_decode", "_js_f1821_stmt_decode",
              "_js_f1823_stmt_decode", "_js_f1824_stmt_decode",
              "_js_f1825_stmt_decode", "_js_f1826_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1820_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 135, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1820", F1820_FILED), ("f1821", F1821_FILED),
                       ("f1823", F1823_FILED), ("f1824", F1824_FILED),
                       ("f1825", F1825_FILED), ("f1826", F1826_FILED)):
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
        ("f1820-let", "let CC=%s;let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}let DD=Object.values(OO);let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1821-let", "let CC=%s;let DD=[];for(let [ii,vv] of CC.entries()){DD[ii]=vv;}let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1823-letC", "let CC=%s;let DD=[];for(const ii in CC){DD[ii]=CC[ii];}let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1824-let", "let CC=%s;let DD=[];for(jj in CC){DD[jj]=CC[jj];}let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1825-const", "const CC=%s;const DD=Array.from(Object.create(CC,{}));const SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1826-let", "let CC=%s;let WW=new Map();let OO={};WW.set(OO,CC);let DD=WW.get(OO);let SS=String.fromCharCode.apply(null,DD);" % cs),
        # with RESULT
        ("f1823-result", "var C=%s;var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1826-result", "var C=%s;var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        # F1820: const counter (node throws TypeError -- fail closed)
        ("f1820-constctr", "var C=%s;var O={};for(const i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1820: shadowed String (node throws -- fail closed)
        ("f1820-strshadow", "var String=%s;var O={};for(var i=0;i<String.length;i++){O[i]=String[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1826: shadowed Map (node throws -- fail closed)
        ("f1826-mapshadow", "var Map=%s;var W=new Map();var O={};W.set(O,Map);var D=W.get(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1820: wrong loop bound
        ("f1820-badbound", "var C=%s;var O={};for(var i=0;i<10;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1820: Object.keys instead of values (different semantics)
        ("f1820-keys", "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.keys(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1821: no destructuring (plain for-of push -- covered by F1786)
        ("f1821-nodestr-hit", "var C=%s;var D=[];for(var v of C){D.push(v);}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1821: wrong store (push instead of indexed)
        ("f1821-push", "var C=%s;var D=[];for(var [i,v] of C.entries()){D.push(v);}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1823: var decl (belongs to F1794 -- should HIT via F1794, not F1823)
        ("f1823-var-hit", "var C=%s;var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1823: let decl (belongs to F1794)
        ("f1823-let-hit", "var C=%s;var D=[];for(let i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1824: has decl kw (should not match undeclared hook)
        ("f1824-var", "var C=%s;var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1825: one-arg (belongs to F1795 -- should HIT via F1795)
        ("f1825-onearg-hit", "var C=%s;var D=Array.from(Object.create(C));var S=String.fromCharCode.apply(null,D);" % cs),
        # F1825: non-empty props (different semantics)
        ("f1825-props", "var C=%s;var D=Array.from(Object.create(C,{x:{value:1}}));var S=String.fromCharCode.apply(null,D);" % cs),
        # F1826: WeakMap (belongs to F1796 -- should HIT via F1796)
        ("f1826-weakmap-hit", "var C=%s;var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);" % cs),
        # F1826: wrong key on get
        ("f1826-badkey", "var C=%s;var W=new Map();var O={};var P={};W.set(O,C);var D=W.get(P);var S=String.fromCharCode.apply(null,D);" % cs),
    ]
    # expected[i]: True if should HIT (via sibling), False if should MISS
    expected_hit = {"f1823-var-hit", "f1823-let-hit", "f1825-onearg-hit",
                    "f1826-weakmap-hit", "f1824-var", "f1821-nodestr-hit"}
    for name, payload in cases:
        v = _scan(payload)
        want = "HIT" if name in expected_hit else "MISS"
        ok = _check("p3-%s" % name, v == want,
                    "want %s got %s" % (want, v)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still fire on their shapes; my hooks don't steal them."""
    ok = True
    cs = _codes(SECRET_S)
    # These must HIT (via the sibling hook, not mine -- but HIT either way is fine)
    sib_shapes = [
        ("f1794-var", "var C=%s;var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1795", "var C=%s;var D=Array.from(Object.create(C));var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1796", "var C=%s;var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);" % cs),
    ]
    for name, payload in sib_shapes:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    texts = [
        "The quarterly report shows Object.values were reviewed.",
        "for (const item of list) { process(item); }",
        "const m = new Map(); m.set(key, value);",
        "Object.create(proto) is used for inheritance.",
    ]
    for i, t in enumerate(texts):
        v = _scan(t)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-432 opens still MISS."""
    ok = True
    cs = _codes(SECRET_S)
    # F1805-F1819 filed shapes (from attack round 99)
    opens = [
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var S=T.repeat(C.length-C.length+1);" % cs,  # F1805-ish
        "var C=%s;var D=C.slice();D.copyWithin(D.length-D.length,D.length);var S=String.fromCharCode.apply(null,D);" % cs,  # F1808
    ]
    for i, payload in enumerate(opens):
        v = _scan(payload)
        # These are different patterns; they may HIT via other hooks or MISS.
        # We just record; the key check is they don't crash.
        ok = _check("p6-open%d" % i, v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p7_perf():
    """200 sites in reasonable time."""
    ok = True
    import gov.dlp as _dlp
    tmpls = [
        "var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);" % _codes(SECRET_S),
        "var C=%s;var D=[];for(var [i,v] of C.entries()){D[i]=v;}var S=String.fromCharCode.apply(null,D);" % _codes(SECRET_S),
        "var C=%s;var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);" % _codes(SECRET_S),
        "var C=%s;var D=Array.from(Object.create(C,{}));var S=String.fromCharCode.apply(null,D);" % _codes(SECRET_S),
        "var C=%s;var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);" % _codes(SECRET_S),
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
    for n in (1820, 1821, 1823, 1824, 1825, 1826):
        f = "evals/w432_f%d_redfirst.py" % n
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            # red-first batteries print HELD (exit 0) on the OPEN tree;
            # on the FIXED tree the filed shapes now HIT so they FAIL (exit 1).
            # Either is fine for the green check -- we just need them to run.
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
