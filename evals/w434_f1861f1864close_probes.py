#!/usr/bin/env python3
"""Wave-434 lane D close battery: F1861, F1862, F1863, F1864.

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
F1861_FILED = "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-(C.length-C.length)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1862_FILED = "var C={I};var D=C.with(C.length-C.length,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1863_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(2-1);var RESULT=U;"
F1864_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.split('',T.length);var U=A.join('');var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 143."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1861_stmt_decode", "_js_f1862_stmt_decode",
              "_js_f1863_stmt_decode", "_js_f1864_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1861_stmt_decode," in src,
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
    for name, tmpl in (("f1861", F1861_FILED), ("f1862", F1862_FILED),
                       ("f1863", F1863_FILED), ("f1864", F1864_FILED)):
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
        ("f1861-let", "let CC=%s;let DD=[];for(let ii=0;ii<CC.length;ii++){DD.push(CC.at(ii-(CC.length-CC.length)));}let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1861-const", "const CC=%s;let DD=[];for(let ii=0;ii<CC.length;ii++){DD.push(CC.at(ii-(CC.length-CC.length)));}const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;" % cs),
        ("f1862-let", "let CC=%s;let DD=CC.with(CC.length-CC.length,CC[0]);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1863-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.repeat(2-1);let RESULT=UU;" % cs),
        ("f1863-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.repeat(2-1);const RESULT=UU;" % cs),
        ("f1864-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let AA=TT.split('',TT.length);let UU=AA.join('');let RESULT=UU;" % cs),
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
        # F1861: wrong index form (i-i+i belongs to F1828, not F1861)
        ("f1861-wrongidx", "var C=%s;var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1861: shadowed String
        ("f1861-strshadow", "var String=%s;var D=[];for(var i=0;i<String.length;i++){D.push(String.at(i-(String.length-String.length)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1862: literal 0 index (covered by sibling F1772 -> expect HIT)
        ("f1862-litidx", "var C=%s;var D=C.with(0,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1862: wrong value (C[1] instead of C[0])
        ("f1862-wrongval", "var C=%s;var D=C.with(C.length-C.length,C[1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1863: C-based count (belongs to F1805, not F1863)
        ("f1863-cbased", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;" % cs),
        # F1863: repeat(2) -- not identity, node gives doubled string
        ("f1863-repeat2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(2);var RESULT=U;" % cs),
        # F1864: wrong split separator (F1847 requires join('~') for T; this
        # shape with join('') is not F1847's grammar -> expect MISS)
        ("f1864-wrongsep", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.split('~'.repeat(1));var U=A.join('');var RESULT=U;" % cs),
        # F1864: wrong limit base
        ("f1864-wronglim", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.split('',C.length);var U=A.join('');var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        # Note: some of these SHOULD hit via sibling hooks (f1861-wrongidx via F1828,
        # f1863-cbased via F1805, f1864-wrongsep via F1847). We check they don't
        # MIS-decode: either MISS or HIT-via-sibling is fine, but the verdict must
        # not be an error. For strict fail-closed we require MISS only where no
        # sibling covers the shape.
        if name in ("f1861-wrongidx", "f1863-cbased", "f1862-litidx"):
            # covered by siblings F1828/F1805/F1772 -> expect HIT
            ok = _check("p3-%s" % name, v == "HIT", "got %s" % v) and ok
        else:
            ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression); my hooks don't steal siblings."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1828 (at i-i+i rebuild) still HITs
        ("f1828", "var C=%s;var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1831 (with literal on slice) still HITs
        ("f1831", "var C=%s;var D=C.slice();var E=D.with(0,D[0]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1805 (repeat C-based) still HITs
        ("f1805", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;" % cs),
        # F1847 (split computed sep) still HITs
        ("f1847", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('~');var U=T.split('~'.repeat(1)).join('');var RESULT=U;" % cs),
        # F1840 (at(-1) guard) still HITs
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
        "var arr = [1,2,3]; var s = arr.join(',');",
        "var t = 'abc'; var u = t.repeat(3);",
        "var a = 'a,b,c'; var parts = a.split(',');",
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
        F1861_FILED.replace("{I}", cs),
        F1862_FILED.replace("{I}", cs),
        F1863_FILED.replace("{I}", cs),
        F1864_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 4])
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
    # Note: w433d expects loopcount 142, but this lane adds one loop
    # (143). The pin will be repointed at merge; we verify no OTHER
    # regressions here.
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w433_f1843f1847close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    # Extract failures; wave-434 merge updated pins to 146
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
                print("  %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")

if __name__ == "__main__":
    main()
