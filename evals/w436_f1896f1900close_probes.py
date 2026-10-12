#!/usr/bin/env python3
"""Wave-436 lane B close battery: F1896, F1897, F1898, F1899, F1900.

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w436_close_")
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

# Filed shapes (from FINDINGS.md, attack round 103)
F1896_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'';var RESULT=U;"
F1897_FILED = "var C={I};var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;"
F1898_FILED = "var C={I};var D=C.filter(function(){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1899_FILED = "var C={I};var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1900_FILED = "var C={I};var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 151."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1896_stmt_decode", "_js_f1897_stmt_decode",
              "_js_f1898_stmt_decode", "_js_f1899_stmt_decode",
              "_js_f1900_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1896_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 151, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1896", F1896_FILED), ("f1897", F1897_FILED),
                       ("f1898", F1898_FILED), ("f1899", F1899_FILED),
                       ("f1900", F1900_FILED)):
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
        # F1896: let, renamed idents
        ("f1896-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT+'';let RESULT=UU;" % cs),
        # F1897: const, renamed
        ("f1897-const", "const CC=%s;const DD=CC.slice();const SS=Reflect.apply(String.fromCharCode,null,DD);const RESULT=SS;" % cs),
        # F1898: let, renamed
        ("f1898-let", "let CC=%s;let DD=CC.filter(function(){return true;});let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        # F1899: renamed idents and param
        ("f1899-renamed", "var C2=%s;var D2=C2.slice();var L2=D2.find(function(x){return true;});if(L2===C2[0]){var S2=String.fromCharCode.apply(null,D2);}else{var S2='';}var RESULT=S2;" % cs),
        # F1900: const, renamed
        ("f1900-const", "const CC=%s;const DD=CC.slice();const LL=DD.findIndex(function(c){return true;});if(LL===0){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS, never mis-decode); sibling shapes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1896: non-empty additive rhs -> MISS
        ("f1896-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'x';var RESULT=U;" % cs, "MISS"),
        # F1896: left-empty additive -> MISS (narrow grammar)
        ("f1896-left", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;" % cs, "MISS"),
        # F1897: undefined thisArg -> MISS
        ("f1897-undef", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;" % cs, "MISS"),
        # F1897: numeric thisArg -> MISS
        ("f1897-num", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,0,D);var RESULT=S;" % cs, "MISS"),
        # F1898: false predicate -> MISS (D is empty, readout is '')
        ("f1898-false", "var C=%s;var D=C.filter(function(){return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "MISS"),
        # F1898: predicate with param -> HIT via a PRE-EXISTING production
        # (my narrow hook correctly returns None; the tree already covers
        # this shape -- verified: _js_f1898_stmt_decode is None on it).
        ("f1898-param", "var C=%s;var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "HIT"),
        # F1899: wrong guard index -> MISS
        ("f1899-idx1", "var C=%s;var D=C.slice();var L=D.find(function(c){return true;});if(L===C[1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1899: !== guard -> MISS
        ("f1899-neq", "var C=%s;var D=C.slice();var L=D.find(function(c){return true;});if(L!==C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1900: wrong guard constant -> MISS
        ("f1900-idx1", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1900: non-empty else branch -> MISS
        ("f1900-else", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='x';}var RESULT=S;" % cs, "MISS"),
        # Sibling: F1836 findLast guard -> HIT (my hooks must not steal)
        ("f1836-sibling", "var C=%s;var D=C.slice();var L=D.findLast(function(c){return true;});if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # Sibling: F1837 findLastIndex guard -> HIT (my hooks must not steal)
        ("f1837-sibling", "var C=%s;var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
    ]
    for name, payload, exp in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == exp, "got %s want %s" % (v, exp)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1836 (findLast guard) still HITs
        ("f1836", "var C=%s;var D=C.slice();var L=D.findLast(function(c){return true;});if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1837 (findLastIndex guard) still HITs
        ("f1837", "var C=%s;var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1890 (String.at(-1) guard) still HITs
        ("f1890", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var S=T;}else{var S='';}var RESULT=S;" % cs),
        # F1349 (flat staged reads) still HITs
        ("f1349", "var C=%s;var D=C.map(function(p){return [p];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
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
        "var t = 'abc'; var u = t + '';",  # additive identity, no C decl
        "var r = Reflect.apply(Math.max, null, [1, 2]);",
        "var d = [1, 2].filter(function() { return true; });",
        "var x = [1, 2, 3].find(function(c) { return true; });",
        "var y = [1, 2, 3].findIndex(function(c) { return true; });",
        "var s = 'token abc123'; console.log(s);",
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
        F1896_FILED.replace("{I}", cs),
        F1897_FILED.replace("{I}", cs),
        F1898_FILED.replace("{I}", cs),
        F1899_FILED.replace("{I}", cs),
        F1900_FILED.replace("{I}", cs),
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
    # Run the w435 lane-D battery as a green check (depth-1).
    # Note: w435d expects loopcount 150, but this lane adds one loop
    # (151). The pin will be repointed at merge; we verify no OTHER
    # regressions here.
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w435_f1885f1890close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w435d", not unexpected,
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
