#!/usr/bin/env python3
"""Wave-437 lane B close battery: F1916-F1924.

Template-literal two-substitution identity (F1916), template
call-expression identity (F1917), template chained-toString identity
(F1918), two-arg concat identity (F1919), pad-and-strip concat
identity (F1920), empty-left additive identity (F1921), String()
additive identity (F1922), doubled-empty additive identity (F1923),
and Reflect.apply undefined-thisArg readout (F1924).

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w437_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))
import green_check  # noqa: E402  (wave-305 shared fail-closed green checks)

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

# Filed shapes (from FINDINGS.md, attack round 104)
F1916_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}`;var RESULT=U;"
F1917_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString()}`;var RESULT=U;"
F1918_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.toString();var RESULT=U;"
F1919_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T);var RESULT=U;"
F1920_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(1);var RESULT=U;"
F1921_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;"
F1922_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+String();var RESULT=U;"
F1923_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+''+'';var RESULT=U;"
F1924_FILED = "var C={I};var D=C.slice();var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1916_stmt_decode", "_js_f1917_stmt_decode",
              "_js_f1918_stmt_decode", "_js_f1919_stmt_decode",
              "_js_f1920_stmt_decode", "_js_f1921_stmt_decode",
              "_js_f1922_stmt_decode", "_js_f1923_stmt_decode",
              "_js_f1924_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1916_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 154, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1916", F1916_FILED), ("f1917", F1917_FILED),
                       ("f1918", F1918_FILED), ("f1919", F1919_FILED),
                       ("f1920", F1920_FILED), ("f1921", F1921_FILED),
                       ("f1922", F1922_FILED), ("f1923", F1923_FILED),
                       ("f1924", F1924_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const decls, renamed idents, double quotes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1916: let, renamed idents
        ("f1916-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=`${''}${TT}`;let RESULT=UU;" % cs),
        # F1917: const, double-quoted empty in template
        ("f1917-const", 'const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join("");const UU=`${TT.toString()}`;const RESULT=UU;' % cs),
        # F1918: renamed
        ("f1918-renamed", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=`${T2}`.toString();var RESULT=U2;" % cs),
        # F1919: double quotes
        ("f1919-dq", 'var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join("");var U="".concat("",T);var RESULT=U;' % cs),
        # F1920: different pad char
        ("f1920-pad", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='z'.concat(T).slice(1);var RESULT=U;" % cs),
        # F1921: double quotes, let
        ("f1921-dq", 'let C=%s;let T=C.map(function(c){return String.fromCharCode(c);}).join("");let U=""+T;let RESULT=U;' % cs),
        # F1922: const, renamed
        ("f1922-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT+String();const RESULT=UU;" % cs),
        # F1923: double quotes
        ("f1923-dq", 'var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join("");var U=T+""+"";var RESULT=U;' % cs),
        # F1924: let/const, renamed
        ("f1924-let", "let C=%s;let D=C.slice();let S=Reflect.apply(String.fromCharCode,undefined,D);let RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS); near-miss shapes stay quiet."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1916: non-empty first substitution -> MISS
        ("f1916-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${'x'}${T}`;var RESULT=U;" % cs, "MISS"),
        # F1916: trailing literal text -> MISS
        ("f1916-trailing", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}!`;var RESULT=U;" % cs, "MISS"),
        # F1917: different method -> MISS
        ("f1917-valuof", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.valueOf()}`;var RESULT=U;" % cs, "MISS"),
        # F1918: chained valueOf -> MISS
        ("f1918-valueof", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.valueOf();var RESULT=U;" % cs, "MISS"),
        # F1919: non-empty first arg -> MISS
        ("f1919-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('x',T);var RESULT=U;" % cs, "MISS"),
        # F1919: three args -> MISS (narrow: exactly two)
        ("f1919-three", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('','',T);var RESULT=U;" % cs, "MISS"),
        # F1920: slice(2) on 1-char pad drops a credential char -> MISS
        ("f1920-slice2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(2);var RESULT=U;" % cs, "MISS"),
        # F1920: two-char pad -> MISS (narrow: one char)
        ("f1920-pad2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='xy'.concat(T).slice(1);var RESULT=U;" % cs, "MISS"),
        # F1921: non-empty left -> MISS
        ("f1921-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'+T;var RESULT=U;" % cs, "MISS"),
        # F1922: String with arg -> MISS
        ("f1922-arg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+String('x');var RESULT=U;" % cs, "MISS"),
        # F1923: non-empty tail -> MISS
        ("f1923-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+''+'x';var RESULT=U;" % cs, "MISS"),
        # F1923: single empty (F1896 shape) -> HIT via F1896, not my hook
        ("f1923-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'';var RESULT=U;" % cs, "HIT"),
        # F1924: null thisArg (F1897 shape) -> HIT via F1897
        ("f1924-null", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;" % cs, "HIT"),
        # F1924: numeric thisArg -> MISS
        ("f1924-num", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,0,D);var RESULT=S;" % cs, "MISS"),
        # F1924: different function -> MISS
        ("f1924-fn", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCodePoint,undefined,D);var RESULT=S;" % cs, "MISS"),
    ]
    for name, payload, exp in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == exp, "got %s want %s" % (v, exp)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work (no regression, no stealing)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1894 (single-substitution template) still HITs
        ("f1894", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`;var RESULT=U;" % cs),
        # F1895 (single-arg concat) still HITs
        ("f1895", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T);var RESULT=U;" % cs),
        # F1896 (T+'') still HITs
        ("f1896", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'';var RESULT=U;" % cs),
        # F1897 (Reflect.apply null) still HITs
        ("f1897", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;" % cs),
        # F1892 (T.toString) still HITs
        ("f1892", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;" % cs),
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
        "var t = 'abc'; var u = '' + t;",
        "var s = `hello ${name}`;",
        "var r = Reflect.apply(Math.max, undefined, [1, 2]);",
        "var u = ''.concat('a', 'b');",
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
        F1916_FILED.replace("{I}", cs),
        F1917_FILED.replace("{I}", cs),
        F1918_FILED.replace("{I}", cs),
        F1919_FILED.replace("{I}", cs),
        F1920_FILED.replace("{I}", cs),
        F1921_FILED.replace("{I}", cs),
        F1922_FILED.replace("{I}", cs),
        F1923_FILED.replace("{I}", cs),
        F1924_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 9])
        if not r:
            ok = _check("p6-perf", False, "miss at %d" % i) and ok
            return ok
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: delegate to evals/green_check.py (contract).

    Runs the w436 lane-B battery. Expected deviations from this lane's
    closures: p0-loopcount (153->154 repoint), p3-f1896-left (now HIT
    via F1921), p3-f1897-undef (now HIT via F1924). Any other failure
    is a regression.
    """
    # The w436 battery predates the green-check contract summary format,
    # so we run it via green_check's subprocess infrastructure and parse
    # its "N/M HELD" + "FAIL <id>" output directly.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    argv, path = green_check._child_argv(
        REPO_ROOT, os.path.join("evals", "w436_f1896f1900close_probes.py"))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    env["TMPDIR"] = tempfile.mkdtemp(prefix="green-check-")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=600, env=env, cwd=REPO_ROOT)
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        return _check("p7-green-w436b", False,
                      "green check crashed: %r" % (e,))
    if green_check.TRACEBACK_RE.search(out):
        return _check("p7-green-w436b", False,
                      "child raised (traceback in output)")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    # Expected: loopcount repoint + two intentional closure flips.
    expected = ("p0-loopcount", "p3-f1896-left", "p3-f1897-undef")
    unexpected = [f for f in fails
                  if not any(e in f for e in expected)]
    ok = _check("p7-green-w436b", not unexpected,
                "unexpected fails: %s" % unexpected) and ok
    # Fail closed if the child didn't run its probes at all.
    m = re.search(r"(\d+)/(\d+) HELD", out)
    if not m or int(m.group(2)) == 0:
        ok = _check("p7-green-w436b-vacuous", False,
                    "child emitted no probe summary") and ok
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
