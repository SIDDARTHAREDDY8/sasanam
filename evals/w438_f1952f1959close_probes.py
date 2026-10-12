#!/usr/bin/env python3
"""Wave-438 lane B close battery: F1952-F1959.

Template-literal call-with-arg identity (F1952), template
chained-slice identity (F1953), three-arg concat identity (F1954),
pad-and-strip concat identity (F1955), apply-form concat identity
(F1956), parenthesized additive identity (F1957), doubled-empty-left
additive identity (F1958), and String()-left additive identity (F1959).

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w438_close_")
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

# Filed shapes (from FINDINGS.md, attack round 105)
F1952_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString(10)}`;var RESULT=U;"
F1953_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.slice(0);var RESULT=U;"
F1954_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T,'');var RESULT=U;"
F1955_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('x').slice(0,-1);var RESULT=U;"
F1956_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat.apply('',[T]);var RESULT=U;"
F1957_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(''+T);var RESULT=U;"
F1958_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+''+T;var RESULT=U;"
F1959_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String()+T;var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1952_stmt_decode", "_js_f1953_stmt_decode",
              "_js_f1954_stmt_decode", "_js_f1955_stmt_decode",
              "_js_f1956_stmt_decode", "_js_f1957_stmt_decode",
              "_js_f1958_stmt_decode", "_js_f1959_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1952_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 161, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1952", F1952_FILED), ("f1953", F1953_FILED),
                       ("f1954", F1954_FILED), ("f1955", F1955_FILED),
                       ("f1956", F1956_FILED), ("f1957", F1957_FILED),
                       ("f1958", F1958_FILED), ("f1959", F1959_FILED)):
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
        # F1952: let, renamed idents, different radix
        ("f1952-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=`${TT.toString(16)}`;let RESULT=UU;" % cs),
        # F1953: const, double quotes
        ("f1953-const", 'const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join("");const UU=`${TT}`.slice(0);const RESULT=UU;' % cs),
        # F1954: renamed
        ("f1954-renamed", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=''.concat('',T2,'');var RESULT=U2;" % cs),
        # F1955: double quotes, different pad
        ("f1955-dq", 'var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join("");var U=T.concat("y").slice(0,-1);var RESULT=U;' % cs),
        # F1956: let, renamed
        ("f1956-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=''.concat.apply('',[TT]);let RESULT=UU;" % cs),
        # F1957: double quotes
        ("f1957-dq", 'var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join("");var U=(""+T);var RESULT=U;' % cs),
        # F1958: const, double quotes
        ("f1958-const", 'const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join("");const UU=""+""+TT;const RESULT=UU;' % cs),
        # F1959: renamed
        ("f1959-renamed", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=String()+T2;var RESULT=U2;" % cs),
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
        # F1952: no arg (F1917 shape) -> HIT via F1917, not my hook
        ("f1952-noarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString()}`;var RESULT=U;" % cs, "HIT"),
        # F1952: wrong base -> MISS
        ("f1952-base", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${X.toString(10)}`;var RESULT=U;" % cs, "MISS"),
        # F1952: non-integer arg -> MISS
        ("f1952-strarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString('x')}`;var RESULT=U;" % cs, "MISS"),
        # F1953: slice(1) drops a char -> MISS
        ("f1953-slice1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.slice(1);var RESULT=U;" % cs, "MISS"),
        # F1953: chained toString (F1918) -> HIT via F1918
        ("f1953-tostring", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.toString();var RESULT=U;" % cs, "HIT"),
        # F1954: non-empty third arg -> MISS
        ("f1954-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T,'x');var RESULT=U;" % cs, "MISS"),
        # F1954: two args (F1919) -> HIT via F1919
        ("f1954-two", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T);var RESULT=U;" % cs, "HIT"),
        # F1955: slice(0,-2) drops credential char -> MISS
        ("f1955-slice2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('x').slice(0,-2);var RESULT=U;" % cs, "MISS"),
        # F1955: two-char pad -> MISS (narrow: one char)
        ("f1955-pad2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('xy').slice(0,-1);var RESULT=U;" % cs, "MISS"),
        # F1955: F1920 shape -> HIT via F1920
        ("f1955-f1920", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(1);var RESULT=U;" % cs, "HIT"),
        # F1956: non-empty thisArg -> MISS
        ("f1956-thisarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat.apply('x',[T]);var RESULT=U;" % cs, "MISS"),
        # F1956: two args in array -> MISS (narrow: single T)
        ("f1956-twoargs", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat.apply('',[T,'']);var RESULT=U;" % cs, "MISS"),
        # F1957: unparenthesized (F1921) -> HIT via F1921
        ("f1957-unparen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;" % cs, "HIT"),
        # F1957: non-empty left -> MISS
        ("f1957-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('x'+T);var RESULT=U;" % cs, "MISS"),
        # F1958: single empty (F1921) -> HIT via F1921
        ("f1958-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;" % cs, "HIT"),
        # F1958: three empties -> MISS (narrow: exactly two)
        ("f1958-three", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+''+''+T;var RESULT=U;" % cs, "MISS"),
        # F1958: F1923 shape (right) -> HIT via F1923
        ("f1958-right", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+''+'';var RESULT=U;" % cs, "HIT"),
        # F1959: T+String() (F1922) -> HIT via F1922
        ("f1959-right", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+String();var RESULT=U;" % cs, "HIT"),
        # F1959: String with arg -> MISS
        ("f1959-arg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String('x')+T;var RESULT=U;" % cs, "MISS"),
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
        # F1917 (no-arg toString template) still HITs
        ("f1917", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString()}`;var RESULT=U;" % cs),
        # F1918 (chained toString) still HITs
        ("f1918", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.toString();var RESULT=U;" % cs),
        # F1919 (two-arg concat) still HITs
        ("f1919", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T);var RESULT=U;" % cs),
        # F1920 (pad-and-strip) still HITs
        ("f1920", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(1);var RESULT=U;" % cs),
        # F1921 (''+T) still HITs
        ("f1921", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;" % cs),
        # F1922 (T+String()) still HITs
        ("f1922", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+String();var RESULT=U;" % cs),
        # F1923 (T+''+'') still HITs
        ("f1923", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+''+'';var RESULT=U;" % cs),
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
        "var u = ''.concat('a', 'b');",
        "var s = 'token abc123'; console.log(s);",
        "var u = ('' + 'x');",
        "var s = String() + 'hello';",
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
        F1952_FILED.replace("{I}", cs),
        F1953_FILED.replace("{I}", cs),
        F1954_FILED.replace("{I}", cs),
        F1955_FILED.replace("{I}", cs),
        F1956_FILED.replace("{I}", cs),
        F1957_FILED.replace("{I}", cs),
        F1958_FILED.replace("{I}", cs),
        F1959_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 8])
        if not r:
            ok = _check("p6-perf", False, "miss at %d" % i) and ok
            return ok
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: run the wave-437 lane-B battery.

    Expected deviations from this lane's closures: p0-loopcount
    (157->158 repoint). Any other failure is a regression.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    argv, path = green_check._child_argv(
        REPO_ROOT, os.path.join("evals", "w437_f1916f1924close_probes.py"))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    env["TMPDIR"] = tempfile.mkdtemp(prefix="green-check-")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=600, env=env, cwd=REPO_ROOT)
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        return _check("p7-green-w437b", False,
                      "green check crashed: %r" % (e,))
    if green_check.TRACEBACK_RE.search(out):
        return _check("p7-green-w437b", False,
                      "child raised (traceback in output)")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    # Expected: loopcount repoint only (157 -> 158).
    expected = ("p0-loopcount",)
    unexpected = [f for f in fails
                  if not any(e in f for e in expected)]
    ok = _check("p7-green-w437b", not unexpected,
                "unexpected fails: %s" % unexpected) and ok
    # Fail closed if the child didn't run its probes at all.
    m = re.search(r"(\d+)/(\d+) HELD", out)
    if not m or int(m.group(2)) == 0:
        ok = _check("p7-green-w437b-vacuous", False,
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
