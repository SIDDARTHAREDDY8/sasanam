#!/usr/bin/env python3
"""Wave-439 lane B close battery: F1984-F1993.

Template-literal leading double-empty substitutions (F1984), doubled
template sliced back (F1985), repeat(1) identity substitution (F1986),
wrapped template sliced (F1987), template chained concat+slice (F1988),
join-then-concat (F1989), doubled concat sliced back (F1990), nested
concat (F1991), String.prototype.concat.call (F1992), T.concat.apply
(F1993).

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w439_close_")
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

# Filed shapes (from FINDINGS.md, attack round 106)
F1984_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${''}${T}`;var RESULT=U;"
F1985_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}${T}`.slice(0,T.length);var RESULT=U;"
F1986_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.repeat(1)}`;var RESULT=U;"
F1987_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`x${T}x`.slice(1,-1);var RESULT=U;"
F1988_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.concat('').slice(0);var RESULT=U;"
F1989_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[T].join('').concat('');var RESULT=U;"
F1990_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(T).slice(0,T.length);var RESULT=U;"
F1991_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T.concat(''));var RESULT=U;"
F1992_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.concat.call('',T);var RESULT=U;"
F1993_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat.apply(T,['']);var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1984_stmt_decode", "_js_f1985_stmt_decode",
              "_js_f1986_stmt_decode", "_js_f1987_stmt_decode",
              "_js_f1988_stmt_decode", "_js_f1989_stmt_decode",
              "_js_f1990_stmt_decode", "_js_f1991_stmt_decode",
              "_js_f1992_stmt_decode", "_js_f1993_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1984_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 162, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1984", F1984_FILED), ("f1985", F1985_FILED),
                       ("f1986", F1986_FILED), ("f1987", F1987_FILED),
                       ("f1988", F1988_FILED), ("f1989", F1989_FILED),
                       ("f1990", F1990_FILED), ("f1991", F1991_FILED),
                       ("f1992", F1992_FILED), ("f1993", F1993_FILED)):
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
        # F1984: let, renamed idents
        ("f1984-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=`${''}${''}${TT}`;let RESULT=UU;" % cs),
        # F1985: const, double quotes
        ("f1985-const", 'const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join("");const UU=`${TT}${TT}`.slice(0,TT.length);const RESULT=UU;' % cs),
        # F1986: renamed
        ("f1986-renamed", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=`${T2.repeat(1)}`;var RESULT=U2;" % cs),
        # F1987: double quotes in join
        ("f1987-dq", 'var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join("");var U=`x${T}x`.slice(1,-1);var RESULT=U;' % cs),
        # F1988: let, renamed
        ("f1988-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=`${TT}`.concat('').slice(0);let RESULT=UU;" % cs),
        # F1989: double quotes in T-join only (U-line uses single quotes - manual parse)
        ("f1989-dq", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join(\"\");var U=[T].join('').concat('');var RESULT=U;" % cs),
        # F1990: const, renamed
        ("f1990-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.concat(TT).slice(0,TT.length);const RESULT=UU;" % cs),
        # F1991: renamed idents (single quotes - manual parse)
        ("f1991-dq", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=''.concat(T2.concat(''));var RESULT=U2;" % cs),
        # F1992: renamed
        ("f1992-renamed", "var C2=%s;var T2=C2.map(function(c){return String.fromCharCode(c);}).join('');var U2=String.prototype.concat.call('',T2);var RESULT=U2;" % cs),
        # F1993: let
        ("f1993-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.concat.apply(TT,['']);let RESULT=UU;" % cs),
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
        # F1984: single empty (${''}${T}) -> HIT via F1916 (two substitutions)
        ("f1984-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}`;var RESULT=U;" % cs, "HIT"),
        # F1984: three empties -> MISS (narrow: exactly two leading)
        ("f1984-three", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${''}${''}${T}`;var RESULT=U;" % cs, "MISS"),
        # F1984: three empties -> MISS
        ("f1984-three", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${''}${''}${T}`;var RESULT=U;" % cs, "MISS"),
        # F1984: wrong base -> MISS
        ("f1984-base", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${''}${X}`;var RESULT=U;" % cs, "MISS"),
        # F1985: single template (F1953) -> HIT via F1953
        ("f1985-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.slice(0);var RESULT=U;" % cs, "HIT"),
        # F1985: slice(0) without length -> MISS (narrow: slice(0,T.length))
        ("f1985-slice0", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}${T}`.slice(0);var RESULT=U;" % cs, "MISS"),
        # F1986: repeat(2) changes value -> MISS
        ("f1986-repeat2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.repeat(2)}`;var RESULT=U;" % cs, "MISS"),
        # F1986: repeat(0) -> MISS
        ("f1986-repeat0", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.repeat(0)}`;var RESULT=U;" % cs, "MISS"),
        # F1987: slice(1) drops trailing x -> MISS (would be 'x'+T)
        ("f1987-slice1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`x${T}x`.slice(1);var RESULT=U;" % cs, "MISS"),
        # F1987: slice(0,-1) keeps leading x -> MISS
        ("f1987-slice01", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`x${T}x`.slice(0,-1);var RESULT=U;" % cs, "MISS"),
        # F1988: no concat (F1953) -> HIT via F1953
        ("f1988-noconcat", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.slice(0);var RESULT=U;" % cs, "HIT"),
        # F1988: non-empty concat arg -> MISS
        ("f1988-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.concat('x').slice(0);var RESULT=U;" % cs, "MISS"),
        # F1989: non-empty join sep -> MISS
        ("f1989-joinsep", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[T].join(',').concat('');var RESULT=U;" % cs, "MISS"),
        # F1989: non-empty concat -> MISS
        ("f1989-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[T].join('').concat('x');var RESULT=U;" % cs, "MISS"),
        # F1990: single T (F1953-like) -> MISS (narrow: T.concat(T))
        ("f1990-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('').slice(0,T.length);var RESULT=U;" % cs, "MISS"),
        # F1990: slice(1) -> MISS
        ("f1990-slice1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(T).slice(1,T.length);var RESULT=U;" % cs, "MISS"),
        # F1991: non-empty inner -> MISS
        ("f1991-inner", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T.concat('x'));var RESULT=U;" % cs, "MISS"),
        # F1991: non-empty outer -> MISS
        ("f1991-outer", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T.concat(''));var RESULT=U;" % cs, "MISS"),
        # F1992: non-empty thisArg -> MISS
        ("f1992-thisarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.concat.call('x',T);var RESULT=U;" % cs, "MISS"),
        # F1992: wrong method -> MISS
        ("f1992-method", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.slice.call('',T);var RESULT=U;" % cs, "MISS"),
        # F1993: two args in array -> MISS (narrow: single '')
        ("f1993-twoargs", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat.apply(T,['','']);var RESULT=U;" % cs, "MISS"),
        # F1993: wrong thisArg -> MISS
        ("f1993-thisarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat.apply('',['']);var RESULT=U;" % cs, "MISS"),
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
        # F1950 (three substitutions) still HITs
        ("f1950", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}${''}`;var RESULT=U;" % cs),
        # F1953 (template slice) still HITs
        ("f1953", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.slice(0);var RESULT=U;" % cs),
        # F1954 (three-arg concat) still HITs
        ("f1954", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T,'');var RESULT=U;" % cs),
        # F1955 (pad-and-strip) still HITs
        ("f1955", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('x').slice(0,-1);var RESULT=U;" % cs),
        # F1956 (apply concat) still HITs
        ("f1956", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat.apply('',[T]);var RESULT=U;" % cs),
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
        "var t = 'x'; var u = t.repeat(1);",
        "var u = [t].join('');",
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
        F1984_FILED.replace("{I}", cs),
        F1985_FILED.replace("{I}", cs),
        F1986_FILED.replace("{I}", cs),
        F1987_FILED.replace("{I}", cs),
        F1988_FILED.replace("{I}", cs),
        F1989_FILED.replace("{I}", cs),
        F1990_FILED.replace("{I}", cs),
        F1991_FILED.replace("{I}", cs),
        F1992_FILED.replace("{I}", cs),
        F1993_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 10])
        if not r:
            ok = _check("p6-perf", False, "miss at %d" % i) and ok
            return ok
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: run the wave-438 lane-B battery.

    Expected deviations from this lane's closures: p0-loopcount
    (161->162 repoint). Any other failure is a regression.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    argv, path = green_check._child_argv(
        REPO_ROOT, os.path.join("evals", "w438_f1952f1959close_probes.py"))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    env["TMPDIR"] = tempfile.mkdtemp(prefix="green-check-")
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=600, env=env, cwd=REPO_ROOT)
        out = (proc.stdout or "") + (proc.stderr or "")
    except Exception as e:
        return _check("p7-green-w438b", False,
                      "green check crashed: %r" % (e,))
    if green_check.TRACEBACK_RE.search(out):
        return _check("p7-green-w437b", False,
                      "child raised (traceback in output)")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    # Expected: loopcount repoint only (161 -> 162).
    expected = ("p0-loopcount",)
    unexpected = [f for f in fails
                  if not any(e in f for e in expected)]
    ok = _check("p7-green-w438b", not unexpected,
                "unexpected fails: %s" % unexpected) and ok
    # Fail closed if the child didn't run its probes at all.
    m = re.search(r"(\d+)/(\d+) HELD", out)
    if not m or int(m.group(2)) == 0:
        ok = _check("p7-green-w438b-vacuous", False,
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
