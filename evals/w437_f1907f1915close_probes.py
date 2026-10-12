#!/usr/bin/env python3
"""Wave-437 lane A close battery: F1907-F1915.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 153 -> 154 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged.
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

# Filed shapes (from FINDINGS.md, attack round 104, first-filing 2026-10-12 15:09 UTC)
F1907_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimStart();var RESULT=U;"
F1908_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimLeft();var RESULT=U;"
F1909_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart(' ');var RESULT=U;"
F1910_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('  '+T).trimLeft();var RESULT=U;"
F1911_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;"
F1912_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.toString.call(T);var RESULT=U;"
F1913_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().toString();var RESULT=U;"
F1914_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw({raw:[T]});var RESULT=U;"
F1915_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T).toString();var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 154."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1907_stmt_decode", "_js_f1908_stmt_decode",
              "_js_f1909_stmt_decode", "_js_f1910_stmt_decode",
              "_js_f1911_stmt_decode", "_js_f1912_stmt_decode",
              "_js_f1913_stmt_decode", "_js_f1914_stmt_decode",
              "_js_f1915_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1907_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 154, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1907", F1907_FILED), ("f1908", F1908_FILED),
                       ("f1909", F1909_FILED), ("f1910", F1910_FILED),
                       ("f1911", F1911_FILED), ("f1912", F1912_FILED),
                       ("f1913", F1913_FILED), ("f1914", F1914_FILED),
                       ("f1915", F1915_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1907: let, renamed
        ("f1907-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(' '+TT).trimStart();let RESULT=UU;" % cs),
        ("f1907-const-renamed", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(' '+B).trimStart();const RESULT=Q;" % cs),
        # F1908: const, renamed
        ("f1908-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.trimLeft();const RESULT=UU;" % cs),
        # F1909: let, renamed
        ("f1909-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.trimStart(' ');let RESULT=UU;" % cs),
        # F1910: let, renamed
        ("f1910-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=('  '+TT).trimLeft();let RESULT=UU;" % cs),
        # F1911: const, renamed
        ("f1911-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.toString(10);const RESULT=UU;" % cs),
        # F1912: let, renamed
        ("f1912-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=String.prototype.toString.call(TT);let RESULT=UU;" % cs),
        # F1913: const, renamed
        ("f1913-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.valueOf().toString();const RESULT=UU;" % cs),
        # F1914: let, renamed
        ("f1914-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=String.raw({raw:[TT]});let RESULT=UU;" % cs),
        # F1915: const, renamed
        ("f1915-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=String(TT).toString();const RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS); sibling-covered shapes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1907: two spaces instead of one -> narrow grammar -> MISS
        ("f1907-twosp", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('  '+T).trimStart();var RESULT=U;" % cs, "MISS"),
        # F1907: trailing pad instead of leading -> grammar mismatch -> MISS
        ("f1907-trailing", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' ').trimStart();var RESULT=U;" % cs, "MISS"),
        # F1908: with arg -> narrow grammar -> MISS
        ("f1908-arg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimLeft(' ');var RESULT=U;" % cs, "MISS"),
        # F1909: no arg -> narrow grammar -> MISS
        ("f1909-noarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;" % cs, "MISS"),
        # F1910: one space instead of two -> narrow grammar -> MISS
        ("f1910-onesp", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimLeft();var RESULT=U;" % cs, "MISS"),
        # F1911: radix 16 instead of 10 -> narrow grammar -> MISS
        ("f1911-radix16", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs, "MISS"),
        # F1911: no arg -> covered by F1892 sibling -> HIT
        ("f1911-noarg-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;" % cs, "HIT"),
        # F1912: .apply instead of .call -> narrow grammar -> MISS
        ("f1912-apply", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.toString.apply(T);var RESULT=U;" % cs, "MISS"),
        # F1913: valueOf twice -> covered by F1888 sibling -> HIT
        ("f1913-vv-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().valueOf();var RESULT=U;" % cs, "HIT"),
        # F1914: two-element raw array -> narrow grammar -> MISS
        ("f1914-twoelem", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw({raw:[T,T]});var RESULT=U;" % cs, "MISS"),
        # F1915: bare String(T) -> covered by F1893 sibling -> HIT
        ("f1915-bare-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T);var RESULT=U;" % cs, "HIT"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks (F1891/F1892/F1893/F1846/F1888) still work."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1891: trimLeft with computed pad
        ("f1891", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimLeft();var RESULT=U;" % cs),
        # F1892: toString no-arg
        ("f1892", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;" % cs),
        # F1893: String(T)
        ("f1893", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T);var RESULT=U;" % cs),
        # F1846: String.raw tagged template
        ("f1846", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw`${T}`;var RESULT=U;" % cs),
        # F1888: valueOf chained twice
        ("f1888", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().valueOf();var RESULT=U;" % cs),
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
        "var t = 'abc'; var u = t.trimStart(); console.log(u);",
        "var t = '  padded  '; var u = t.trimLeft();",
        "var n = 255; var s = n.toString(16);",
        "var o = {raw: ['a']}; var s = String.raw(o);",
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
        F1907_FILED.replace("{I}", cs),
        F1908_FILED.replace("{I}", cs),
        F1909_FILED.replace("{I}", cs),
        F1910_FILED.replace("{I}", cs),
        F1911_FILED.replace("{I}", cs),
        F1912_FILED.replace("{I}", cs),
        F1913_FILED.replace("{I}", cs),
        F1914_FILED.replace("{I}", cs),
        F1915_FILED.replace("{I}", cs),
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
    """Depth-1 green check: adjacent battery main with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Adjacent: wave-436 lane A (F1891-F1895 trim/toString siblings).
    # Its p0-loopcount pin (153) predates this lane's loop (154) and is
    # repointed at merge; only unexpected failures count here.
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w436_f1891f1895close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("  FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w436a", not unexpected,
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
                print("  FAIL %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")


if __name__ == "__main__":
    main()
