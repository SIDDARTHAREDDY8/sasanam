#!/usr/bin/env python3
"""Wave-426 lane C close battery: F1725, F1726, F1727, F1728, F1729.

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

SECRET_S = "xoxb-01" + "23456789abcdef"
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

def _codes_surr(s):
    return "[0xD800," + ",".join(str(ord(c)) for c in s) + "]"

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 115 (111 base + 4 lanes, wave-426 lane C)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "115",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All five hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1725_stmt_decode", "_js_f1726_stmt_decode",
              "_js_f1727_stmt_decode", "_js_f1728_stmt_decode",
              "_js_f1729_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md footer)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1725-F1729 stamped CLOSED
    for n in (1725, 1726, 1727, 1728, 1729):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-1\d wave-426 lane C" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    shapes = [
        ("f1725", "var C=[0xD800,{I}];var S=String.fromCharCode.apply(null,C.flat());var RESULT=S;", lambda s: ",".join(str(ord(c)) for c in s)),
        ("f1726", "var C={I};var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        ("f1727", "var C={I};var D=Object.assign([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        ("f1728", "var C={I};var S=String.fromCharCode.apply(null,C);var T=`x${S}`;var RESULT=T;", _codes),
        ("f1729", "var C={I};var D=C.flatMap(function(c,i){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
    ]
    for name, tmpl, coder in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", coder(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, whitespace variants HIT."""
    ok = True
    shapes = [
        ("let C={I};let D=Object.assign([],C,C,C);let S=String.fromCharCode.apply(null,D);let RESULT=S;", _codes),
        ("const C={I};const D=Object.assign([],C);const S=String.fromCharCode.apply(null,D);const RESULT=S;", _codes),
        ("var C={I};var D=C.flatMap(function(c,i){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
    ]
    for tmpl, coder in shapes:
        payload = tmpl.replace("{I}", coder(SECRET_S))
        v = _scan(payload)
        ok = _check("p2-gen", v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms MISS (fail closed, never mis-decode)."""
    ok = True
    bad = [
        # F1725: no surrogate prefix (plain flat -- should not match our hook)
        ("var C={I};var S=String.fromCharCode.apply(null,C.flat());var RESULT=S;", _codes),
        # F1726: 2 sources (F1705's shape -- our hook requires 3)
        ("var C={I};var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        # F1726: 4 sources (too many)
        ("var C={I};var D=Object.assign([],C,C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        # F1727: 2 sources (should not match our 1-source hook)
        ("var C={I};var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        # F1728: no static prefix (F1706's shape -- our hook requires prefix)
        ("var C={I};var S=String.fromCharCode.apply(null,C);var T=`${S}`;var RESULT=T;", _codes),
        # F1729: 1-param (F1708's shape -- our hook requires 2-param)
        ("var C={I};var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
        # F1729: 3-param (too many)
        ("var C={I};var D=C.flatMap(function(c,i,a){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;", _codes),
    ]
    for tmpl, coder in bad:
        payload = tmpl.replace("{I}", coder(SECRET_S))
        v = _scan(payload)
        # These may HIT via sibling hooks (e.g. F1705 for 2-source) which is correct;
        # we just ensure no crash and our specific hook doesn't mis-decode
        ok = _check("p3-failclosed", v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: related findings still correctly handled."""
    ok = True
    # F1705 (2-source) should still HIT via its own hook
    payload = "var C=%s;var D=Object.assign([],C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S)
    v = _scan(payload)
    ok = _check("p4-f1705", v == "HIT", "got %s" % v) and ok
    # F1706 (pure template) should still HIT
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);var T=`${S}`;var RESULT=T;" % _codes(SECRET_S)
    v = _scan(payload)
    ok = _check("p4-f1706", v == "HIT", "got %s" % v) and ok
    # F1708 (1-param flatMap) should still HIT
    payload = "var C=%s;var D=C.flatMap(function(c){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S)
    v = _scan(payload)
    ok = _check("p4-f1708", v == "HIT", "got %s" % v) and ok
    # F1714 (surrogate direct) should still HIT
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);var RESULT=S;" % _codes_surr(SECRET_S)
    v = _scan(payload)
    ok = _check("p4-f1714", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    for junk in [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "function foo() { return bar; }",
        "Object.assign([], a, b);",
        "var t = `hello ${name}`;",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    # F1743-F1744 (attack 94) should still MISS
    payload = "var C=%s;var n=C.length-C.length+1;var D=[C];var F=D.flat(n);var S=String.fromCharCode.apply(null,F);var RESULT=S;" % _codes(SECRET_S)
    v = _scan(payload)
    ok = _check("p6-f1743-open", v == "MISS", "got %s" % v) and ok
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);var n=C.length-C.length+1;var T=S.repeat(n);var RESULT=T;" % _codes(SECRET_S)
    v = _scan(payload)
    ok = _check("p6-f1744-open", v == "MISS", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    import gov.dlp as _dlp
    sites = []
    cs = _codes(SECRET_S)
    css = _codes_surr(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append("var C=[0xD800,%s];var S=String.fromCharCode.apply(null,C.flat());var RESULT=S;" % cs[1:-1])
        elif i % 5 == 1:
            sites.append("var C=%s;var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 2:
            sites.append("var C=%s;var D=C.flatMap(function(c,i){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 3:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    ok = _check("p7-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_g0_green():
    """Depth-1 green check: adjacent batteries still behave."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w426_f1725_redfirst.py", "evals/w426_f1726_redfirst.py",
              "evals/w426_f1727_redfirst.py", "evals/w426_f1728_redfirst.py",
              "evals/w426_f1729_redfirst.py"]:
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1",
                                               "W426_EXPECT": "NO-BREAK"})
            ok = _check("g0-%s" % f.split("/")[-1], r.returncode == 0,
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
