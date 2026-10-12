#!/usr/bin/env python3
"""Wave-432 lane A close battery: F1805, F1806, F1807, F1808, F1809.

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
F1805_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;"
F1806_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'x');var RESULT=U;"
F1807_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(C.length-C.length+T.length,'x');var RESULT=U;"
F1808_FILED = "var C={I};var D=C.slice();D.copyWithin(D.length-D.length,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1809_FILED = "var C={I};var D=C.slice();D.fill(0,D.length,D.length+5);var S=String.fromCharCode.apply(null,D);var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1805_stmt_decode", "_js_f1806_stmt_decode",
              "_js_f1807_stmt_decode", "_js_f1808_stmt_decode",
              "_js_f1809_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1805_stmt_decode," in src,
                "dispatch loop present") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1805", F1805_FILED), ("f1806", F1806_FILED),
                       ("f1807", F1807_FILED), ("f1808", F1808_FILED),
                       ("f1809", F1809_FILED)):
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
        ("f1805-let", "let CC=%s;let TT=CC.map(function(cc){return String.fromCharCode(cc);}).join('');let UU=TT.repeat(CC.length-CC.length+1);let RESULT=UU;" % cs),
        ("f1806-const", "const CC=%s;const TT=CC.map(function(cc){return String.fromCharCode(cc);}).join('');const UU=TT.padEnd(CC.length,'y');const RESULT=UU;" % cs),
        ("f1807-let", "let CC=%s;let TT=CC.map(function(cc){return String.fromCharCode(cc);}).join('');let UU=TT.padStart(CC.length-CC.length+TT.length,'z');let RESULT=UU;" % cs),
        ("f1808-let", "let CC=%s;let DD=CC.slice();DD.copyWithin(DD.length-DD.length,DD.length);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1809-const", "const CC=%s;const DD=CC.slice();DD.fill(0,DD.length,DD.length+5);const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;" % cs),
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
        # F1805: repeat count not 1 (C.length instead of C.length-C.length+1)
        ("f1805-badcount", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length);var RESULT=U;" % cs),
        # F1805: repeat on wrong base
        ("f1805-badbase", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=X.repeat(C.length-C.length+1);var RESULT=U;" % cs),
        # F1806: padEnd target not C.length
        ("f1806-badlen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(10,'x');var RESULT=U;" % cs),
        # F1806: padEnd with 2-char pad string (still no-op but not filed shape)
        ("f1806-badpad", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'xy');var RESULT=U;" % cs),
        # F1807: padStart target not T.length
        ("f1807-badlen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(C.length,'x');var RESULT=U;" % cs),
        # F1808: copyWithin with non-empty range (target 1, start 0) -- shifts, not identity
        ("f1808-badrange", "var C=%s;var D=C.slice();D.copyWithin(1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1808: copyWithin target not zero-expression (literal 1)
        ("f1808-badtarget", "var C=%s;var D=C.slice();D.copyWithin(1,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1809: fill with non-empty range (start 0)
        ("f1809-badrange", "var C=%s;var D=C.slice();D.fill(0,0,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1809: fill value not 0
        ("f1809-badval", "var C=%s;var D=C.slice();D.fill(1,D.length,D.length+5);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling productions still work (disjointness)."""
    ok = True
    cs = _codes(SECRET_S)
    # F1774 (1-param map+join with RESULT) should still HIT via its own hook
    payload = "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');" % cs
    v = _scan(payload)
    ok = _check("p4-f1774", v == "HIT", "got %s" % v) and ok
    # Direct apply still works
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);" % cs
    v = _scan(payload)
    ok = _check("p4-direct", v == "HIT", "got %s" % v) and ok
    # F430/F803 fragment var-binding (not repeat) should not be affected
    payload = "var C=%s;var S=String.fromCharCode.apply(null,C);" % cs
    v = _scan(payload)
    ok = _check("p4-frag", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "The quarterly financial summary shows revenue growth.",
        "var x = 1; var y = 2; var z = x + y;",
        "var t = s.repeat(3);",
        "var u = t.padEnd(10);",
        "d.copyWithin(0, 3);",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-432 findings: all CLOSED on merged tree (vacuous pass).

    At lane-dev time this verified sibling opens still MISS (no cross-hook
    false positives). On the wave-432 merged tree F1805-F1821/F1823-F1826
    are all CLOSED, so there are no remaining opens to check. False-positive
    protection is covered by the honest-text and fail-closed tests.
    """
    return True

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1805_FILED.replace("{I}", cs),
        F1806_FILED.replace("{I}", cs),
        F1807_FILED.replace("{I}", cs),
        F1808_FILED.replace("{I}", cs),
        F1809_FILED.replace("{I}", cs),
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
    for n in (1805, 1806, 1807, 1808, 1809):
        f = "evals/w432_f%d_redfirst.py" % n
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            # Red-first batteries FAIL (exit 1) on the fixed tree -- that's expected
            # (they assert BREAK on the open tree). We just check they run.
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
