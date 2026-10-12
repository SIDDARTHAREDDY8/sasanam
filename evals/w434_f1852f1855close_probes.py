#!/usr/bin/env python3
"""Wave-434 lane B close battery: F1852, F1853, F1854, F1855.

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

# Filed shapes (from FINDINGS.md entries)
F1852_FILED = "var C={I};var D=C.slice();if(D.indexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1853_FILED = "var C={I};var D=C.slice();var E=D.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"
F1854_FILED = "var C={I};var D=C.slice();var E=D.toReversed().toReversed();var S=String.fromCharCode.apply(null,E);var RESULT=S;"
F1855_FILED = "var C={I};var D=[C];var E=D.flat(2-1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"


def _hook(name):
    # direct hook import for precise fail-closed checks
    from gov.dlp import (_js_f1852_stmt_decode, _js_f1853_stmt_decode,
                         _js_f1854_stmt_decode, _js_f1855_stmt_decode)
    return {"f1852": _js_f1852_stmt_decode, "f1853": _js_f1853_stmt_decode,
            "f1854": _js_f1854_stmt_decode, "f1855": _js_f1855_stmt_decode}[name]


def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, N_STMTDEC_LOOPS."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1852_stmt_decode", "_js_f1853_stmt_decode",
              "_js_f1854_stmt_decode", "_js_f1855_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1852_stmt_decode," in src,
                "dispatch loop present") and ok
    # N_STMTDEC_LOOPS: wave-434 merge (142 base + 4 lanes) = 146
    loops = re.findall(r"for _stmtdec in \(", src)
    ok = _check("p0-loops", len(loops) == 146,
                "%d loops (expect 146)" % len(loops)) and ok
    return ok


def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1852", F1852_FILED), ("f1853", F1853_FILED),
                       ("f1854", F1854_FILED), ("f1855", F1855_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok


def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, computed-depth variants HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1852-let", "let CC=%s;let DD=CC.slice();if(DD.indexOf(CC[0])>=0){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        ("f1852-const-noresult", "const CC=%s;const DD=CC.slice();if(DD.indexOf(CC[0])>=0){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}" % cs),
        ("f1853-const", "const CC=%s;const DD=CC.slice();const EE=DD.toSorted(function(x,y){return 0;});const SS=String.fromCharCode.apply(null,EE);const RESULT=SS;" % cs),
        ("f1853-hex0", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return 0x0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1854-let", "let CC=%s;let DD=CC.slice();let EE=DD.toReversed().toReversed();let SS=String.fromCharCode.apply(null,EE);let RESULT=SS;" % cs),
        ("f1855-let", "let CC=%s;let DD=[CC];let EE=DD.flat(2-1);let SS=String.fromCharCode.apply(null,EE);let RESULT=SS;" % cs),
        ("f1855-lit1", "var C=%s;var D=[C];var E=D.flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1855-sub32", "var C=%s;var D=[C];var E=D.flat(3-2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok


def test_p3_failclosed():
    """Fail-closed: mutations that break the identity must MISS our hooks."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1852: lastIndexOf is the sibling hook's shape, not ours
        ("f1852-lastindexof", "f1852", "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1852: guard on C[1] instead of C[0]
        ("f1852-idx1", "f1852", "var C=%s;var D=C.slice();if(D.indexOf(C[1])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1852: strict > instead of >=
        ("f1852-gt", "f1852", "var C=%s;var D=C.slice();if(D.indexOf(C[0])>0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1852: missing else branch
        ("f1852-noelse", "f1852", "var C=%s;var D=C.slice();if(D.indexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}var RESULT=S;" % cs),
        # F1853: comparator returns 1 (not identity)
        ("f1853-ret1", "f1853", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return 1;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1853: comparator returns a-b (real sort)
        ("f1853-sort", "f1853", "var C=%s;var D=C.slice();var E=D.toSorted(function(a,b){return a-b;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1853: sort (in-place) instead of toSorted
        ("f1853-sort-inplace", "f1853", "var C=%s;var D=C.slice();var E=D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1854: single toReversed
        ("f1854-single", "f1854", "var C=%s;var D=C.slice();var E=D.toReversed();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1854: toReversed + reverse (F1742's shape, not ours)
        ("f1854-torev-rev", "f1854", "var C=%s;var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1854: reverse twice (F1770's shape, not ours)
        ("f1854-revrev", "f1854", "var C=%s;var D=C.slice(0).reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1855: depth 0 (not identity -- leaves [C] nested)
        ("f1855-depth0", "f1855", "var C=%s;var D=[C];var E=D.flat(0);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1855: depth 2 (outside filed grammar)
        ("f1855-depth2", "f1855", "var C=%s;var D=[C];var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1855: no-arg flat (outside filed grammar)
        ("f1855-noarg", "f1855", "var C=%s;var D=[C];var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1855: nest base is D not C
        ("f1855-nestD", "f1855", "var C=%s;var D=[D];var E=D.flat(2-1);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
    ]
    for name, hookname, payload in cases:
        r = _hook(hookname)(payload)
        ok = _check("p3-%s" % name, r is None,
                    "hook returned %r" % (r,)) and ok
    return ok


def test_p4_siblings():
    """Sibling pins: related findings still behave correctly."""
    ok = True
    cs = _codes(SECRET_S)
    # F1811 (lastIndexOf guard) should still HIT
    p = "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1811-still-hit", v == "HIT", "got %s" % v) and ok
    # F1770 (reverse twice) should still HIT
    p = "var C=%s;var D=C.slice(0).reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1770-still-hit", v == "HIT", "got %s" % v) and ok
    # F1742 (toReversed+reverse) should still HIT
    p = "var C=%s;var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1742-still-hit", v == "HIT", "got %s" % v) and ok
    # F1851 (includes guard, lane A, CLOSED) -- lane B hooks must not catch it (disjointness)
    p = "var C=%s;var D=C.slice();if(D.includes(D[0])){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs
    # Test lane B's hooks directly for disjointness (find_credential HITs via lane A's hook, which is correct)
    disjoint = all(_hook(n)(p) is None for n in ("f1852", "f1853", "f1854", "f1855"))
    ok = _check("p4-f1851-disjoint", disjoint, "lane B hooks miss F1851 shape") and ok
    # F1856 (slice computed, lane C, CLOSED) -- lane B hooks must not catch it (disjointness)
    p = "var C=%s;var D=C.slice(C.length-C.length,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs
    disjoint = all(_hook(n)(p) is None for n in ("f1852", "f1853", "f1854", "f1855"))
    ok = _check("p4-f1856-disjoint", disjoint, "lane B hooks miss F1856 shape") and ok
    return ok


def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1 + 2; console.log(x);",
        "Hello, world!",
        "const arr = [1,2,3]; const s = arr.toSorted((a,b) => a-b);",
        "const flat = [1,[2]].flat();",
    ]:
        v = _scan(txt)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, txt[:30])) and ok
    return ok


def test_p6_perf():
    """Performance: 200 sites in reasonable time."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F1852_FILED.replace("{I}", cs)
    big = " ".join([payload] * 200)
    t0 = time.time()
    v = _scan(big)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "%.1fs" % dt) and ok
    return ok


def _green_check():
    """Depth-1 green check: run w433_attack_probes with GOV_SKIP_GREEN=1.

    Expected: the ONLY failures are the 8 newly-closed F1852-F1855 pins
    (now HIT -- the merge coordinator flips these to the CLOSED side).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    print("GREENCHECK: running w433_attack_probes (depth-1)")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="w434_green_")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w433_attack_probes.py")],
        capture_output=True, text=True, timeout=900, env=env,
        cwd=REPO_ROOT,
    )
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("FAIL new")]
    # Wave-434 merge: w433_attack_probes.py was updated to expect HIT for
    # F1848-F1864 (closed), so no FAIL new lines are expected.
    expected = set()
    unexpected = [l for l in fails if l not in expected]
    missing = [e for e in expected if e not in fails]
    if unexpected:
        print("GREENCHECK: UNEXPECTED failures:")
        for l in unexpected:
            print("  " + l)
        return False
    if missing:
        print("GREENCHECK: expected flips did not occur:")
        for l in missing:
            print("  " + l)
        return False
    print("GREENCHECK: no unexpected failures (w433 pins flipped to HIT at merge)")
    return True


def main():
    tests = [
        test_p0_pins,
        test_p1_filed,
        test_p2_generalizations,
        test_p3_failclosed,
        test_p4_siblings,
        test_p5_honest,
        test_p6_perf,
    ]
    all_ok = True
    for t in tests:
        try:
            all_ok = t() and all_ok
        except Exception as e:
            print("FAIL %s -- EXCEPTION: %s" % (t.__name__, e))
            import traceback
            traceback.print_exc()
            all_ok = False
    # Green check
    if not _green_check():
        all_ok = False
    npass = sum(1 for _, ok, _ in _results if ok)
    nfail = sum(1 for _, ok, _ in _results if not ok)
    print("\n%d/%d HELD" % (npass, npass + nfail))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
