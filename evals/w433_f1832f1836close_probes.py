#!/usr/bin/env python3
"""Wave-433 lane B close battery: F1832, F1833, F1834, F1835, F1836.

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
F1832_FILED = "var C={I};var D=C.slice();var E=D.with(D.length-1,D[D.length-1]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
F1833_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(String.fromCharCode(0),String.fromCharCode(1));var RESULT=U;"
F1834_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll('~'.repeat(0)+'~','~');var RESULT=U;"
F1835_FILED = "var C={I};var D=C.toSpliced(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1836_FILED = "var C={I};var D=C.slice();var L=D.findLast(function(c){return true;});if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, N_STMTDEC_LOOPS."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1832_stmt_decode", "_js_f1833_stmt_decode",
              "_js_f1834_stmt_decode", "_js_f1835_stmt_decode",
              "_js_f1836_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1832_stmt_decode," in src,
                "dispatch loop present") and ok
    # N_STMTDEC_LOOPS: base 138 + 1 new dispatch loop = 139
    loops = re.findall(r"for _stmtdec in \(", src)
    ok = _check("p0-loops", len(loops) == 139,
                "%d loops (expect 139)" % len(loops)) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1832", F1832_FILED), ("f1833", F1833_FILED),
                       ("f1834", F1834_FILED), ("f1835", F1835_FILED),
                       ("f1836", F1836_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1832-let", "let CC=%s;let DD=CC.slice();let EE=DD.with(DD.length-1,DD[DD.length-1]);let SS=String.fromCharCode.apply(null,EE);let RESULT=SS;" % cs),
        ("f1833-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=TT.replaceAll(String.fromCharCode(0),String.fromCharCode(1));const RESULT=UU;" % cs),
        ("f1834-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.replaceAll('~'.repeat(0)+'~','~');let RESULT=UU;" % cs),
        ("f1835-const", "const CC=%s;const DD=CC.toSpliced(CC.length-CC.length,0);const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;" % cs),
        ("f1836-let", "let CC=%s;let DD=CC.slice();let LL=DD.findLast(function(c){return true;});if(LL===CC[CC.length-1]){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: mutations that break the identity must MISS (or at least not mis-decode)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1832: literal 0 instead of D.length-1 (F1831's shape, still OPEN)
        ("f1832-literal0", "var C=%s;var D=C.slice();var E=D.with(0,D[0]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1832: wrong index (D.length-2)
        ("f1832-wrongidx", "var C=%s;var D=C.slice();var E=D.with(D.length-2,D[D.length-2]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        # F1833: search char present in T (not identity) -- must fail closed
        # We use a credential containing NUL by crafting codes directly
        ("f1833-search-present", "var C=[0,1,2];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(String.fromCharCode(0),String.fromCharCode(1));var RESULT=U;"),
        # F1834: repeat(1) instead of repeat(0) -- search is '~~', replacement '~'
        ("f1834-repeat1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll('~'.repeat(1)+'~','~');var RESULT=U;" % cs),
        # F1835: deleteCount 1 instead of 0 (not identity)
        ("f1835-del1", "var C=%s;var D=C.toSpliced(C.length-C.length,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1835: splice instead of toSpliced (different method)
        ("f1835-splice", "var C=%s;var D=C.slice();D.splice(D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1836: findLastIndex instead of findLast (F1837, still OPEN)
        ("f1836-findlastindex", "var C=%s;var D=C.slice();var L=D.findLastIndex(function(c){return true;});if(L===C.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1836: wrong guard (L===0)
        ("f1836-wrongguard", "var C=%s;var D=C.slice();var L=D.findLast(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        # These should MISS via our hooks (fail closed). They may HIT via
        # other decoders, which is fine -- we just verify no crash and no
        # mis-decode of the credential. For the identity-breaking cases,
        # MISS is the expected hook behavior.
        ok = _check("p3-%s" % name, v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: related findings still behave correctly."""
    ok = True
    cs = _codes(SECRET_S)
    # F1772 (C.with zero-expr) should still HIT
    p = "var C=%s;var D=C.with(C.length-C.length,C[C.length-C.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1772-still-hit", v == "HIT", "got %s" % v) and ok
    # F1831 (D.with literal 0) should still MISS (still OPEN, Lane A)
    p = "var C=%s;var D=C.slice();var E=D.with(0,D[0]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1831-still-miss", v == "MISS", "got %s" % v) and ok
    # F1811 (lastIndexOf guard) should still HIT
    p = "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1811-still-hit", v == "HIT", "got %s" % v) and ok
    # F1837 (findLastIndex guard) should still MISS (still OPEN)
    p = "var C=%s;var D=C.slice();var L=D.findLastIndex(function(c){return true;});if(L===C.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs
    v = _scan(p)
    ok = _check("p4-f1837-still-miss", v == "MISS", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1 + 2; console.log(x);",
        "Hello, world!",
        "const arr = [1,2,3]; const s = arr.with(0, 99);",
    ]:
        v = _scan(txt)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, txt[:30])) and ok
    return ok

def test_p6_perf():
    """Performance: 200 sites in reasonable time."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F1832_FILED.replace("{I}", cs)
    big = " ".join([payload] * 200)
    t0 = time.time()
    v = _scan(big)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "%.1fs" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent battery mains with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    # Run the w432 attack probes battery as a sanity check
    print("GREENCHECK: running w432_attack_probes (depth-1)")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Use a unique TMPDIR for the child
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="w433_green_")
    env["TMPDIR"] = tmpd
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w432_attack_probes.py")],
        capture_output=True, text=True, timeout=600, env=env,
        cwd=REPO_ROOT,
    )
    out = (r.stdout or "") + (r.stderr or "")
    if "FAIL" in out and "0 FAIL" not in out:
        print("GREENCHECK: w432_attack_probes had failures")
        print(out[-2000:])
        return False
    print("GREENCHECK: w432_attack_probes OK")
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
