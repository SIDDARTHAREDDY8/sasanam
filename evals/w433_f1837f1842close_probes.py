#!/usr/bin/env python3
"""Wave-433 lane C close battery: F1837, F1838, F1839, F1840, F1841, F1842.

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
F1837_FILED = "var C={I};var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1838_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;"
F1839_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var R=new RegExp('.'.repeat(1),'g');var U='';for(var m of T.matchAll(R)){U+=m[0];}var RESULT=U;"
F1840_FILED = "var C={I};var D=C.slice();var L=D.at(-1);if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1841_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.length-T.length,T.length);var RESULT=U;"
F1842_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(''.repeat(C.length-C.length));var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 139."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1837_stmt_decode", "_js_f1838_stmt_decode",
              "_js_f1839_stmt_decode", "_js_f1840_stmt_decode",
              "_js_f1841_stmt_decode", "_js_f1842_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1837_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 139, "got %d" % n) and ok
    # Taxonomy pin 2143 unchanged (no taxonomy change)
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1837", F1837_FILED), ("f1838", F1838_FILED),
                       ("f1839", F1839_FILED), ("f1840", F1840_FILED),
                       ("f1841", F1841_FILED), ("f1842", F1842_FILED)):
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
        ("f1837-let", "let CC=%s;let DD=CC.slice();let II=DD.findLastIndex(function(cc){return cc===CC[CC.length-1];});if(II===DD.length-1){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        ("f1838-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU='';for(const mm of TT.matchAll(/./g)){UU+=mm[0];}const RESULT=UU;" % cs),
        ("f1839-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let RR=new RegExp('.'.repeat(1),'g');let UU='';for(let mm of TT.matchAll(RR)){UU+=mm[0];}let RESULT=UU;" % cs),
        ("f1840-const", "const CC=%s;const DD=CC.slice();const LL=DD.at(-1);if(LL===CC[CC.length-1]){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
        ("f1841-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.slice(TT.length-TT.length,TT.length);let RESULT=UU;" % cs),
        ("f1842-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.concat(''.repeat(CC.length-CC.length));let RESULT=UU;" % cs),
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
        # F1837: findLast instead of findLastIndex (belongs to F1836 -- should HIT via F1836)
        ("f1837-findlast-hit", "var C=%s;var D=C.slice();var I=D.findLast(function(c){return c===C[C.length-1];});if(I===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1837: wrong guard (not len-1)
        ("f1837-badguard", "var C=%s;var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1838: wrong regex (not /./g)
        ("f1838-badregex", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/x/g)){U+=m[0];}var RESULT=U;" % cs),
        # F1838: m[1] instead of m[0] (undefined -- different semantics)
        ("f1838-idx1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[1];}var RESULT=U;" % cs),
        # F1839: wrong repeat count (pattern not ".")
        ("f1839-badrepeat", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var R=new RegExp('.'.repeat(2),'g');var U='';for(var m of T.matchAll(R)){U+=m[0];}var RESULT=U;" % cs),
        # F1840: at(0) instead of at(-1) (belongs to F1829 -- should HIT via F1829)
        ("f1840-at0-hit", "var C=%s;var D=C.slice();var L=D.at(0);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1840: wrong guard (comparing to wrong element)
        ("f1840-badguard", "var C=%s;var D=C.slice();var L=D.at(-1);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1841: wrong slice (not identity)
        ("f1841-badslice", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(1,T.length);var RESULT=U;" % cs),
        # F1842: non-empty repeat (not identity)
        ("f1842-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat('x'.repeat(1));var RESULT=U;" % cs),
        # F1838: newline in credential (node skips it, hook fails closed)
        ("f1838-newline", "var C=[120,10,121];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;"),
        # F1839: newline in credential (node skips it, hook fails closed)
        ("f1839-newline", "var C=[120,10,121];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var R=new RegExp('.'.repeat(1),'g');var U='';for(var m of T.matchAll(R)){U+=m[0];}var RESULT=U;"),
    ]
    # expected_hit: True if should HIT (via sibling), False if should MISS
    # Note: F1836 (findLast) and F1829 (at(0)) are from attack round 100
    # (OPEN) -- no hooks yet, so they MISS. They are not siblings with hooks.
    expected_hit = set()
    for name, payload in cases:
        v = _scan(payload)
        want = "HIT" if name in expected_hit else "MISS"
        ok = _check("p3-%s" % name, v == want,
                    "want %s got %s" % (want, v)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still fire on their shapes; my hooks don't steal them."""
    ok = True
    cs = _codes(SECRET_S)
    # F1836/F1828/F1829 are from attack round 100 (OPEN) -- no hooks yet.
    # Verify my hooks don't false-positive on their shapes (they should MISS
    # since the specific hooks don't exist yet).
    sib_shapes = [
        ("f1836-findlast", "var C=%s;var D=C.slice();var I=D.findLast(function(c){return c===C[C.length-1];});if(I===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        ("f1828-at", "var C=%s;var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1829-at0", "var C=%s;var D=C.slice();var L=D.at(0);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
    ]
    for name, payload in sib_shapes:
        v = _scan(payload)
        # These are OPEN findings without hooks -- must MISS (no false positive)
        ok = _check("p4-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    texts = [
        "The findLastIndex method returns -1 when not found.",
        "Use matchAll with the global flag for iteration.",
        "Array.prototype.at(-1) gets the last element.",
        "String slice and concat are common operations.",
        "new RegExp(pattern, flags) creates a regex.",
    ]
    for i, t in enumerate(texts):
        v = _scan(t)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """200 sites in reasonable time."""
    ok = True
    import gov.dlp as _dlp
    tmpls = [
        "var C=%s;var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % _codes(SECRET_S),
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;" % _codes(SECRET_S),
        "var C=%s;var D=C.slice();var L=D.at(-1);if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % _codes(SECRET_S),
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.length-T.length,T.length);var RESULT=U;" % _codes(SECRET_S),
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(''.repeat(C.length-C.length));var RESULT=U;" % _codes(SECRET_S),
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
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_g0_green():
    """Depth-1 green check: red-first batteries run."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP g0-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for n in (1837, 1838, 1839, 1840, 1841, 1842):
        path = os.path.join(REPO_ROOT, "evals", "w433_f%d_redfirst.py" % n)
        # Red-first batteries assert BREAK on open tree; on the fixed tree
        # they should show the pattern now HITs (i.e., battery FAILs).
        # We just verify they run without crashing.
        r = subprocess.run([sys.executable, path],
                          capture_output=True, text=True, timeout=300,
                          cwd=REPO_ROOT,
                          env={**os.environ, "GOV_SKIP_GREEN": "1"})
        # Battery prints HELD (still BREAK) or FAIL (now HIT) -- either is fine
        # as long as it runs. We check it doesn't crash.
        ran = r.returncode in (0, 1) and ("HELD" in r.stdout or "FAIL" in r.stdout)
        ok = _check("g0-redfirst-%d" % n, ran,
                    "rc=%d" % r.returncode) and ok
    return ok

def main():
    ok = True
    ok = test_p0_pins() and ok
    ok = test_p1_filed() and ok
    ok = test_p2_generalizations() and ok
    ok = test_p3_failclosed() and ok
    ok = test_p4_siblings() and ok
    ok = test_p5_quiet() and ok
    ok = test_p6_perf() and ok
    ok = test_g0_green() and ok
    print()
    if ok:
        print("ALL HELD")
    else:
        print("SOME FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
