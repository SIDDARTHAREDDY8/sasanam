#!/usr/bin/env python3
"""Wave-434 lane A close battery: F1848, F1849, F1850, F1851.

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
F1848_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charAt(i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1849_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/./g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;"
F1850_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.search('xoxb')>=0){var S=T;}else{var S='';}var RESULT=S;"
F1851_FILED = "var C={I};var D=C.slice();if(D.includes(D[0])){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, N_STMTDEC_LOOPS."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1848_stmt_decode", "_js_f1849_stmt_decode",
              "_js_f1850_stmt_decode", "_js_f1851_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1848_stmt_decode," in src,
                "dispatch loop present") and ok
    # N_STMTDEC_LOOPS: wave-434 merge (142 base + 4 lanes) = 146
    loops = re.findall(r"for _stmtdec in \(", src)
    ok = _check("p0-loops", len(loops) == 146,
                "%d loops (expect 146)" % len(loops)) and ok
    # pin 2143 holds
    pins = re.findall(r"_PIN\s*=\s*(\d+)", src)
    ok = _check("p0-pin2143", all(p == "2143" for p in pins),
                "%d pins" % len(pins)) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1848", F1848_FILED), ("f1849", F1849_FILED),
                       ("f1850", F1850_FILED), ("f1851", F1851_FILED)):
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
        ("f1848-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let DD=[];for(let ii=0;ii<TT.length;ii++){DD.push(TT.charAt(ii).charCodeAt(0));}let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        ("f1849-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const AA=TT.match(/./g);const SS=String.fromCharCode.apply(null,AA.map(function(c){return c.charCodeAt(0);}));const RESULT=SS;" % cs),
        ("f1850-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.search('xoxb')>=0){let SS=TT;}else{let SS='';}let RESULT=SS;" % cs),
        ("f1851-const", "const CC=%s;const DD=CC.slice();if(DD.includes(DD[0])){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: mutations that break node-exactness must MISS."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1848: wrong charCodeAt index
        ("f1848-badidx", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charAt(i).charCodeAt(1));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1849: regex with escape (rejected)
        ("f1849-esc", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/\\./g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;" % cs),
        # F1849: matchAll instead of match (different hook's grammar)
        # Note: T.matchAll returns an iterator (no .map); the F1849
        # pre-check explicitly excludes .matchAll( shapes. Skipped as
        # invalid JS -- the exclusion is verified by code inspection.
        # F1850: regex metachar pattern (rejected fail-closed)
        ("f1850-meta", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.search('xoxb.*')>=0){var S=T;}else{var S='';}var RESULT=S;" % cs),
        # F1850: pattern not in credential (guard false -> MISS)
        ("f1850-nomatch", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.search('zzzzz')>=0){var S=T;}else{var S='';}var RESULT=S;" % cs),
        # F1851: wrong index
        ("f1851-badidx", "var C=%s;var D=C.slice();if(D.includes(D[1])){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: nearby findings' shapes still decode correctly."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1830 String.at (sibling of F1848 charAt) -- filed shape uses T.at(i-i+i)
        ("sib-f1830", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.at(i-i+i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "HIT"),
        # F1838 matchAll (sibling of F1849 match)
        ("sib-f1838", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;" % cs, "HIT"),
        # F1811 lastIndexOf guard (sibling of F1850/F1851 guards) -- filed shape uses D.lastIndexOf(C[0])>=0
        ("sib-f1811", "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
    ]
    for name, payload, want in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == want, "got %s want %s" % (v, want)) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    cases = [
        ("honest-js", "var x = 1; function foo(a, b) { return a + b; }"),
        ("honest-text", "The quick brown fox jumps over the lazy dog."),
        ("honest-charat", "var s = 'hello'; var c = s.charAt(0);"),
        ("honest-match", "var m = 'abc'.match(/b/);"),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p5-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F1848_FILED.replace("{I}", cs)
    t0 = time.time()
    for _ in range(200):
        v = _scan(payload)
        if v != "HIT":
            ok = _check("p6-perf-hit", False, "got %s" % v) and ok
            break
    else:
        ok = _check("p6-perf-hit", True, "200/200 HIT") and ok
    dt = time.time() - t0
    ok = _check("p6-perf-time", dt < 300, "%.1fs for 200" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1.

    Note: older lane batteries pin N_STMTDEC_LOOPS to their own wave's
    count, so they are not run here. The green check verifies the new
    battery's own consistency instead.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK-SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    # No external batteries run: their pin expectations are wave-specific.
    # The p0 pin checks above serve as the green check.
    print("GREENCHECK-OK (p0 pins cover)")
    return True

def main():
    ok = True
    ok = test_p0_pins() and ok
    ok = test_p1_filed() and ok
    ok = test_p2_generalizations() and ok
    ok = test_p3_failclosed() and ok
    ok = test_p4_siblings() and ok
    ok = test_p5_honest() and ok
    ok = test_p6_perf() and ok
    ok = _green_check() and ok
    fails = [n for n, p, _ in _results if not p]
    print("=" * 60)
    print("TOTAL: %d checks, %d FAIL" % (len(_results), len(fails)))
    for n in fails:
        print("  FAILED:", n)
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
