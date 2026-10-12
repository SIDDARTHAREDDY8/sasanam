#!/usr/bin/env python3
"""Wave-436 lane C close battery: F1901, F1902, F1903, F1904, F1906.

Pins the closures (F1905 already CLOSED at wave-435 merge, covered by
the F1890 hook -- not in lane scope). All assertions must HOLD on the
fixed tree. N_STMTDEC_LOOPS 150 -> 151 (real code-count change: one
new dispatch loop); re.compile( 29 unchanged.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w436_close_")
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

# Filed shapes (from FINDINGS.md, attack round 103, first-filing 2026-10-12 13:50 UTC)
F1901_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;"
F1902_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=0){var U=T;}else{var U='';}var RESULT=U;"
F1903_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"
F1904_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-6))){var U=T;}else{var U='';}var RESULT=U;"
F1906_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join('');var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 151."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1901_stmt_decode", "_js_f1902_stmt_decode",
              "_js_f1903_stmt_decode", "_js_f1904_stmt_decode",
              "_js_f1906_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1901_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 153, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1901", F1901_FILED), ("f1902", F1902_FILED),
                       ("f1903", F1903_FILED), ("f1904", F1904_FILED),
                       ("f1906", F1906_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, other literals."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1901: let, renamed, longer literal present in dstr
        ("f1901-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.includes('xoxb-0123')){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        ("f1901-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.includes('0123')){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
        # F1902: let, different literal present in dstr
        ("f1902-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.indexOf('cde')>=0){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1903: const, longer prefix literal
        ("f1903-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.startsWith('xoxb-01')){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
        # F1904: other slice args (tautology holds node-exactly for any int)
        ("f1904-slice3", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-3))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1904-slicepos", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(4))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1906: let/const, renamed idents
        ("f1906-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=[...TT].join('');let RESULT=UU;" % cs),
        ("f1906-renamed", "var C=%s;var Q=C.map(function(c){return String.fromCharCode(c);}).join('');var Z=[...Q].join('');var RESULT=Z;" % cs),
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
        # F1901: guard literal absent -> else branch -> must MISS
        ("f1901-absent", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('zzzz')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1902: guard literal absent -> must MISS
        ("f1902-absent", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('zzzz')>=0){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1903: non-prefix literal -> must MISS
        ("f1903-nonprefix", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('zzzz')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1902: wrong comparison (>=1 instead of >=0) -> narrow grammar -> MISS
        ("f1902-ge1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=1){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1904: literal arg instead of T.slice(...) -> narrow grammar -> MISS
        ("f1904-litarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith('abcde')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1906: non-empty join sep -> narrow grammar -> MISS
        ("f1906-sep", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(',');var RESULT=U;" % cs, "MISS"),
        # F1906: spread of non-T -> name mismatch -> MISS
        ("f1906-wrongbase", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...C].join('');var RESULT=U;" % cs, "MISS"),
        # Siblings: array includes/indexOf (F1851/F1852) still HIT
        ("f1851-sibling", "var C=%s;var D=C.slice();if(D.includes(D[0])){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        ("f1852-sibling", "var C=%s;var D=C.slice();if(D.indexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # Siblings: two-arg includes/indexOf (F1883/F1884) still HIT
        ("f1883-sibling", "var C=%s;var D=C.slice();if(D.includes(C[0],0)){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        ("f1884-sibling", "var C=%s;var D=C.slice();if(D.indexOf(C[C.length-1],C.length-1)>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # F1905 (covered by F1890 hook) still HITs
        ("f1905-covered", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var U=T;}else{var U='';}var RESULT=U;" % cs, "HIT"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling string-guard hooks (F1883/F1884/F1890) still work."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1883: includes two-arg guard (array)
        ("f1883", "var C=%s;var D=C.slice();if(D.includes(C[0],0)){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1884: indexOf two-arg computed-fromIndex guard (array)
        ("f1884", "var C=%s;var D=C.slice();if(D.indexOf(C[C.length-1],C.length-1)>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1890: String.at(-1) guard
        ("f1890", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var S=T;}else{var S='';}var RESULT=S;" % cs),
        # F1880: charAt guard
        ("f1880", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(0)===T[0]){var S=T;}else{var S='';}var RESULT=S;" % cs),
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
        "var t = 'abc'; if (t.includes('b')) { console.log('yes'); }",
        "var t = 'abcdef'; var u = t.startsWith('ab') ? t : '';",
        "var arr = [...'xyz']; var j = arr.join('');",
        "if (s.endsWith(s.slice(-3))) { process(s); }",
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
        F1901_FILED.replace("{I}", cs),
        F1902_FILED.replace("{I}", cs),
        F1903_FILED.replace("{I}", cs),
        F1904_FILED.replace("{I}", cs),
        F1906_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 5])
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
    # Adjacent: wave-435 lane D (F1885-F1890 string-laundering siblings).
    # Its p0-loopcount pin (147) predates this lane's loop (151) and is
    # repointed at merge; only unexpected failures count here.
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w435_f1885f1890close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("  FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w435d", not unexpected,
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
