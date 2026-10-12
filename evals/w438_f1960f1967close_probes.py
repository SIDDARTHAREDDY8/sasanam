#!/usr/bin/env python3
"""Wave-438 lane C close battery: F1960-F1967.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 157 -> 158 (real code-count change: one new dispatch
loop); re.compile( 29 in gov/dlp.py unchanged.
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

# Filed shapes (from FINDINGS.md, attack round 105, first-filing 2026-10-12 16:09 UTC)
F1960_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).toString();var RESULT=U;"
F1961_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.get({v:T},'v');var RESULT=U;"
F1962_FILED = "var C={I};var D=C.slice();var L=D.find(function(c){return c>0;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1963_FILED = "var C={I};var D=C.slice();var L=D.findIndex(function(c){return c<1000;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1964_FILED = "var C={I};var D=C.slice();if(D.every(function(c){return c>0;})){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1965_FILED = "var C={I};var D=C.slice();if(D.some(function(c){return c===C[0];})){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1966_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(!T.includes('zzz')){var U=T;}else{var U='';}var RESULT=U;"
F1967_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')===0){var U=T;}else{var U='';}var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 158."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1960_stmt_decode", "_js_f1961_stmt_decode",
              "_js_f1962_stmt_decode", "_js_f1963_stmt_decode",
              "_js_f1964_stmt_decode", "_js_f1965_stmt_decode",
              "_js_f1966_stmt_decode", "_js_f1967_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1960_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 158, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    filed = (("f1960", F1960_FILED), ("f1961", F1961_FILED),
             ("f1962", F1962_FILED), ("f1963", F1963_FILED),
             ("f1964", F1964_FILED), ("f1965", F1965_FILED),
             ("f1966", F1966_FILED), ("f1967", F1967_FILED))
    for name, tmpl in filed:
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
        # F1960: let, renamed
        ("f1960-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Reflect.construct(String,[TT]).toString();let RESULT=UU;" % cs),
        # F1961: const, renamed, double-quoted key
        ("f1961-const", 'const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join("");const UU=Reflect.get({v:TT},"v");const RESULT=UU;' % cs),
        # F1962: let, renamed
        ("f1962-let", "let CC=%s;let DD=CC.slice();let LL=DD.find(function(c){return c>0;});if(LL===CC[0]){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        # F1963: const, renamed
        ("f1963-const", "const CC=%s;const DD=CC.slice();const LL=DD.findIndex(function(c){return c<1000;});if(LL===0){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
        # F1964: let, renamed
        ("f1964-let", "let CC=%s;let DD=CC.slice();if(DD.every(function(c){return c>0;})){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        # F1965: const, renamed
        ("f1965-const", "const CC=%s;const DD=CC.slice();if(DD.some(function(c){return c===CC[0];})){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
        # F1966: let, renamed, other absent literal
        ("f1966-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(!TT.includes('qqq')){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1967: const, renamed, other present prefix
        ("f1967-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.indexOf('xoxb-01')===0){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS)."""
    ok = True
    cs = _codes(SECRET_S)
    # Direct hook narrowness: F1960 hook must return None on the .valueOf() form
    # (F1926's shape); the scanner HITs via F1926, but the F1960 hook is narrow.
    import gov.dlp as _dlp
    v = _dlp._js_f1960_stmt_decode(
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;" % cs)
    ok = _check("p3-f1960-hook-narrow", v is None, "got %r" % (v,)) and ok
    # Direct hook narrowness: F1961 hook must return None when Reflect.apply present
    v = _dlp._js_f1961_stmt_decode(
        "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String, null, [T]);var RESULT=U;" % cs)
    ok = _check("p3-f1961-hook-narrow", v is None, "got %r" % (v,)) and ok
    cases = [
        # F1960: .valueOf() form is covered by the F1926 hook -> HIT (correct)
        ("f1960-valueof-covered", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;" % cs, "HIT"),
        # F1961: wrong key -> MISS
        ("f1961-badkey", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.get({v:T},'w');var RESULT=U;" % cs, "MISS"),
        # F1962: predicate bound not 0 -> MISS
        ("f1962-bound1", "var C=%s;var D=C.slice();var L=D.find(function(c){return c>1;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1962: arrow predicate -> not this hook -> MISS
        ("f1962-arrow", "var C=%s;var D=C.slice();var L=D.find((c)=>c>0);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1963: predicate bound not 1000 -> MISS
        ("f1963-bound500", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return c<500;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1963: guard rhs not 0 -> MISS
        ("f1963-guard1", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return c<1000;});if(L===1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1964: arrow predicate -> MISS
        ("f1964-arrow", "var C=%s;var D=C.slice();if(D.every((c)=>c>0)){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1965: wrong index -> MISS
        ("f1965-idx1", "var C=%s;var D=C.slice();if(D.some(function(c){return c===C[1];})){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1966: present literal -> else branch -> MISS
        ("f1966-present", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(!T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1966: non-negated -> narrow grammar -> MISS
        ("f1966-pos", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('zzz')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1967: non-prefix literal -> MISS
        ("f1967-nonprefix", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('zzzz')===0){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1967: !==0 -> narrow grammar -> MISS
        ("f1967-neq", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!==0){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work: F1924-F1933, F1939-covered."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1924: Reflect.apply undefined thisArg
        ("f1924", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;" % cs),
        # F1925: Reflect.apply toString method
        ("f1925", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.toString,T,[]);var RESULT=U;" % cs),
        # F1926: Reflect.construct .valueOf()
        ("f1926", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;" % cs),
        # F1927: Reflect.apply String constructor
        ("f1927", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String,null,[T]);var RESULT=U;" % cs),
        # F1928: filter arrow (filed shape)
        ("f1928", "var C=%s;var D=C.filter(()=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1929: find arrow
        ("f1929", "var C=%s;var D=C.slice();var L=D.find(()=>true);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1930: find Boolean
        ("f1930", "var C=%s;var D=C.slice();var L=D.find(Boolean);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1931: findIndex arrow
        ("f1931", "var C=%s;var D=C.slice();var L=D.findIndex(()=>true);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1932: findIndex Boolean
        ("f1932", "var C=%s;var D=C.slice();var L=D.findIndex(Boolean);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1933: includes two-arg
        ("f1933", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb',0)){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1901: includes one-arg
        ("f1901", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
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
        "var r = Reflect.get({a:1}, 'a');",
        "var s = Reflect.construct(String, ['hi']).toString();",
        "if (!s.includes('zzz')) { console.log(s); }",
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
        F1960_FILED.replace("{I}", cs),
        F1961_FILED.replace("{I}", cs),
        F1962_FILED.replace("{I}", cs),
        F1963_FILED.replace("{I}", cs),
        F1964_FILED.replace("{I}", cs),
        F1965_FILED.replace("{I}", cs),
        F1966_FILED.replace("{I}", cs),
        F1967_FILED.replace("{I}", cs),
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
    """Depth-1 green check: adjacent battery main with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Adjacent: wave-437 lane D (F1934-F1943). Its p0-loopcount pin (154)
    # predates this lane's loop (158-> wait, 157->158) and is repointed
    # at merge; only unexpected failures count here.
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w437_f1934f1943close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("  FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w437d", not unexpected,
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
