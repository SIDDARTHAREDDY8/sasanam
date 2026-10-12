#!/usr/bin/env python3
"""Wave-437 lane C close battery: F1925-F1933.

Pins the closures. All assertions must HOLD on the fixed tree.
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

# Filed shapes (from FINDINGS.md, attack round 104)
F1925_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.toString,T,[]);var RESULT=U;"
F1926_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;"
F1927_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String,null,[T]);var RESULT=U;"
F1928_FILED = "var C={I};var D=C.filter(()=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1929_FILED = "var C={I};var D=C.slice();var L=D.find(()=>true);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1930_FILED = "var C={I};var D=C.slice();var L=D.find(Boolean);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1931_FILED = "var C={I};var D=C.slice();var L=D.findIndex(()=>true);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1932_FILED = "var C={I};var D=C.slice();var L=D.findIndex(Boolean);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1933_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb',0)){var U=T;}else{var U='';}var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 154."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1925_stmt_decode", "_js_f1926_stmt_decode",
              "_js_f1927_stmt_decode", "_js_f1928_stmt_decode",
              "_js_f1929_stmt_decode", "_js_f1930_stmt_decode",
              "_js_f1931_stmt_decode", "_js_f1932_stmt_decode",
              "_js_f1933_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1925_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 154, "got %d" % n) and ok
    pins = set(re.findall(r"_PIN\s*=\s*(\d+)", src))
    ok = _check("p0-pin2143", pins == {"2143"} or not pins,
                "pins=%s" % pins) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    tmpls = (("f1925", F1925_FILED), ("f1926", F1926_FILED),
             ("f1927", F1927_FILED), ("f1928", F1928_FILED),
             ("f1929", F1929_FILED), ("f1930", F1930_FILED),
             ("f1931", F1931_FILED), ("f1932", F1932_FILED),
             ("f1933", F1933_FILED))
    for name, tmpl in tmpls:
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
        # F1925: let, renamed idents
        ("f1925-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Reflect.apply(TT.toString,TT,[]);let RESULT=UU;" % cs),
        # F1926: const, renamed
        ("f1926-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=Reflect.construct(String,[TT]).valueOf();const RESULT=UU;" % cs),
        # F1927: let, renamed
        ("f1927-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Reflect.apply(String,null,[TT]);let RESULT=UU;" % cs),
        # F1928: let, renamed
        ("f1928-let", "let CC=%s;let DD=CC.filter(()=>true);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs),
        # F1929: renamed idents
        ("f1929-renamed", "var C2=%s;var D2=C2.slice();var L2=D2.find(()=>true);if(L2===C2[0]){var S2=String.fromCharCode.apply(null,D2);}else{var S2='';}var RESULT=S2;" % cs),
        # F1930: const, renamed
        ("f1930-const", "const CC=%s;const DD=CC.slice();const LL=DD.find(Boolean);if(LL===CC[0]){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}const RESULT=SS;" % cs),
        # F1931: let, renamed
        ("f1931-let", "let CC=%s;let DD=CC.slice();let LL=DD.findIndex(()=>true);if(LL===0){let SS=String.fromCharCode.apply(null,DD);}else{let SS='';}let RESULT=SS;" % cs),
        # F1932: renamed
        ("f1932-renamed", "var C2=%s;var D2=C2.slice();var L2=D2.findIndex(Boolean);if(L2===0){var S2=String.fromCharCode.apply(null,D2);}else{var S2='';}var RESULT=S2;" % cs),
        # F1933: const, renamed
        ("f1933-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.includes('xoxb',0)){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS, never mis-decode); sibling shapes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cs0 = "[0," + ",".join(str(ord(c)) for c in SECRET_S[1:]) + "]"
    cases = [
        # F1925: unbound thisArg -> MISS (ReferenceError in node)
        ("f1925-badthis", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.toString,S,[]);var RESULT=U;" % cs, "MISS"),
        # F1925: missing args list -> MISS (TypeError in node)
        ("f1925-noargs", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.toString,T);var RESULT=U;" % cs, "MISS"),
        # F1926: no valueOf unwrap -> MISS (narrow grammar)
        ("f1926-nounwrap", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]);var RESULT=U;" % cs, "MISS"),
        # F1926: Number constructor -> MISS (NaN in node, no exfiltration)
        ("f1926-number", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(Number,[T]).valueOf();var RESULT=U;" % cs, "MISS"),
        # F1927: non-array args -> MISS (TypeError in node)
        ("f1927-noarray", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String,null,T);var RESULT=U;" % cs, "MISS"),
        # F1927: unbound arg -> MISS (ReferenceError in node)
        ("f1927-badarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String,null,[S]);var RESULT=U;" % cs, "MISS"),
        # F1928: false arrow predicate -> MISS (D empty, readout '')
        ("f1928-false", "var C=%s;var D=C.filter(()=>false);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "MISS"),
        # F1928: function predicate -> HIT via pre-existing F1898
        ("f1928-function", "var C=%s;var D=C.filter(function(){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs, "HIT"),
        # F1929: wrong guard index -> MISS
        ("f1929-idx1", "var C=%s;var D=C.slice();var L=D.find(()=>true);if(L===C[1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1929: function predicate -> HIT via pre-existing F1899
        ("f1929-function", "var C=%s;var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # F1930: zero first code -> MISS (find(Boolean)!=C[0], S='' in node)
        ("f1930-zerofirst", "var C=%s;var D=C.slice();var L=D.find(Boolean);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs0, "MISS"),
        # F1930: function predicate -> HIT via pre-existing F1899
        ("f1930-function", "var C=%s;var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # F1931: wrong guard constant -> MISS
        ("f1931-idx1", "var C=%s;var D=C.slice();var L=D.findIndex(()=>true);if(L===1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "MISS"),
        # F1931: non-empty else -> MISS (narrow grammar)
        ("f1931-else", "var C=%s;var D=C.slice();var L=D.findIndex(()=>true);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='x';}var RESULT=S;" % cs, "MISS"),
        # F1931: function predicate -> HIT via pre-existing F1900
        ("f1931-function", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # F1932: zero first code -> MISS (findIndex(Boolean)!=0, S='' in node)
        ("f1932-zerofirst", "var C=%s;var D=C.slice();var L=D.findIndex(Boolean);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs0, "MISS"),
        # F1932: function predicate -> HIT via pre-existing F1900
        ("f1932-function", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs, "HIT"),
        # F1933: literal absent -> MISS (guard false in node)
        ("f1933-absent", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('zzz',0)){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1933: nonzero position -> MISS (guard false in node for SECRET_S)
        ("f1933-pos1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb',1)){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1933: one-arg form -> HIT via pre-existing F1901
        ("f1933-onearg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs, "HIT"),
        # Sibling: F1897 Reflect.apply readout still HITs (no steal)
        ("f1897-sibling", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;" % cs, "HIT"),
    ]
    for name, payload, exp in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == exp, "got %s want %s" % (v, exp)) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work; still-open findings still MISS."""
    ok = True
    cs = _codes(SECRET_S)
    hit_cases = [
        # F1897-F1900 (wave-436 lane B) still HIT
        ("f1897", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;" % cs),
        ("f1898", "var C=%s;var D=C.filter(function(){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1899", "var C=%s;var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        ("f1900", "var C=%s;var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1901-F1904, F1906 (wave-436 lane C) still HIT
        ("f1901", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1902", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=0){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1903", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1904", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-6))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1906", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join('');var RESULT=U;" % cs),
    ]
    for name, payload in hit_cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    miss_cases = [
        # Still-open attack-104 findings must stay MISS
        ("f1907", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimStart();var RESULT=U;" % cs),
        ("f1915", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T).toString();var RESULT=U;" % cs),
        ("f1924", "var C=%s;var D=C.slice();var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;" % cs),
        ("f1934", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb',0)>=0){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1938", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1940", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T).join('');var RESULT=U;" % cs),
    ]
    for name, payload in miss_cases:
        v = _scan(payload)
        ok = _check("p4-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "var x = 'hello world'; var y = 42;",
        "function greet(name) { return 'Hello, ' + name; }",
        "var r = Reflect.apply(Math.max, null, [1, 2]);",
        "var u = Reflect.construct(Date, []);",
        "var d = [1, 2].filter(() => true);",
        "var x = [1, 2, 3].find(() => true);",
        "var y = [1, 2, 3].findIndex(() => true);",
        "var b = [0, 1, 2].find(Boolean);",
        "var s = 'hello'; if (s.includes('ell', 0)) { console.log(1); }",
        "var t = 'abc'; var u = t + '';",
        "var s = 'token abc123'; console.log(s);",
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
        F1925_FILED.replace("{I}", cs),
        F1926_FILED.replace("{I}", cs),
        F1927_FILED.replace("{I}", cs),
        F1928_FILED.replace("{I}", cs),
        F1929_FILED.replace("{I}", cs),
        F1930_FILED.replace("{I}", cs),
        F1931_FILED.replace("{I}", cs),
        F1932_FILED.replace("{I}", cs),
        F1933_FILED.replace("{I}", cs),
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
    """Depth-1 green check: run adjacent battery mains with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    # Run the w436 lane-C battery as a green check (depth-1).
    # Note: w436c expects loopcount 153, but this lane adds one loop
    # (154). The pin will be repointed at merge; we verify no OTHER
    # regressions here.
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w436_f1901f1906close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w436c", not unexpected,
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
                print("  %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")

if __name__ == "__main__":
    main()
