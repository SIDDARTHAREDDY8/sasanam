#!/usr/bin/env python3
"""Wave-444 lane A close battery: F2156-F2181.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 185 -> 186 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged; pin 2143.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w444_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-" + "a" * 15
SECRET_L = "xoxb-" + "a" * 35

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

# Filed shapes (attack round 111, first-filing 2026-10-13 01:55 UTC)
F2156_FILED_0 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.toString();"
F2156_FILED_1 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.substring(0);"
F2156_FILED_2 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.substr(0,T.length);"
F2156_FILED_3 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.slice(0,undefined);"
F2156_FILED_4 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.prototype.valueOf.call(T);"
F2157_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.padStart(T.length,' ');"
F2158_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=''.concat(...[T]);"
F2159_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.prototype.join.call(T.split(''),'');"
F2160_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.replaceAll('zzz','zzz');"
F2161_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.replaceAll(/(.)/g,'$1');"
F2162_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.from(T.matchAll(/./g)).join('');"
F2163_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=encodeURI(T);"
F2164_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=decodeURI(T);"
F2165_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.repeat(1);"
F2166_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.concat().concat();"
F2167_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.fromCharCode(...[...T].map(function(c){return c.charCodeAt(0);}));"
F2168_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.at(0)+T.slice(1);"
F2169_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';var i=0;while(i<T.length){U+=T[i];i++;}var RESULT=U;"
F2170_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.split('').filter(function(){return true;}).join('');"
F2171_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.length?T:'';"
F2172_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.startsWith('')?T:'';"
F2173_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=`${T}${''}`;"
F2174_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.prototype.concat.apply('',[T]);"
F2175_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Reflect.apply(String.prototype.concat,'',[T]);"
F2176_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.of(T).join('');"
F2177_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=new Array(T).join('');"
F2178_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.split(/(?:)/).join('');"
F2179_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=[...T].sort(function(){return 0;}).join('');"
F2180_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.normalize();"
F2181_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.normalize('NFD').normalize('NFC');"

def test_p0_pins():
    """Pin checks."""
    import gov.dlp as dlp
    for n in range(2156, 2182):
        fn = "_js_f%d_stmt_decode" % n
        _check("hook F%d defined" % n, hasattr(dlp, fn), fn)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    _check("dispatch loop F2156-F2181", "_js_f2156_stmt_decode," in src and "_js_f2181_stmt_decode):" in src)
    loops = src.count("for _stmtdec in")
    _check("N_STMTDEC_LOOPS=186", loops == 186, "got %d" % loops)
    rec = len(re.findall(r"re\.compile\(", src))
    _check("re.compile=29", rec == 29, "got %d" % rec)

def test_p1_filed_shapes():
    """All filed shapes HIT."""
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2156_FILED_0.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2156_0 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2156_FILED_1.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2156_1 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2156_FILED_2.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2156_2 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2156_FILED_3.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2156_3 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2156_FILED_4.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2156_4 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2157_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2157 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2158_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2158 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2159_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2159 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2160_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2160 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2161_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2161 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2162_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2162 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2163_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2163 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2164_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2164 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2165_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2165 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2166_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2166 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2167_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2167 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2168_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2168 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2169_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2169 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2170_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2170 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2171_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2171 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2172_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2172 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2173_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2173 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2174_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2174 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2175_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2175 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2176_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2176 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2177_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2177 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2178_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2178 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2179_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2179 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2180_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2180 filed HIT (%s)" % name, v == "HIT", v)
    for sec, name in ((SECRET_S, "short"), (SECRET_L, "long")):
        p = F2181_FILED.replace("{I}", _codes(sec))
        v = _scan(p)
        _check("F2181 filed HIT (%s)" % name, v == "HIT", v)

def test_p2_honest_text():
    """Honest text does not HIT."""
    for txt in ["the quick brown fox jumps over the lazy dog", "var x = 1;", "hello world"]:
        v = _scan(txt)
        _check("honest quiet", v == "MISS", v)

def test_p3_fail_closed():
    """Malformed shapes fail closed."""
    p = "var C=[1,2,3];var T=C.map(function(c){return String.fromCharCode(c);}).join('');var X=T.toString();"
    v = _scan(p)
    _check("fail-closed wrong var", v == "MISS", v)

def test_p4_siblings():
    """Sibling F2144 still HIT."""
    p = "var C=" + _codes(SECRET_S) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.split('').reduce(function(a,c){return a+c;},'');"
    v = _scan(p)
    _check("sibling F2144 HIT", v == "HIT", v)

def test_p5_perf():
    """Perf: 200 sites."""
    p = F2156_FILED_0.replace("{I}", _codes(SECRET_S))
    t0 = time.time()
    for _ in range(200):
        _scan(p)
    dt = time.time() - t0
    _check("perf 200 sites", dt < 180, "%.1fs" % dt)

def main():
    test_p0_pins()
    test_p1_filed_shapes()
    test_p2_honest_text()
    test_p3_fail_closed()
    test_p4_siblings()
    test_p5_perf()
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        import glob
        for fn in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w444_f21*_redfirst.py"))):
            r = subprocess.run([sys.executable, fn], capture_output=True, text=True, timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
            lines = [l for l in out.strip().split("\n") if l.strip()]
            held = lines and lines[-1].strip() == "HELD"
            _check("green " + os.path.basename(fn), held, lines[-1] if lines else "no output")
    passed = sum(1 for _, ok, _ in _results if ok)
    total = len(_results)
    print("\n%d/%d checks HELD" % (passed, total))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL: %s (%s)" % (name, detail))
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    main()
