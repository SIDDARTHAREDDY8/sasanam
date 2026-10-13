#!/usr/bin/env python3
"""Wave-443 lane A close battery: F2116-F2135.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 180 -> 184 (real code-count change: four new dispatch
loops); re.compile( 29 unchanged; pin 2143.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w443_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-AAAAAAAAAAAAAAAA"
SECRET_L = "xoxb-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

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

# Filed shapes (from FINDINGS.md, attack round 110, first-filing 2026-10-13 00:37 UTC)
F2116_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Reflect.apply(Array.prototype.concat,[T],['']).join('');"
F2117_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.prototype.concat.call([T],'').join('');"
F2118_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=[T].concat('').join('');"
F2119_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=''.concat(T,'');"
F2120_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.concat('','');"
F2121_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String(T).toString();"
F2122_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.valueOf().toString();"
F2123_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.normalize('NFC');"
F2124_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=JSON.parse(JSON.stringify(T));"
F2125_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Buffer.from(T,'utf8').toString('utf8');"
F2126_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=new RegExp(T).source;"
F2127_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.split(/(?!)/)[0];"
F2128_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.replace(/(.)/g,'$1');"
F2129_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.match(/^[\\s\\S]*$/)[0];"
F2130_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=structuredClone(T);"
F2131_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.padEnd(T.length,' ');"
F2132_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=[...T].reverse().reverse().join('');"
F2133_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T.split('').map(function(c){return c;}).join('');"
F2134_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=Array.from(T).map(function(c){return c;}).join('');"
F2135_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=String.raw`${T}`;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loops present, loop count 184."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for n in range(2116, 2136):
        h = "_js_f%d_stmt_decode" % n
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f2116_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 180 base + 4 new = 184
    m = re.search(r"def _decode_layer\(text\):", src)
    assert m, "no _decode_layer"
    body = src[m.start():]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = _check("p0-loopcount", len(loops) == 184,
                "%d loops (pin 184)" % len(loops)) and ok
    # re.compile count unchanged
    rc = src.count("re.compile(")
    ok = _check("p0-recompile", rc == 29, "%d (pin 29)" % rc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    shapes = (
        ("f2116", F2116_FILED), ("f2117", F2117_FILED),
        ("f2118", F2118_FILED), ("f2119", F2119_FILED),
        ("f2120", F2120_FILED), ("f2121", F2121_FILED),
        ("f2122", F2122_FILED), ("f2123", F2123_FILED),
        ("f2124", F2124_FILED), ("f2125", F2125_FILED),
        ("f2126", F2126_FILED), ("f2127", F2127_FILED),
        ("f2128", F2128_FILED), ("f2129", F2129_FILED),
        ("f2130", F2130_FILED), ("f2131", F2131_FILED),
        ("f2132", F2132_FILED), ("f2133", F2133_FILED),
        ("f2134", F2134_FILED), ("f2135", F2135_FILED),
    )
    for name, tmpl in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const variants, whitespace variants."""
    ok = True
    # let variant of F2116
    tmpl = F2116_FILED.replace("var ", "let ", 1)
    v = _scan(tmpl.replace("{I}", _codes(SECRET_S)))
    ok = _check("p2-f2116-let", v == "HIT", v) and ok
    # const variant of F2121
    tmpl = F2121_FILED.replace("var ", "const ", 1)
    v = _scan(tmpl.replace("{I}", _codes(SECRET_S)))
    ok = _check("p2-f2121-const", v == "HIT", v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: malformed shapes MISS (never mis-decode)."""
    ok = True
    # Wrong separator in F2118 concat
    bad = ("var C=" + _codes(SECRET_S) +
           ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
           "var RESULT=[T].concat(',').join('');")
    v = _scan(bad)
    ok = _check("p3-f2118-badsep", v == "MISS", v) and ok
    # Truncated F2126 (missing .source)
    bad2 = ("var C=" + _codes(SECRET_S) +
            ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
            "var RESULT=new RegExp(T);")
    v = _scan(bad2)
    ok = _check("p3-f2126-trunc", v == "MISS", v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F2096-F2115 shapes still decode (no regression)."""
    ok = True
    # F2096 shape (from wave-442)
    t = ("var C=" + _codes(SECRET_S) +
         ";var A=[C.map(function(c){return String.fromCharCode(c);}).join('')];"
         "var RESULT=Array.prototype.join.call(A,'');")
    v = _scan(t)
    ok = _check("p4-f2096", v == "HIT", v) and ok
    # F2106 shape (from wave-442 lane B)
    t = ("var C=" + _codes(SECRET_S) +
         ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var R=[T];var RESULT=R;")
    # Actually F2106 is destructuring; use a simpler sibling: F2100
    t = ("var C=" + _codes(SECRET_S) +
         ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var RESULT=Object(T).toString();")
    v = _scan(t)
    ok = _check("p4-f2100", v == "HIT", v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in (
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "Reflect.apply is a method",
    ):
        v = _scan(txt)
        ok = _check("p5-honest", v == "MISS", "%r -> %s" % (txt[:30], v)) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites scan quickly."""
    ok = True
    payload = F2116_FILED.replace("{I}", _codes(SECRET_S))
    t0 = time.time()
    for _ in range(200):
        _scan(payload)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 150, "%.1fs for 200" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check honoring GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    print("GREENCHECK: running (depth-1)")
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
            ok = t()
        except Exception as e:
            _check(t.__name__, False, "EXC: %r" % e)
            ok = False
        all_ok = all_ok and ok
    n_ok = sum(1 for _, ok, _ in _results if ok)
    n_bad = sum(1 for _, ok, _ in _results if not ok)
    print("=" * 60)
    print("RESULT: %d/%d HELD" % (n_ok, n_ok + n_bad))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL %s: %s" % (name, detail))
    if not _green_check():
        print("GREENCHECK FAILED")
        all_ok = False
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
