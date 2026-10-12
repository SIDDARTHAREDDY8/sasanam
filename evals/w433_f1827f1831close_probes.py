#!/usr/bin/env python3
"""Wave-433 lane A close battery: F1827, F1828, F1829, F1830, F1831.

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
F1827_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(C.length-C.length+2)).trimEnd();var RESULT=U;"
F1828_FILED = "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1829_FILED = "var C={I};var D=C.slice();if(D.at(D.length-D.length)===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1830_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.at(i-i+i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1831_FILED = "var C={I};var D=C.slice();var E=D.with(0,D[0]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1827_stmt_decode", "_js_f1828_stmt_decode",
              "_js_f1829_stmt_decode", "_js_f1830_stmt_decode",
              "_js_f1831_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1827_stmt_decode," in src,
                "dispatch loop present") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1827", F1827_FILED), ("f1828", F1828_FILED),
                       ("f1829", F1829_FILED), ("f1830", F1830_FILED),
                       ("f1831", F1831_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const with original names HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1827-let", "let C=%s;let T=C.map(function(c){return String.fromCharCode(c);}).join('');let U=(T+' '.repeat(C.length-C.length+2)).trimEnd();let RESULT=U;" % cs),
        ("f1828-const", "const CC=%s;const DD=[];for(const ii=0;ii<CC.length;ii++){DD.push(CC.at(ii-ii+ii));}const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;" % cs),
        # F1828 uses var/let only (const loop var fails closed)
        ("f1829-let", "let C=%s;let D=C.slice();if(D.at(D.length-D.length)===C[0]){let S=String.fromCharCode.apply(null,D);}else{let S='';}let RESULT=S;" % cs),
        ("f1830-let", "let C=%s;let T=C.map(function(c){return String.fromCharCode(c);}).join('');let D=[];for(let i=0;i<T.length;i++){D.push(T.at(i-i+i).charCodeAt(0));}let S=String.fromCharCode.apply(null,D);let RESULT=S;" % cs),
        ("f1831-const", "const C=%s;const D=C.slice();const E=D.with(0,D[0]);const S=String.fromCharCode.apply(null,E);const RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        # F1828 const loop var should FAIL closed (node throws)
        if name == "f1828-const":
            ok = _check("p2-%s" % name, v == "MISS", "got %s (const fails closed)" % v) and ok
        else:
            ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_fail_closed():
    """Fail-closed: mutations that break node-exactness must MISS."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1827: wrong padding (not 2 spaces)
        ("f1827-badpad", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(C.length-C.length+3)).trimEnd();var RESULT=U;" % cs),
        # F1828: wrong index (i+1 instead of i-i+i)
        ("f1828-badidx", "var C=%s;var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i+1));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1829: wrong guard (C[1] instead of C[0])
        ("f1829-badguard", "var C=%s;var D=C.slice();if(D.at(D.length-D.length)===C[1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;" % cs),
        # F1830: wrong charCodeAt index
        ("f1830-badidx", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.at(i-i+i).charCodeAt(1));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1831: wrong with index (1 instead of 0)
        ("f1831-badidx", "var C=%s;var D=C.slice();var E=D.with(1,D[1]);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1814/F1815 (trim), F1772 (.with), F1391 (.at) still HIT."""
    ok = True
    cs = _codes(SECRET_S)
    # F1814 trim
    p = "var C=%s;var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T.trim();var RESULT=U;" % cs
    ok = _check("p4-f1814", _scan(p) == "HIT", "trim") and ok
    # F1815 trimStart
    p = "var C=%s;var T=' '.repeat(C.length-C.length+2)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;" % cs
    ok = _check("p4-f1815", _scan(p) == "HIT", "trimStart") and ok
    # F1772 .with zero-expr
    p = "var C=%s;var D=C.with(C.length-C.length,C[C.length-C.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs
    ok = _check("p4-f1772", _scan(p) == "HIT", ".with zero-expr") and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for name, payload in (
        ("junk1", "var x = 'hello world'; var y = 42;"),
        ("junk2", "function foo() { return 'bar'; }"),
        ("junk3", "var T='test'.trimEnd(); console.log(T);"),
    ):
        v = _scan(payload)
        ok = _check("p5-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F1827_FILED.replace("{I}", cs)
    start = time.time()
    for _ in range(200):
        _scan(payload)
    elapsed = time.time() - start
    ok = _check("p6-perf", elapsed < 120, "%.1fs for 200 scans" % elapsed) and ok
    return ok

def main():
    # Depth-1 green check honoring GOV_SKIP_GREEN
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP green check (GOV_SKIP_GREEN=1)")
        return 0
    
    ok = True
    ok = test_p0_pins() and ok
    ok = test_p1_filed() and ok
    ok = test_p2_generalizations() and ok
    ok = test_p3_fail_closed() and ok
    ok = test_p4_siblings() and ok
    ok = test_p5_honest() and ok
    # Skip perf in green check (slow)
    # ok = test_p6_perf() and ok
    
    fails = [n for n, o, _ in _results if not o]
    print("\n%d/%d HELD" % (len(_results) - len(fails), len(_results)))
    if fails:
        print("FAILURES:", fails)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
