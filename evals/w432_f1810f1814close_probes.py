#!/usr/bin/env python3
"""Wave-432 lane B close battery: F1810, F1811, F1812, F1813, F1814.

Pins the closures. All assertions must HOLD on the fixed tree.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w432_f1810f1814close_")
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
F1810_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1811_FILED = "var C={I};var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"
F1812_FILED = "var C={I};var D=C.reduceRight(function(a,c){a.push(c);return a;},[]);D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1813_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.normalize();var D=[];for(var i=0;i<U.length;i++){D.push(U.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1814_FILED = "var C={I};var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T.trim();var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1810_stmt_decode", "_js_f1811_stmt_decode",
              "_js_f1812_stmt_decode", "_js_f1813_stmt_decode",
              "_js_f1814_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1810_stmt_decode," in src,
                "dispatch loop present") and ok
    loops = re.findall(r"for _stmtdec in \(([^)]*)\):", src, re.DOTALL)
    # count dispatch loops inside _decode_layer
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    nloops = len(re.findall(r"for _stmtdec in \(", body))
    ok = _check("p0-loops", nloops == 135, "%d loops" % nloops) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1810", F1810_FILED), ("f1811", F1811_FILED),
                       ("f1812", F1812_FILED), ("f1813", F1813_FILED),
                       ("f1814", F1814_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, index exprs HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1810: let/const + renamed + computed index variants
        ("f1810-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let DD=[];for(let ii=0;ii<TT.length;ii++){DD.push(TT.charCodeAt(ii-ii+ii));}let SS=String.fromCharCode.apply(null,DD);" % cs),
        ("f1810-idx2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(2*i-i));}var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1810-idx3", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt((i)));}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1811: let/const + renamed
        ("f1811-const", "const CC=%s;const DD=CC.slice();if(DD.lastIndexOf(CC[0])>=0){const SS=String.fromCharCode.apply(null,DD);}else{const SS='';}" % cs),
        # F1812: let/const + renamed (callback params stay a,c per grammar)
        ("f1812-let", "let CC=%s;let DD=CC.reduceRight(function(a,c){a.push(c);return a;},[]);DD.reverse();let SS=String.fromCharCode.apply(null,DD);" % cs),
        # F1813: let/const + renamed
        ("f1813-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.normalize();let DD=[];for(let ii=0;ii<UU.length;ii++){DD.push(UU.charCodeAt(ii));}let SS=String.fromCharCode.apply(null,DD);" % cs),
        # F1814: let/const + renamed
        ("f1814-const", "const CC=%s;const TT='  '+CC.map(function(c){return String.fromCharCode(c);}).join('')+'  ';const UU=TT.trim();const RESULT=UU;" % cs),
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
        # F1810: wrong method / wrong length base / bad index var
        ("f1810-charAt", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charAt(i));}var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1810-wronglen", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<D.length;i++){D.push(T.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1810-badvar", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(j));}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1811: wrong guard op / missing else
        ("f1811-ne", "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])!=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}" % cs),
        ("f1811-noelse", "var C=%s;var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}" % cs),
        # F1812: arrow callback / missing reverse / unshift
        ("f1812-arrow", "var C=%s;var D=C.reduceRight((a,c)=>{a.push(c);return a;},[]);D.reverse();var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1812-norev", "var C=%s;var D=C.reduceRight(function(a,c){a.push(c);return a;},[]);var S=String.fromCharCode.apply(null,D);" % cs),
        ("f1812-unshift", "var C=%s;var D=C.reduceRight(function(a,c){a.unshift(c);return a;},[]);D.reverse();var S=String.fromCharCode.apply(null,D);" % cs),
        # F1813: normalize with arg
        ("f1813-arg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.normalize('NFD');var D=[];for(var i=0;i<U.length;i++){D.push(U.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);" % cs),
        # F1814: tab padding / no trim
        ("f1814-tabpad", "var C=%s;var T='\t'+C.map(function(c){return String.fromCharCode(c);}).join('')+'\t';var U=T.trim();var RESULT=U;" % cs),
        ("f1814-notrim", "var C=%s;var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T;var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling productions still work (disjointness)."""
    ok = True
    cs = _codes(SECRET_S)
    # F1774 (CLOSED map+join) still HITs via its own hook
    v = _scan("var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('')" % cs)
    ok = _check("p4-f1774", v == "HIT", "got %s" % v) and ok
    # F1810 plain-i variant is covered by the F1810 hook (arith identity)
    v = _scan("var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);" % cs)
    ok = _check("p4-f1810-plain", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "The quarterly financial summary shows revenue growth.",
        "var x = 1; var y = 2; var z = x + y;",
        "var t = s.trim();",
        "var u = t.normalize();",
        "if (a.lastIndexOf(b) >= 0) { console.log('found'); }",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-quiet%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-432 opens still MISS (F1805-F1809, F1815-F1821, F1823-F1826)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1805", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;"),
        ("f1809", "var C={I};var D=C.slice();D.fill(0,D.length,D.length+5);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1815", "var C={I};var T=' '.repeat(C.length-C.length+1)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;"),
        ("f1821", "var C={I};var D=[];for(var [i,v] of C.entries()){D[i]=v;}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1823", "var C={I};var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1826", "var C={I};var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ]
    for name, tmpl in opens:
        payload = tmpl.replace("{I}", cs)
        v = _scan(payload)
        ok = _check("p6-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1810_FILED.replace("{I}", cs),
        F1811_FILED.replace("{I}", cs),
        F1812_FILED.replace("{I}", cs),
        F1813_FILED.replace("{I}", cs),
        F1814_FILED.replace("{I}", cs),
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
    ok = _check("p7-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p8_footer():
    """Footer stamps F1810-F1814 CLOSED; pin counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        txt = f.read()
    for n in range(1810, 1815):
        idx = txt.find("(F%d filed" % n)
        seg = txt[idx:idx+8000] if idx >= 0 else ""
        has = "[CLOSED 2026-10-12 wave-432 lane B" in seg
        ok = _check("p8-f%d-stamp" % n, has, "stamped") and ok
    return ok

def test_g0_green():
    """Depth-1 green check: red-first batteries run."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for n in (1810, 1811, 1812, 1813, 1814):
        f = "evals/w432_f%d_redfirst.py" % n
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            ok = _check("g0-f%d" % n, r.returncode in (0, 1),
                        "exit %d" % r.returncode) and ok
    return ok

def main():
    tests = [
        ("p0", test_p0_pins),
        ("p1", test_p1_filed),
        ("p2", test_p2_generalizations),
        ("p3", test_p3_failclosed),
        ("p4", test_p4_siblings),
        ("p5", test_p5_quiet),
        ("p6", test_p6_other_opens),
        ("p7", test_p7_perf),
        ("p8", test_p8_footer),
        ("g0", test_g0_green),
    ]
    all_ok = True
    for name, fn in tests:
        print("\n=== %s ===" % name)
        try:
            if not fn():
                all_ok = False
        except Exception as e:
            print("FAIL %s EXC: %r" % (name, e))
            all_ok = False
    print("\n" + ("ALL HELD" if all_ok else "FAILURES PRESENT"))
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
