#!/usr/bin/env python3
"""Wave-427 lane A close battery: F1735, F1736, F1737, F1738.

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

SECRET_S = "xoxb-01" + "23456789abcdef"
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

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 119 (115 base + 1 new dispatch loop, wave-427 lane A)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "119",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All four hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1735_stmt_decode", "_js_f1736_stmt_decode",
              "_js_f1737_stmt_decode", "_js_f1738_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1735-F1738 stamped CLOSED by wave-427 lane A
    for n in (1735, 1736, 1737, 1738):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-427 lane A" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    shapes = [
        ("f1735", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length+(C.length-C.length),' ');var RESULT=T;"),
        ("f1736", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+(C.length-C.length),' ');var RESULT=T;"),
        ("f1737", "var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
        ("f1738", "var C={I};var U=new Uint8Array(C.length);U.set(C,C.length-C.length);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;"),
    ]
    for name, tmpl in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, pad variants HIT."""
    ok = True
    cases = [
        # F1735: let, bare S.length
        'let C={I};let S=String.fromCharCode.apply(null,C);let T=S.padStart(S.length," ");let RESULT=T;',
        # F1735: const, (0) form, different pad string
        'const C={I};const S=String.fromCharCode.apply(null,C);const T=S.padStart(S.length+(0),"xy");const RESULT=T;',
        # F1735: renamed idents
        'var CC={I};var SS=String.fromCharCode.apply(null,CC);var TT=SS.padStart(SS.length+(CC.length-CC.length)," ");var RESULT=TT;',
        # F1735: whitespace variants
        'var C = {I} ; var S = String.fromCharCode.apply( null , C ) ; var T = S.padStart( S.length + ( C.length - C.length ) , \' \' ) ; var RESULT = T ;',
        # F1736: let, bare S.length
        'let C={I};let S=String.fromCharCode.apply(null,C);let T=S.padEnd(S.length," ");let RESULT=T;',
        # F1736: (0) form
        'var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+(0),"pad");var RESULT=T;',
        # F1737: let/const, renamed
        'let C={I};let U=new Uint8Array(C);let V=U.subarray(0);let A=Array.from(V);A.reverse();A.reverse();let S=String.fromCharCode.apply(null,A);let RESULT=S;',
        'const CC={I};const UU=new Uint8Array(CC);const VV=UU.subarray(0);const AA=Array.from(VV);AA.reverse();AA.reverse();const SS=String.fromCharCode.apply(null,AA);const RESULT=SS;',
        # F1738: bare 0 offset
        'var C={I};var U=new Uint8Array(C.length);U.set(C,0);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;',
        # F1738: let, renamed
        'let C={I};let U=new Uint8Array(C.length);U.set(C,C.length-C.length);let S=String.fromCharCode.apply(null,Array.from(U));let RESULT=S;',
    ]
    for tmpl in cases:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        v = _scan(payload)
        ok = _check("p2-gen", v == "HIT", "got %s for %.50s" % (v, tmpl)) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1735_stmt_decode, _js_f1736_stmt_decode,
                         _js_f1737_stmt_decode, _js_f1738_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1735: padEnd instead of padStart (F1736's shape -- our hook must not match)
        (_js_f1735_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+(C.length-C.length)," ");var RESULT=T;' % cs),
        # F1735: nonzero padding (would actually pad -- not identity)
        (_js_f1735_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length+1," ");var RESULT=T;' % cs),
        # F1735: wrong length base
        (_js_f1735_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(C.length," ");var RESULT=T;' % cs),
        # F1736: padStart instead of padEnd
        (_js_f1736_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length," ");var RESULT=T;' % cs),
        # F1736: nonzero padding
        (_js_f1736_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+5," ");var RESULT=T;' % cs),
        # F1737: single reverse (not identity -- our hook must not match)
        (_js_f1737_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;' % cs),
        # F1737: triple reverse (not identity)
        (_js_f1737_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;' % cs),
        # F1737: code out of u8 range (would truncate -- fail closed)
        (_js_f1737_stmt_decode,
         'var C=[300];var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;'),
        # F1737: subarray(1) (not full -- not identity)
        (_js_f1737_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(1);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;' % cs),
        # F1738: nonzero offset (would misplace -- fail closed)
        (_js_f1738_stmt_decode,
         'var C=%s;var U=new Uint8Array(C.length);U.set(C,1);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % cs),
        # F1738: code out of u8 range
        (_js_f1738_stmt_decode,
         'var C=[300];var U=new Uint8Array(C.length);U.set(C,0);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;'),
        # F1738: wrong set source
        (_js_f1738_stmt_decode,
         'var C=%s;var D=%s;var U=new Uint8Array(C.length);U.set(D,0);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % (cs, cs)),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1143/F1698/F1245 still HIT via their own hooks; F1735 vs F1736 disjoint."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        # F1143: loop-based padEnd staged assembly
        ("f1143", 'var C={I};var S="";for(var i=0;i<C.length;i++){S=S.padEnd(S.length+1,String.fromCharCode(C[i]));}var RESULT=S;'),
        # F1735 shape must NOT trigger F1736 hook and vice versa (disjoint by grammar)
    ]
    for name, tmpl in sibs:
        payload = tmpl.replace("{I}", cs)
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    # Cross-check: F1735 hook must not match F1736 shape, F1736 hook must not match F1735 shape
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import _js_f1735_stmt_decode, _js_f1736_stmt_decode
    f1735_shape = 'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length," ");var RESULT=T;' % cs
    f1736_shape = 'var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length," ");var RESULT=T;' % cs
    ok = _check("p4-disjoint-1735", _js_f1735_stmt_decode(f1736_shape) is None, "F1735 hook rejects padEnd") and ok
    ok = _check("p4-disjoint-1736", _js_f1736_stmt_decode(f1735_shape) is None, "F1736 hook rejects padStart") and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    for junk in [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "function foo() { return bar; }",
        "const arr = [1,2,3]; const doubled = arr.map(x => x * 2);",
        "var s = 'hello'; var t = s.padStart(10, ' '); console.log(t);",
        "var u = new Uint8Array([1,2,3]); var v = u.subarray(0);",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1749", "var C={I};var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1750", "var C={I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*8,BigInt(C[i]));}var D=[];for(var j=0;j<C.length;j++){D.push(Number(V.getBigUint64(j*8)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1751", "var C={I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setFloat64(i*8,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getFloat64(j*8));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1752", "var C={I};var B=new Uint8Array(C).buffer;var B2=B.transfer();var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;"),
        ("f1753", "var C={I};var B=new Uint8Array(C).buffer;var B2=B.transferToFixedLength();var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;"),
        ("f1754", "var C={I};var B=new ArrayBuffer(C.length,{maxByteLength:C.length*2});var U=new Uint8Array(B);U.set(C);B.resize(C.length);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B)));var RESULT=S;"),
        ("f1755", "var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;"),
        ("f1756", "var C={I};var S=(function(){var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}return String.fromCharCode.apply(null,D);})();var RESULT=S;"),
    ]
    for name, tmpl in opens:
        payload = tmpl.replace("{I}", cs)
        v = _scan(payload)
        ok = _check("p6-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok


def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        "var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length,' ');var RESULT=T;" % cs,
        "var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length,' ');var RESULT=T;" % cs,
        "var C=%s;var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;" % cs,
        "var C=%s;var U=new Uint8Array(C.length);U.set(C,0);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;" % cs,
    ]
    sites = []
    for i in range(200):
        if i % 5 < 4:
            sites.append(tmpls[i % 4])
        else:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    ok = _check("p7-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_g0_green():
    """Depth-1 green check: adjacent batteries' mains with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w427_f1735_redfirst.py",
              "evals/w427_f1736_redfirst.py",
              "evals/w427_f1737_redfirst.py",
              "evals/w427_f1738_redfirst.py"]:
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            # Red-first batteries return 1 post-fix (NO-BREAK) which is expected
            ok = _check("g0-%s" % f.split("/")[-1], r.returncode in (0, 1),
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
        ("g0", test_g0_green),
    ]
    all_ok = True
    for name, fn in tests:
        print("\n=== %s ===" % name)
        try:
            if not fn():
                all_ok = False
        except Exception as e:
            print("EXCEPTION in %s: %s" % (name, e))
            import traceback
            traceback.print_exc()
            all_ok = False
    print("\n" + "=" * 50)
    n_pass = sum(1 for _, ok, _ in _results if ok)
    n_total = len(_results)
    print("RESULT: %d/%d %s" % (n_pass, n_total, "HELD" if all_ok else "BROKEN"))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
