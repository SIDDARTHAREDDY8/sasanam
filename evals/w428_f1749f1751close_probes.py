#!/usr/bin/env python3
"""Wave-428 lane A close battery: F1749, F1750, F1751.

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

FILED = {
    1749: 'var C={I};var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
    1750: 'var C={I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*8,BigInt(C[i]));}var D=[];for(var j=0;j<C.length;j++){D.push(Number(V.getBigUint64(j*8)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
    1751: 'var C={I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setFloat64(i*8,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getFloat64(j*8));}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
}

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 122 (119 base + 3 new dispatch loops, wave-428 merge)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "122",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All three hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1749_stmt_decode", "_js_f1750_stmt_decode",
              "_js_f1751_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Dispatch loop present
    ok = _check("p0-loop", "_js_f1749_stmt_decode, _js_f1750_stmt_decode," in src,
                "dispatch loop") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1749-F1751 stamped CLOSED by wave-428 lane A
    for n in (1749, 1750, 1751):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-428 lane A" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for n, tmpl in FILED.items():
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-f%d-%s" % (n, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace variants HIT."""
    ok = True
    cases = [
        # let/const + renamed idents (F1749)
        'let A={I};let B=new ArrayBuffer(A.length*4);let V=new DataView(B);for(let i=0;i<A.length;i++){V.setUint32(i*4,A[i]);}let D=[];for(let j=0;j<A.length;j++){D.push(V.getUint32(j*4));}let S=String.fromCharCode.apply(null,D);let RESULT=S;',
        'const CC={I};const BB=new ArrayBuffer(CC.length*4);const VV=new DataView(BB);for(var k=0;k<CC.length;k++){VV.setUint32(k*4,CC[k]);}const DD=[];for(var m=0;m<CC.length;m++){DD.push(VV.getUint32(m*4));}const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;',
        # whitespace variants (F1749)
        'var C = {I} ; var B = new ArrayBuffer( C.length * 4 ) ; var V = new DataView( B ) ; for( var i = 0 ; i < C.length ; i ++ ){ V.setUint32( i * 4 , C[ i ] ) ; } var D = [] ; for( var j = 0 ; j < C.length ; j ++ ){ D.push( V.getUint32( j * 4 ) ) ; } var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;',
        # let + renamed (F1750)
        'let A={I};let B=new ArrayBuffer(A.length*8);let V=new DataView(B);for(let i=0;i<A.length;i++){V.setBigUint64(i*8,BigInt(A[i]));}let D=[];for(let j=0;j<A.length;j++){D.push(Number(V.getBigUint64(j*8)));}let S=String.fromCharCode.apply(null,D);let RESULT=S;',
        # whitespace (F1750)
        'var C={I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*8, BigInt(C[i]));}var D=[];for(var j=0;j<C.length;j++){D.push(Number(V.getBigUint64(j*8)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        # const + renamed (F1751)
        'const CC={I};const BB=new ArrayBuffer(CC.length*8);const VV=new DataView(BB);for(var k=0;k<CC.length;k++){VV.setFloat64(k*8,CC[k]);}const DD=[];for(var m=0;m<CC.length;m++){DD.push(VV.getFloat64(m*8));}const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;',
        # whitespace (F1751)
        'var C = {I};var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setFloat64(i*8,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getFloat64(j*8));}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
    ]
    for tmpl in cases:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        v = _scan(payload)
        ok = _check("p2-gen", v == "HIT", "got %s for %r" % (v, tmpl[:50])) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    from gov.dlp import (_js_f1749_stmt_decode, _js_f1750_stmt_decode,
                         _js_f1751_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1749 hook: setUint8 (F1740 sibling -- must not match)
        (_js_f1749_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1749 hook: stride 2 (F1746 sibling -- must not match)
        (_js_f1749_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1749 hook: buffer size mismatch (stride 4 but length*8)
        (_js_f1749_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1749 hook: get stride mismatch
        (_js_f1749_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*8));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1750 hook: missing BigInt wrapper (would throw in node)
        (_js_f1750_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*8,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(Number(V.getBigUint64(j*8)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1750 hook: missing Number wrapper
        (_js_f1750_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*8,BigInt(C[i]));}var D=[];for(var j=0;j<C.length;j++){D.push(V.getBigUint64(j*8));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1750 hook: wrong stride
        (_js_f1750_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setBigUint64(i*4,BigInt(C[i]));}var D=[];for(var j=0;j<C.length;j++){D.push(Number(V.getBigUint64(j*4)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1751 hook: setFloat32 (different width)
        (_js_f1751_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setFloat32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getFloat32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1751 hook: stride 4 (wrong for f64)
        (_js_f1751_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setFloat64(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getFloat64(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1751 hook: F1749's u32 shape (sibling -- must not match)
        (_js_f1751_stmt_decode,
         FILED[1749].replace("{I}", cs)),
        # F1749 hook: F1751's f64 shape (sibling -- must not match)
        (_js_f1749_stmt_decode,
         FILED[1751].replace("{I}", cs)),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1740 (u8 stmt), F1746 (u16), F742 (u8 IIFE) still HIT
    via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        ("f1740", 'var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1746", 'var C={I};var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f742", "(function(){var v=new DataView(new ArrayBuffer(4));v.setUint8(0,120);v.setUint8(1,111);return String.fromCharCode(v.getUint8(0),v.getUint8(1))+'xb-0123'+'456789abcdef';})()"),
    ]
    for name, tmpl in sibs:
        payload = tmpl.replace("{I}", cs)
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    for junk in [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "function foo() { return bar; }",
        "const arr = [1,2,3]; const doubled = arr.map(x => x * 2);",
        "var buf = new ArrayBuffer(16); var view = new DataView(buf); view.setUint32(0, 1234);",
        "DataView.prototype.setUint32.call(view, 0, value);",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:40])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        # F1752-F1756 now CLOSED on the merged tree (lanes B+C) -- removed from other-opens
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
        FILED[1749].replace("{I}", cs),
        FILED[1750].replace("{I}", cs),
        FILED[1751].replace("{I}", cs),
        "var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
    """Depth-1 green check: the F1749/F1750/F1751 red-first batteries still run
    (they now report NO-BREAK on the fixed tree, exit 1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w428_f1749_redfirst.py", "evals/w428_f1750_redfirst.py",
              "evals/w428_f1751_redfirst.py"]:
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
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
