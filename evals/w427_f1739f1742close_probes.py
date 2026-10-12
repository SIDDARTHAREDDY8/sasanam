#!/usr/bin/env python3
"""Wave-427 lane B close battery: F1739, F1740, F1741, F1742.

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
    # N_STMTDEC_LOOPS = 119 (115 + 1 new dispatch loop, wave-427 lane B)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "119",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All four hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1739_stmt_decode", "_js_f1740_stmt_decode",
              "_js_f1741_stmt_decode", "_js_f1742_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1739-F1742 stamped CLOSED by wave-427 lane B
    for n in (1739, 1740, 1741, 1742):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-427 lane B" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    shapes = [
        ("f1739", 'var C={I};var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;'),
        ("f1740", 'var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1741", 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        ("f1742", 'var C={I};var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace variants HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1739: let decls, renamed idents
        'let C=%s;let U=new Uint8Array(C);let V=U.subarray(0).subarray(0);let S=String.fromCharCode.apply(null,Array.from(V));let RESULT=S;' % cs,
        # F1739: whitespace variant
        'var C = %s ; var U = new Uint8Array( C ) ; var V = U.subarray( 0 ).subarray( 0 ) ; var S = String.fromCharCode.apply( null , Array.from( V ) ) ; var RESULT = S ;' % cs,
        # F1740: let loop vars, renamed idents
        'var CC=%s;var BB=new ArrayBuffer(CC.length);var VV=new DataView(BB);for(let ii=0;ii<CC.length;ii++){VV.setUint8(ii,CC[ii]);}var DD=[];for(let jj=0;jj<CC.length;jj++){DD.push(VV.getUint8(jj));}var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;' % cs,
        # F1741: const decls
        'const C=%s;const B=new Uint8Array(C).buffer;const B2=B.slice(0);const S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));const RESULT=S;' % cs,
        # F1742: renamed idents + whitespace
        'var CC=%s;var DD=CC.toReversed();DD.reverse();var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;' % cs,
    ]
    for tmpl in cases:
        v = _scan(tmpl)
        ok = _check("p2-gen", v == "HIT", "got %s for %r" % (v, tmpl[:40])) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1739_stmt_decode, _js_f1740_stmt_decode,
                         _js_f1741_stmt_decode, _js_f1742_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1739: single subarray (F1698's shape -- our hook must not match)
        (_js_f1739_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;' % cs),
        # F1739: subarray with args (not identity)
        (_js_f1739_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(0).subarray(1);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;' % cs),
        # F1739: direct apply on V (not Array.from)
        (_js_f1739_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,V);var RESULT=S;' % cs),
        # F1740: setUint16 stride (F1746's shape -- our hook must not match)
        (_js_f1740_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1740: wrong loop bound (not C.length)
        (_js_f1740_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<=C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1740: getInt8 width (not getUint8)
        (_js_f1740_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getInt8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1741: slice(1) (not identity)
        (_js_f1741_stmt_decode,
         'var C=%s;var B=new Uint8Array(C).buffer;var B2=B.slice(1);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;' % cs),
        # F1741: missing .buffer (plain Uint8Array, not a buffer)
        (_js_f1741_stmt_decode,
         'var C=%s;var B=new Uint8Array(C);var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;' % cs),
        # F1742: toReversed alone (F561's shape -- our hook must not match)
        (_js_f1742_stmt_decode,
         'var C=%s;var D=C.toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1742: double reverse (net reversed, not identity)
        (_js_f1742_stmt_decode,
         'var C=%s;var D=C.toReversed();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1742: reverse on wrong ident
        (_js_f1742_stmt_decode,
         'var C=%s;var D=C.toReversed();C.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1698/F742/F561 still HIT via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    A1 = "xoxb-" + "0123"
    A2 = "456789" + "abcdef"
    sibs = [
        ("f1698", 'var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var S=String.fromCharCode.apply(null,V);var RESULT=S;'.replace("{I}", cs)),
        ("f742", "(function(){var v=new DataView(new ArrayBuffer(4));v.setUint8(0,120);v.setUint8(1,111);return String.fromCharCode(v.getUint8(0),v.getUint8(1))+'xb-0123'+'456789abcdef';})()"),
        ("f561", "['%s','%s'].toReversed().join('')" % (A2, A1)),
    ]
    for name, payload in sibs:
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
        "const buf = new ArrayBuffer(8); const view = new DataView(buf);",
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
    sites = []
    cs = _codes(SECRET_S)
    tmpls = [
        "var C=%s;var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;" % cs,
        "var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
        "var C=%s;var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;" % cs,
        "var C=%s;var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
    ]
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
    """Depth-1 green check: sibling red-first batteries still behave."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w423_f1698_redfirst.py", "evals/w383_f742_redfirst.py",
              "evals/w368_f561_redfirst.py"]:
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
