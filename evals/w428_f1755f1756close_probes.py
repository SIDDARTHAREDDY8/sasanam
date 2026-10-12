#!/usr/bin/env python3
"""Wave-428 lane C close battery: F1755, F1756.

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

def _node_result(payload):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:]
    return None

def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"

F1755_FILED = 'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'
F1756_FILED = 'var C={I};var S=(function(){var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}return String.fromCharCode.apply(null,D);})();var RESULT=S;'

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 120 (119 base + 1 new dispatch loop, wave-428 lane C)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "122",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # Both hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1755_stmt_decode", "_js_f1756_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1755-F1756 stamped CLOSED by wave-428 lane C
    for n in (1755, 1756):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-428 lane C" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    # F1767 filed OPEN (lane-C residual on F1755 flag filter)
    o = bool(re.search(r"\(F1767 filed 2026-10-12 06:42 UTC.*?LOW, OPEN:", ftxt, re.DOTALL))
    ok = _check("p0-f1767-open", o, "filed OPEN" if o else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT, node-exact."""
    ok = True
    for name, tmpl in (("f1755", F1755_FILED), ("f1756", F1756_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
            # node-exactness: hook decode == node RESULT == secret
            sys.path.insert(0, REPO_ROOT)
            from gov.dlp import (_js_f1755_stmt_decode, _js_f1756_stmt_decode)
            hook = _js_f1755_stmt_decode if name == "f1755" else _js_f1756_stmt_decode
            dec = hook(payload)
            nr = _node_result(payload)
            ok = _check("p1-%s-%s-nodeexact" % (name, label),
                        dec == secret and nr == secret,
                        "hook==node==secret" if (dec == secret and nr == secret)
                        else "hook=%r node=%r" % (dec, nr)) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, dg flag order HIT."""
    ok = True
    cases = [
        # F1755: let + renamed idents
        'let CC={I};let SS=String.fromCharCode.apply(null,CC);let RR=/(.)/gd;let DD=new Array(CC.length);let MM;while((MM=RR.exec(SS))!==null){DD[MM.indices[0][0]]=MM[1].charCodeAt(0);}let TT=String.fromCharCode.apply(null,DD);let RESULT=TT;',
        # F1755: const + whitespace
        'const C = {I} ; const S = String.fromCharCode.apply( null , C ) ; const R = /(.)/gd ; const D = new Array( C.length ) ; var M ; while ( ( M = R.exec( S ) ) !== null ) { D[ M.indices[0][0] ] = M[1].charCodeAt( 0 ) ; } const T = String.fromCharCode.apply( null , D ) ; const RESULT = T ;',
        # F1755: dg flag order (node-identical)
        'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/dg;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;',
        # F1755: let M
        'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);let M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;',
        # F1756: let/const + renamed idents
        'let CC={I};let SS=(function(){let BB=new ArrayBuffer(CC.length*4);let VV=new DataView(BB);for(let i=0;i<CC.length;i++){VV.setUint32(i*4,CC[i]);}let DD=[];for(let j=0;j<CC.length;j++){DD.push(VV.getUint32(j*4));}return String.fromCharCode.apply(null,DD);})();let RESULT=SS;',
        # F1756: whitespace
        'var C = {I} ; var S = ( function ( ) { var B = new ArrayBuffer( C.length * 4 ) ; var V = new DataView( B ) ; for ( var i = 0 ; i < C.length ; i ++ ) { V.setUint32( i * 4 , C[ i ] ) ; } var D = [ ] ; for ( var j = 0 ; j < C.length ; j ++ ) { D.push( V.getUint32( j * 4 ) ) ; } return String.fromCharCode.apply( null , D ) ; } ) ( ) ; var RESULT = S ;',
    ]
    for tmpl in cases:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        v = _scan(payload)
        ok = _check("p2-gen", v == "HIT", "got %s for %r" % (v, tmpl[:60])) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1755_stmt_decode, _js_f1756_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1755: missing d flag (node TypeError on M.indices -- must not match)
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/g;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: missing g flag (node infinite loop -- must not match)
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/d;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: s (dotAll) flag changes `.` semantics -- must not match
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gds;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: two-char pattern -- different staging
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(..)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: indices[0][1] (end, not start) -- different
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][1]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: M[2] (no such group) -- different
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[2].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: charCodeAt(1) -- different
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(1);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: line terminator in codes (node leaves a hole -> NUL)
        (_js_f1755_stmt_decode,
         'var C=[120,10,120];var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
        # F1755: const M (node SyntaxError) -- must not match
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);const M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1755: !=null (narrower than filed !==null -- fail closed, miss not mis-decode)
        (_js_f1755_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!=null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1756: u16 width (sibling domain -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var S=(function(){var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}return String.fromCharCode.apply(null,D);})();var RESULT=S;' % cs),
        # F1756: u8 width (F742 domain -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var S=(function(){var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}return String.fromCharCode.apply(null,D);})();var RESULT=S;' % cs),
        # F1756: statement form, no IIFE (F1749 domain -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1756: wrong stride i*8 (out-of-range writes in node -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var S=(function(){var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*8,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*8));}return String.fromCharCode.apply(null,D);})();var RESULT=S;' % cs),
        # F1756: buffer C.length*8 (width mismatch -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var S=(function(){var B=new ArrayBuffer(C.length*8);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}return String.fromCharCode.apply(null,D);})();var RESULT=S;' % cs),
        # F1756: F1740's u8 statement shape (sibling -- must not match)
        (_js_f1756_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1755 hook on F1033's replace-callback shape (sibling -- must not match)
        (_js_f1755_stmt_decode,
         'var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT="#####################".replace(/./g,function(m,i){return String.fromCharCode(codes[i]);});'),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1740 (u8 stmt), F1746 (u16 stmt), F1033 (regexp
    replace) still HIT via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        ("f1740", 'var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1746", 'var C={I};var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1033", 'var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT="#####################".replace(/./g,function(m,i){return String.fromCharCode(codes[i]);});'),
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
        "var re = /(.)/gd; var m = re.exec('hello');",
        "var B = new ArrayBuffer(16); var V = new DataView(B);",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        # All other wave-428 findings now CLOSED on the merged tree
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
        F1755_FILED.replace("{I}", cs),
        F1756_FILED.replace("{I}", cs),
        "var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/g;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;" % cs,
        "var C=%s;var B=new ArrayBuffer(C.length*4);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint32(i*4,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint32(j*4));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
    """Depth-1 green check: the F1755/F1756 red-first batteries still run
    (they now report NO-BREAK on the fixed tree, exit 1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w428_f1755_redfirst.py", "evals/w428_f1756_redfirst.py",
              "evals/w428_f1767_redfirst.py"]:
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
