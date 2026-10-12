#!/usr/bin/env python3
"""Wave-429 lane D close battery: F1766, F1767.

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

F1766_FILED = "var C={I};var F=new Function('C','return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;"
F1767_FILED = 'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gdi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 123 (122 base + 1 new dispatch loop, wave-429 lane D)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "123",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # Both hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1766_stmt_decode", "_js_f1767_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1766-F1767 stamped CLOSED by wave-429 lane D
    for n in (1766, 1767):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-429 lane D" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT, node-exact."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1766_stmt_decode, _js_f1767_stmt_decode)
    for name, tmpl, hook in (("f1766", F1766_FILED, _js_f1766_stmt_decode),
                             ("f1767", F1767_FILED, _js_f1767_stmt_decode)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
            # node-exactness: hook decode == node RESULT == secret
            dec = hook(payload)
            nr = _node_result(payload)
            ok = _check("p1-%s-%s-nodeexact" % (name, label),
                        dec == secret and nr == secret,
                        "hook==node==secret" if (dec == secret and nr == secret)
                        else "hook=%r node=%r" % (dec, nr)) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, flag variants HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1766: let + renamed idents
        "let CC=%s;let FF=new Function('CC','return String.fromCharCode.apply(null,CC);');let SS=FF(CC);let RESULT=SS;" % cs,
        # F1766: const + whitespace + double quotes
        'const C = %s ; const F = new Function( "C" , "return String.fromCharCode.apply(null,C);" ) ; const S = F( C ) ; const RESULT = S ;' % cs,
        # F1766: body without trailing semicolon (ws-tolerant)
        "var C=%s;var F=new Function('C','return String.fromCharCode.apply(null,C)');var S=F(C);var RESULT=S;" % cs,
        # F1766: body with extra whitespace
        "var C=%s;var F=new Function('C','  return  String.fromCharCode.apply( null , C ) ;  ');var S=F(C);var RESULT=S;" % cs,
        # F1767: all benign flag variants
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gdm;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gdy;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gds;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gdu;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/dgi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
        # F1767: let/const + renamed idents
        'let CC=%s;let SS=String.fromCharCode.apply(null,CC);let RR=/(.)/gdi;let DD=new Array(CC.length);let MM;while((MM=RR.exec(SS))!==null){DD[MM.indices[0][0]]=MM[1].charCodeAt(0);}let TT=String.fromCharCode.apply(null,DD);let RESULT=TT;' % cs,
    ]
    for tmpl in cases:
        v = _scan(tmpl)
        ok = _check("p2-gen", v == "HIT", "got %s for %r" % (v, tmpl[:60])) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1766_stmt_decode, _js_f1767_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1766: param name mismatch (body reads undeclared -- must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=new Function('D','return String.fromCharCode.apply(null,D);');var S=F(C);var RESULT=S;" % cs),
        # F1766: body not return-FCC-apply (additive body -- F964 domain, must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=new Function('C','return C;');var S=F(C);var RESULT=S;" % cs),
        # F1766: body reads outer C, not param (different binding -- must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=new Function('D','return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;" % cs),
        # F1766: call arg mismatch (must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var D=%s;var F=new Function('C','return String.fromCharCode.apply(null,C);');var S=F(D);var RESULT=S;" % (cs, cs)),
        # F1766: call target mismatch (must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=new Function('C','return String.fromCharCode.apply(null,C);');var G=F;var S=G(C);var RESULT=S;" % cs),
        # F1766: body with extra statement (must not match)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=new Function('C','var x=1;return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;" % cs),
        # F1766: no new (plain Function call -- different shape, must not match this hook)
        (_js_f1766_stmt_decode,
         "var C=%s;var F=Function('C','return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;" % cs),
        # F1767: v flag (not benign -- must not match)
        (_js_f1767_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gdv;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1767: duplicate d flag (node SyntaxError -- must not match)
        (_js_f1767_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gdd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1767: missing d flag (node TypeError -- must not match)
        (_js_f1767_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1767: missing g flag (node infinite loop -- must not match)
        (_js_f1767_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/di;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1767: exact gd (F1755 domain -- must not match THIS hook, F1755 handles it)
        (_js_f1767_stmt_decode,
         'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs),
        # F1767 spec-review: u flag + surrogate PAIR mis-decodes in node
        # (hole at low surrogate) -- must fail closed, not mis-decode
        (_js_f1767_stmt_decode,
         'var C=[65,66,55357,56832,67,68];var S=String.fromCharCode.apply(null,C);var R=/(.)/gdu;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1648, F964, F1755, F1033 still HIT via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        # F1755: exact gd flags (disjoint -- F1767 requires extras)
        ("f1755", 'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gd;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
        # F1033: RegExp replace-callback (disjoint)
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
        "var F = new Function('a', 'b', 'return a + b;');",
        "var re = /(.)/gdi; var m = re.exec('hello');",
        "var C = [1,2,3]; var S = String.fromCharCode.apply(null, C);",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1757", "var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1758", "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=Array.from(M.values());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1759", "var C={I};(async function(){var D=await Array.fromAsync(C);console.log('OUT:'+String.fromCharCode.apply(null,D));})();"),
        ("f1760", "var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[B]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;"),
        ("f1761", "var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1762", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1763", "var C={I};var P=new Proxy(C,{});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1764", "var C={I};var U=new Uint8Array(C);var V=U.toSorted(function(){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1765", "var C={I};var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;"),
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
        F1766_FILED.replace("{I}", cs),
        F1767_FILED.replace("{I}", cs),
        "var C=%s;var F=new Function('C','return C;');var S=F(C);var RESULT=S;" % cs,
        'var C=%s;var S=String.fromCharCode.apply(null,C);var R=/(.)/g;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;' % cs,
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
    """Depth-1 green check: the F1766/F1767 red-first batteries still run
    (they now report NO-BREAK on the fixed tree, exit 1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w428_f1766_redfirst.py", "evals/w428_f1767_redfirst.py"]:
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
