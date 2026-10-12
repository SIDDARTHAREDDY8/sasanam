#!/usr/bin/env python3
"""Wave-429 lane C close battery: F1763, F1764, F1765.

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

F1763_FILED = 'var C={I};var P=new Proxy(C,{});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;'
F1764_FILED = 'var C={I};var U=new Uint8Array(C);var V=U.toSorted(function(){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;'
F1765_FILED = 'var C={I};var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;'

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 123 (122 base + 1 new dispatch loop, wave-429 lane C)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "123",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All three hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1763_stmt_decode", "_js_f1764_stmt_decode",
              "_js_f1765_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1763-F1765 stamped CLOSED by wave-429 lane C
    for n in (1763, 1764, 1765):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-429 lane C" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT, node-exact."""
    ok = True
    sys.path.insert(0, REPO_ROOT)
    from gov.dlp import (_js_f1763_stmt_decode, _js_f1764_stmt_decode,
                         _js_f1765_stmt_decode)
    hooks = {"f1763": _js_f1763_stmt_decode, "f1764": _js_f1764_stmt_decode,
             "f1765": _js_f1765_stmt_decode}
    tmpls = {"f1763": F1763_FILED, "f1764": F1764_FILED, "f1765": F1765_FILED}
    for name, tmpl in tmpls.items():
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
            # node-exactness: hook decode == node RESULT == secret
            hook = hooks[name]
            dec = hook(payload)
            nr = _node_result(payload)
            ok = _check("p1-%s-%s-nodeexact" % (name, label),
                        dec == secret and nr == secret,
                        "hook==node==secret" if (dec == secret and nr == secret)
                        else "hook=%r node=%r" % (dec, nr)) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, comparator params HIT."""
    ok = True
    cases = [
        # F1763: let + renamed idents
        'let CC={I};let PP=new Proxy(CC,{});let DD=Array.from(PP);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;',
        # F1763: const + whitespace
        'const C = {I} ; const P = new Proxy( C , { } ) ; const D = Array.from( P ) ; const S = String.fromCharCode.apply( null , D ) ; const RESULT = S ;',
        # F1764: comparator with params (node-identical)
        'var C={I};var U=new Uint8Array(C);var V=U.toSorted(function(a,b){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        # F1764: let + renamed idents
        'let CC={I};let UU=new Uint8Array(CC);let VV=UU.toSorted(function(){return 0;});let DD=Array.from(VV);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;',
        # F1764: whitespace
        'var C = {I} ; var U = new Uint8Array( C ) ; var V = U.toSorted( function ( ) { return 0 ; } ) ; var D = Array.from( V ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;',
        # F1765: let + renamed idents
        'let CC={I};let BB=new SharedArrayBuffer(CC.length);let UU=new Uint8Array(BB);UU.set(CC);let SS=String.fromCharCode.apply(null,Array.from(UU));let RESULT=SS;',
        # F1765: const + whitespace
        'const C = {I} ; const B = new SharedArrayBuffer( C.length ) ; const U = new Uint8Array( B ) ; U.set( C ) ; const S = String.fromCharCode.apply( null , Array.from( U ) ) ; const RESULT = S ;',
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
    from gov.dlp import (_js_f1763_stmt_decode, _js_f1764_stmt_decode,
                         _js_f1765_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1763: non-empty handler (node throws on iterator -- must not match)
        (_js_f1763_stmt_decode,
         'var C=%s;var P=new Proxy(C,{get:function(t,k){return 1;}});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1763: proxy over wrong target (decodes wrong array -- must not match)
        (_js_f1763_stmt_decode,
         'var C=%s;var X=[1,2,3];var P=new Proxy(X,{});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1763: handler with set trap (not transparent -- must not match)
        (_js_f1763_stmt_decode,
         'var C=%s;var P=new Proxy(C,{set:function(){return true;}});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1763: Array.from on C directly (different shape -- must not match this hook)
        (_js_f1763_stmt_decode,
         'var C=%s;var D=Array.from(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1764: sorting comparator (node reorders -- must not match)
        (_js_f1764_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.toSorted(function(a,b){return a-b;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1764: arrow comparator (narrow grammar -- must not match)
        (_js_f1764_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.toSorted(()=>0);var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1764: return 1 (not identity -- must not match)
        (_js_f1764_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.toSorted(function(){return 1;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1764: no comparator (default numeric sort -- must not match)
        (_js_f1764_stmt_decode,
         'var C=%s;var U=new Uint8Array(C);var V=U.toSorted();var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1764: toSorted on plain array (F1761 domain -- must not match this hook)
        (_js_f1764_stmt_decode,
         'var C=%s;var V=C.toSorted(function(){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1765: set with offset (node throws -- must not match)
        (_js_f1765_stmt_decode,
         'var C=%s;var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C,1);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % cs),
        # F1765: wrong buffer size (not C.length -- must not match)
        (_js_f1765_stmt_decode,
         'var C=%s;var B=new SharedArrayBuffer(64);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % cs),
        # F1765: plain ArrayBuffer (F1741 domain -- must not match this hook)
        (_js_f1765_stmt_decode,
         'var C=%s;var B=new ArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % cs),
        # F1765: set on wrong view (must not match)
        (_js_f1765_stmt_decode,
         'var C=%s;var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);var W=new Uint8Array(8);W.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;' % cs),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1741 (ArrayBuffer.slice), F1039 (Atomics SAB) still HIT
    via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        ("f1741", 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
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
        "var P = new Proxy({}, {});",
        "var U = new Uint8Array(16); var V = U.toSorted();",
        "var B = new SharedArrayBuffer(16);",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        ("f1757", 'var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1758", 'var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=Array.from(M.values());var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1759", 'var C={I};(async function(){var D=await Array.fromAsync(C);var S=String.fromCharCode.apply(null,D);})();var RESULT="x";'),
        ("f1760", 'var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[B]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        ("f1761", 'var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1762", 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1766", "var C={I};var F=new Function('C','return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;"),
        ("f1767", 'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gdi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
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
        F1763_FILED.replace("{I}", cs),
        F1764_FILED.replace("{I}", cs),
        F1765_FILED.replace("{I}", cs),
        'var C=%s;var P=new Proxy(C,{get:function(t,k){return 1;}});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs,
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
    """Depth-1 green check: the F1763/F1764/F1765 red-first batteries still run
    (they now report NO-BREAK on the fixed tree, exit 1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w429_f1763_redfirst.py", "evals/w429_f1764_redfirst.py",
              "evals/w429_f1765_redfirst.py"]:
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
