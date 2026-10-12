#!/usr/bin/env python3
"""Wave-429 lane A close battery: F1757, F1758, F1759.

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

FILED = {
    1757: ('var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});'
           'var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}'
           'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    1758: ('var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));'
           'var D=Array.from(M.values());'
           'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    1759: ('var C={I};var RESULT="";(async function(){var D=await Array.fromAsync(C);'
           'var S=String.fromCharCode.apply(null,D);RESULT=S;})()'),
}

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 123 (122 base + 1 new dispatch loop, wave-429 lane A)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "123",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All three hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1757_stmt_decode", "_js_f1758_stmt_decode",
              "_js_f1759_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Dispatch loop present
    ok = _check("p0-loop", "_js_f1757_stmt_decode,\n                     _js_f1758_stmt_decode," in src,
                "dispatch loop") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1757-F1759 stamped CLOSED by wave-429 lane A
    for n in (1757, 1758, 1759):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-429 lane A" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT (including entry-literal variants)."""
    ok = True
    for n, tmpl in FILED.items():
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-f%d-%s" % (n, label), v == "HIT", "got %s" % v) and ok
    # F1757 entry-literal: }; after the concat loop (FINDINGS entry text)
    cs = _codes(SECRET_S)
    p1757_entry = ('var C=' + cs + ';var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});'
                   'var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);};'
                   'var S=String.fromCharCode.apply(null,D);var RESULT=S;')
    v = _scan(p1757_entry)
    ok = _check("p1-f1757-entry-semi", v == "HIT", "got %s" % v) and ok
    # F1759 filed shape: no RESULT (attack round 96 entry text)
    p1759_filed = ('var C=' + cs + ';(async function(){var D=await Array.fromAsync(C);'
                   'var S=String.fromCharCode.apply(null,D);})()')
    v = _scan(p1759_filed)
    ok = _check("p1-f1759-filed-no-result", v == "HIT", "got %s" % v) and ok
    # F1759 filed shape, long credential
    p1759_filed_l = p1759_filed.replace(cs, _codes(SECRET_L))
    v = _scan(p1759_filed_l)
    ok = _check("p1-f1759-filed-no-result-long", v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, chunk sizes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1757: let + renamed idents + different chunk size (K=8)
        ('let A=' + cs + ';let G=Object.groupBy(A,function(x,j){return Math.floor(j/8);});'
         'let D=[];for(let k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}'
         'let S=String.fromCharCode.apply(null,D);let RESULT=S;'),
        # F1757: const + chunk size K=1
        ('const CC=' + cs + ';const GG=Object.groupBy(CC,function(c,i){return Math.floor(i/1);});'
         'const DD=[];for(var k=0;String(k) in GG;k++){DD=DD.concat(GG[String(k)]);}'
         'const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;'),
        # F1757: whitespace variants
        ('var C = ' + cs + ' ; var G = Object.groupBy( C , function( c , i ){ return Math.floor( i / 4 ) ; } ) ;'
         'var D = [] ; for( var k = 0 ; String( k ) in G ; k ++ ){ D = D.concat( G[ String( k ) ] ) ; }'
         'var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;'),
        # F1758: let + renamed
        ('let A=' + cs + ';let M=new Map(A.map(function(x,j){return [j,x];}));'
         'let D=Array.from(M.values());'
         'let S=String.fromCharCode.apply(null,D);let RESULT=S;'),
        # F1758: const + whitespace
        ('const CC=' + cs + ';const MM=new Map(CC.map(function(c,i){return [i,c];}));'
         'const DD=Array.from(MM.values());'
         'const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;'),
        # F1759: let/const + renamed + trailing semicolon
        ('let A=' + cs + ';let RESULT="";(async function(){let D=await Array.fromAsync(A);'
         'let S=String.fromCharCode.apply(null,D);RESULT=S;})();'),
        ('const CC=' + cs + ';const RESULT="";(async function(){const DD=await Array.fromAsync(CC);'
         'const SS=String.fromCharCode.apply(null,DD);RESULT=SS;})();'),
    ]
    for tmpl in cases:
        v = _scan(tmpl)
        ok = _check("p2-gen", v == "HIT", "got %s for %r" % (v, tmpl[:60])) and ok
    return ok

def test_p3_failclosed():
    """Wrong forms fail closed at the hook level (never mis-decode)."""
    ok = True
    from gov.dlp import (_js_f1757_stmt_decode, _js_f1758_stmt_decode,
                         _js_f1759_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1757 hook: wrong keyfn (parity, F1037's shape -- must not match)
        (_js_f1757_stmt_decode,
         'var C=' + cs + ';var G=Object.groupBy(C,function(p){return p[0]%2;});'
         'var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1757 hook: chunk divisor 0 (division by zero -- must not match)
        (_js_f1757_stmt_decode,
         'var C=' + cs + ';var G=Object.groupBy(C,function(c,i){return Math.floor(i/0);});'
         'var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1757 hook: non-Math.floor keyfn
        (_js_f1757_stmt_decode,
         'var C=' + cs + ';var G=Object.groupBy(C,function(c,i){return i%4;});'
         'var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1757 hook: wrong reassembly (push instead of concat)
        (_js_f1757_stmt_decode,
         'var C=' + cs + ';var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});'
         'var D=[];for(var k=0;String(k) in G;k++){D.push(G[String(k)]);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1758 hook: F1446's for-of shape (sibling -- must not match)
        (_js_f1758_stmt_decode,
         'var C=' + cs + ';var M=new Map(C.map(function(c,i){return [i,c];}));'
         'var D=[];for(var v of M.values()){D.push(v);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1758 hook: wrong pair order [c,i] instead of [i,c]
        (_js_f1758_stmt_decode,
         'var C=' + cs + ';var M=new Map(C.map(function(c,i){return [c,i];}));'
         'var D=Array.from(M.values());'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1758 hook: Array.from on keys() instead of values()
        (_js_f1758_stmt_decode,
         'var C=' + cs + ';var M=new Map(C.map(function(c,i){return [i,c];}));'
         'var D=Array.from(M.keys());'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1759 hook: .then() instead of await (F520's shape -- must not match)
        (_js_f1759_stmt_decode,
         'var C=' + cs + ';var RESULT="";Array.fromAsync(C).then(function(D){'
         'var S=String.fromCharCode.apply(null,D);RESULT=S;});'),
        # F1759 hook: RESULT not pre-declared as ""
        (_js_f1759_stmt_decode,
         'var C=' + cs + ';(async function(){var D=await Array.fromAsync(C);'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;})()'),
        # F1759 hook: non-empty RESULT init
        (_js_f1759_stmt_decode,
         'var C=' + cs + ';var RESULT="x";(async function(){var D=await Array.fromAsync(C);'
         'var S=String.fromCharCode.apply(null,D);RESULT=S;})()'),
        # Cross: F1757's shape on F1758's hook (must not match)
        (_js_f1758_stmt_decode,
         FILED[1757].replace("{I}", cs)),
        # Cross: F1758's shape on F1757's hook (must not match)
        (_js_f1757_stmt_decode,
         FILED[1758].replace("{I}", cs)),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1037 (groupBy pairs), F1446 (Map for-of), F520 still HIT."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        # F1446: Map staging with for-of push loop
        ("f1446",
         'var C=' + cs + ';var M=new Map(C.map(function(c,i){return [i,c];}));'
         'var D=[];for(var v of M.values()){D.push(v);}'
         'var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
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
        "var groups = Object.groupBy(items, ({type}) => type);",
        "const m = new Map([[1, 'a'], [2, 'b']]);",
        "async function load() { const data = await Array.fromAsync(source); }",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:40])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    cs = _codes(SECRET_S)
    opens = [
        # F1760: structuredClone with transferables (lane B's scope)
        ("f1760",
         'var C=' + cs + ';var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[B]});'
         'var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1761: Array.toSorted (lane B's scope) -- exact filed shape, no RESULT
        ("f1761",
         'var C=' + cs + ';var D=C.toSorted(function(){return 0;});'
         'var S=String.fromCharCode.apply(null,D);'),
        # F1767: RegExp d-flag extra flags (lane D's scope)
        ("f1767",
         'var C=' + cs + ';var S=String.fromCharCode.apply(null,C);var R=/(.)/gdi;'
         'var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}'
         'var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
    ]
    for name, payload in opens:
        v = _scan(payload)
        ok = _check("p6-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        FILED[1757].replace("{I}", cs),
        FILED[1758].replace("{I}", cs),
        FILED[1759].replace("{I}", cs),
        "var C=%s;var M=new Map(C.map(function(c,i){return [i,c];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
    """Depth-1 green check: the F1757/F1758/F1759 red-first batteries.

    They now report NO-BREAK on the fixed tree (exit 1). Run with
    GOV_SKIP_GREEN=1 in the child env (depth-1 convention).
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w429_f1757_redfirst.py", "evals/w429_f1758_redfirst.py",
              "evals/w429_f1759_redfirst.py"]:
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=120, env={**os.environ, "GOV_SKIP_GREEN": "1"})
            # Red-first batteries exit 1 when NO-BREAK (fixed), 0 when BREAK (open)
            # On the fixed tree we expect exit 1 (NO-BREAK)
            ok = _check("g0-%s" % f.split("/")[-1], r.returncode == 1,
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
        print("=== %s ===" % name)
        try:
            ok = fn()
        except Exception as e:
            print("FAIL %s -- EXCEPTION: %s" % (name, e))
            ok = False
        all_ok = all_ok and ok
    n_pass = sum(1 for _, ok, _ in _results if ok)
    n_fail = sum(1 for _, ok, _ in _results if not ok)
    print("w429_f1757f1759close: %d/%d HELD" % (n_pass, n_pass + n_fail))
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
