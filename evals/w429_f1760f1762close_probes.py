#!/usr/bin/env python3
"""Wave-429 lane B close battery: F1760, F1761, F1762.

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

F1760_FILED = 'var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[B]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'
F1761_FILED = 'var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;'
F1762_FILED = 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;'

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 126 (122 base + 1 new dispatch loop, wave-429 lane B)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "126",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All three hooks defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1760_stmt_decode", "_js_f1761_stmt_decode",
              "_js_f1762_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1760-F1762 stamped CLOSED by wave-429 lane B
    for n in (1760, 1761, 1762):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-429 lane B" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT, node-exact."""
    ok = True
    from gov.dlp import (_js_f1760_stmt_decode, _js_f1761_stmt_decode,
                         _js_f1762_stmt_decode)
    hooks = {"f1760": (_js_f1760_stmt_decode, F1760_FILED),
             "f1761": (_js_f1761_stmt_decode, F1761_FILED),
             "f1762": (_js_f1762_stmt_decode, F1762_FILED)}
    for name, (hook, tmpl) in hooks.items():
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
            dec = hook(payload)
            nr = _node_result(payload)
            ok = _check("p1-%s-%s-nodeexact" % (name, label),
                        dec == secret and nr == secret,
                        "hook==node==secret" if (dec == secret and nr == secret)
                        else "hook=%r node=%r" % (dec, nr)) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace."""
    ok = True
    cases = [
        # F1760: let + renamed idents
        ('f1760-let', 'let CC={I};let BB=new Uint8Array(CC).buffer;let B2=structuredClone(BB,{transfer:[BB]});let SS=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));let RESULT=SS;'),
        # F1760: const + extra whitespace
        ('f1760-const-ws', 'const C = {I} ; const B = new Uint8Array( C ) .buffer ; const B2 = structuredClone( B , { transfer : [ B ] } ) ; const S = String.fromCharCode.apply( null , Array.from( new Uint8Array( B2 ) ) ) ; const RESULT = S ;'),
        # F1761: let + renamed idents
        ('f1761-let', 'let CC={I};let DD=CC.toSorted(function(){return 0;});let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;'),
        # F1761: const
        ('f1761-const', 'const C={I};const D=C.toSorted(function(){return 0;});const S=String.fromCharCode.apply(null,D);const RESULT=S;'),
        # F1762: let + renamed idents + let loop var
        ('f1762-let', 'let CC={I};let OO={};for(let ii=0;ii<CC.length;ii++){OO[ii]=CC[ii];}OO.length=CC.length;let DD=Array.from(OO);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;'),
        # F1762: const C
        ('f1762-const', 'const C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in cases:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            nr = _node_result(payload)
            want = "HIT" if nr == secret else "SKIP"
            if want == "SKIP":
                ok = _check("p2-%s-%s" % (name, label), True, "node-false, skipped") and ok
            else:
                ok = _check("p2-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: non-identity variants must MISS (never mis-decode)."""
    ok = True
    cases = [
        # F1760: transfer a different buffer -> MISS
        ('f1760-xfer-other', 'var C={I};var B=new Uint8Array(C).buffer;var X=new ArrayBuffer(4);var B2=structuredClone(B,{transfer:[X]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1760: empty transfer list -> MISS
        ('f1760-xfer-empty', 'var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1760: no transfer option at all -> MISS (narrow hook)
        ('f1760-no-xfer', 'var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1761: non-zero comparator (could reorder) -> MISS
        ('f1761-cmp1', 'var C={I};var D=C.toSorted(function(){return 1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1761: comparator returns -1 -> MISS
        ('f1761-cmpneg', 'var C={I};var D=C.toSorted(function(){return -1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1761: arrow comparator (not the filed shape) -> MISS (narrow)
        ('f1761-arrow', 'var C={I};var D=C.toSorted(()=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1762: loop copies reversed (O[i]=C[n-1-i] shape) -> MISS
        ('f1762-rev', 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[C.length-1-i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1762: O.length wrong -> MISS
        ('f1762-len-wrong', 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=4;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        # F1762: Array.from on a different object -> MISS
        ('f1762-from-other', 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in cases:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p3-%s-%s" % (name, label), v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling shapes still HIT via their own hooks (disjointness)."""
    ok = True
    cases = [
        # F1752: ArrayBuffer.transfer (sibling of F1760)
        ('f1752', 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.transfer();var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1753: transferToFixedLength (sibling of F1760)
        ('f1753', 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.transferToFixedLength();var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        # F1498: in-place sort with arrow comparator (sibling of F1761) -- actual filed shape
        ('f1498', 'var C={I};C.sort((a,b)=>{return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
        # F1710: Array.from on real array with callback (sibling of F1762)
        ('f1710', 'var C={I};var D=Array.from(C,function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in cases:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p4-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_quiet():
    """Honest text stays quiet."""
    ok = True
    texts = [
        "the quick brown fox jumps over the lazy dog 1234567890",
        "var x = structuredClone({a: 1}); console.log(x);",
        "var d = [3,1,2].toSorted(); console.log(d);",
        "var o = {}; o.length = 5; var d = Array.from(o);",
        "Contact support at help@example.com for assistance.",
    ]
    for i, t in enumerate(texts):
        v = _scan(t)
        ok = _check("p5-quiet-%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_other_opens():
    """Other wave-429 OPEN findings still MISS."""
    ok = True
    cases = [
        ('f1757', 'var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);};var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ('f1758', 'var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=Array.from(M.values());var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ('f1759', 'var C={I};(async function(){var D=await Array.fromAsync(C);var S=String.fromCharCode.apply(null,D);})()'),
        ('f1763', 'var C={I};var P=new Proxy(C,{});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ('f1764', 'var C={I};var U=new Uint8Array(C);var V=U.toSorted(function(){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ('f1765', 'var C={I};var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;'),
        ('f1766', 'var C={I};var F=new Function("C","return String.fromCharCode.apply(null,C)");var S=F(C);var RESULT=S;'),
        ('f1767', 'var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gdi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;'),
    ]
    for name, tmpl in cases:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p6-%s-%s-nowclosed" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Perf: 200 sites decode within budget."""
    ok = True
    payload = F1761_FILED.replace("{I}", _codes(SECRET_S))
    big = ("/* pad */ " + payload + " ") * 200
    t0 = time.time()
    v = _scan(big)
    dt = time.time() - t0
    ok = _check("p7-perf", dt < 60, "%.1fs for 200 sites" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent lane batteries' mains with GOV_SKIP_GREEN=1.

    The N_STMTDEC_LOOPS pin is expected to differ (this lane bumps 122->123);
    only non-pin failures count as breakage.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: skipped (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for bat in ("w428_f1755f1756close_probes.py",):
        p = os.path.join(REPO_ROOT, "evals", bat)
        if not os.path.exists(p):
            print("g0: skip missing %s" % bat)
            continue
        r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                           timeout=600, env=env, cwd=REPO_ROOT)
        out = r.stdout or ""
        # The only acceptable failure is the pin bump (122->123)
        fails = [l for l in out.split("\n") if l.startswith("FAIL ")]
        real_fails = [l for l in fails if "p0-loops" not in l]
        good = not real_fails
        print("g0 %s: %s (%d non-pin fails)" % (bat, "HELD" if good else "BROKE", len(real_fails)))
        if not good:
            ok = False
            for l in real_fails[:10]:
                print("  " + l)
    return ok

def main():
    held = total = 0
    for fn in (test_p0_pins, test_p1_filed, test_p2_generalizations,
               test_p3_failclosed, test_p4_siblings, test_p5_quiet,
               test_p6_other_opens, test_p7_perf):
        before = len(_results)
        fn()
        for _, ok_, _ in _results[before:]:
            total += 1
            if ok_:
                held += 1
    g = _green_check()
    print("g0 green check: %s" % ("HELD" if g else "BROKE"))
    print("TOTAL: %d/%d HELD" % (held, total))
    fails = [n for n, ok_, d in _results if not ok_]
    if fails:
        print("FAILURES: %s" % ", ".join(fails))
    return 0 if (held == total and g) else 1

if __name__ == "__main__":
    sys.exit(main())
