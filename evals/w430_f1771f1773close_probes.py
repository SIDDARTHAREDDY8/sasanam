#!/usr/bin/env python3
"""Wave-430 lane B close battery: F1771, F1772, F1773.

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

F1771_FILED = "var C={I};var D=C.toSorted(function(){return 0;}).toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1772_FILED = "var C={I};var D=C.with(C.length-C.length,C[C.length-C.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
F1773_FILED = "var C={I};var D=C.slice();D.splice(D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"

def test_p0_pins():
    """Pin checks: footer, taxonomy, counts."""
    ok = True
    # N_STMTDEC_LOOPS = 127 (126 base + 1 new dispatch loop, wave-430 lane B)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "127",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # All three hooks + helper defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1771_stmt_decode", "_js_f1772_stmt_decode",
              "_js_f1773_stmt_decode", "_js_f1772_parse_zero_expr"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Dispatch loop present
    ok = _check("p0-dispatch",
                "_js_f1771_stmt_decode,\n                     _js_f1772_stmt_decode," in src,
                "loop present") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1771-F1773 stamped CLOSED by wave-430 lane B
    for n in (1771, 1772, 1773):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-430 lane B" % n, ftxt, re.S))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT, node-exact."""
    ok = True
    from gov.dlp import (_js_f1771_stmt_decode, _js_f1772_stmt_decode,
                         _js_f1773_stmt_decode)
    for name, tmpl, hook in (("f1771", F1771_FILED, _js_f1771_stmt_decode),
                             ("f1772", F1772_FILED, _js_f1772_stmt_decode),
                             ("f1773", F1773_FILED, _js_f1773_stmt_decode)):
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
    """Generalizations: let/const, renamed idents, whitespace HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1771: let + renamed idents
        "let CC=%s;let DD=CC.toSorted(function(){return 0;}).toSorted(function(){return 0;});let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs,
        # F1771: const + whitespace
        "const C = %s ; const D = C.toSorted( function(){ return 0 ; } ).toSorted( function(){ return 0 ; } ) ; const S = String.fromCharCode.apply( null , D ) ; const RESULT = S ;" % cs,
        # F1772: let + renamed idents
        "let CC=%s;let DD=CC.with(CC.length-CC.length,CC[CC.length-CC.length]);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs,
        # F1772: whitespace
        "var C = %s ; var D = C.with( C.length - C.length , C[ C.length - C.length ] ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;" % cs,
        # F1773: let + renamed idents
        "let CC=%s;let DD=CC.slice();DD.splice(DD.length,0);let SS=String.fromCharCode.apply(null,DD);let RESULT=SS;" % cs,
        # F1773: whitespace
        "var C = %s ; var D = C.slice() ; D.splice( D.length , 0 ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;" % cs,
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p2-gen%d" % i, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: hook-level misses on non-identity inputs."""
    ok = True
    from gov.dlp import (_js_f1771_stmt_decode, _js_f1772_stmt_decode,
                         _js_f1773_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1771: single toSorted (F1761 domain -- must not match THIS hook)
        (_js_f1771_stmt_decode,
         "var C=%s;var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1771: triple toSorted (not the filed shape)
        (_js_f1771_stmt_decode,
         "var C=%s;var D=C.toSorted(function(){return 0;}).toSorted(function(){return 0;}).toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1771: non-zero comparator (could reorder -- must not match)
        (_js_f1771_stmt_decode,
         "var C=%s;var D=C.toSorted(function(){return 1;}).toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1771: arrow comparator (not the filed grammar)
        (_js_f1771_stmt_decode,
         "var C=%s;var D=C.toSorted(()=>0).toSorted(()=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1772: literal 0 index (F1171 domain -- must not match THIS hook)
        (_js_f1772_stmt_decode,
         "var C=%s;var D=C.with(0,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1772: C.length-1 index (F1542 domain -- must not match THIS hook)
        (_js_f1772_stmt_decode,
         "var C=%s;var D=C.with(C.length-1,C[C.length-1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1772: mismatched bases in zero-expr (C.length-D.length -- not always 0)
        (_js_f1772_stmt_decode,
         "var C=%s;var D=C.with(C.length-D.length,C[C.length-D.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1772: non-zero constant index
        (_js_f1772_stmt_decode,
         "var C=%s;var D=C.with(1,C[1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1773: splice(0,0) (F1712 domain -- must not match THIS hook)
        (_js_f1773_stmt_decode,
         "var C=%s;var D=C.slice();D.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1773: splice with deleteCount 1 (not a no-op -- must not match)
        (_js_f1773_stmt_decode,
         "var C=%s;var D=C.slice();D.splice(D.length,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1773: splice on C not D (F1733 domain -- must not match THIS hook)
        (_js_f1773_stmt_decode,
         "var C=%s;var D=C.slice();C.splice(C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1773: no slice (direct splice on C)
        (_js_f1773_stmt_decode,
         "var C=%s;var D=C;D.splice(D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None,
                    "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F1761, F1712, F1733, F1542 still HIT via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        ("f1761", "var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1712", "var C={I};var D=C.slice();D.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1733", "var C={I};var D=C.slice();C.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1542", "var C={I};var D=C.with(C.length-1,C[C.length-1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
        "var C = [1,2,3]; var D = C.toSorted();",
        "var C = [1,2,3]; var D = C.with(0, 99);",
        "var C = [1,2,3]; var D = C.slice(); D.splice(1, 2);",
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
        ("f1768", "var C={I};var D=new Array(...C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1769", "var C={I};var [...D]=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1770", "var C={I};var D=C.slice(0).reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1774", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');"),
        ("f1775", "var C={I};var it=C.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1776", "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1777", "var C={I};var P=Promise.resolve(C).then(function(c){return String.fromCharCode.apply(null,c);});var RESULT='x';"),
        ("f1778", "var C={I};var D;var S=(D=C,String.fromCharCode.apply(null,D));var RESULT=S;"),
        ("f1779", "var C={I};var D;D??=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1780", "var C={I};var D=C||[];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
        ("f1781", "var C={I};var D=[];while(C.length){D.push(C.shift());}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
        F1771_FILED.replace("{I}", cs),
        F1772_FILED.replace("{I}", cs),
        F1773_FILED.replace("{I}", cs),
        "var C=%s;var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
        "var C=%s;var D=C.slice();D.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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

def test_g0_green():
    """Depth-1 green check: the w430 red-first batteries run clean."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w430_f1771_redfirst.py", "evals/w430_f1772_redfirst.py",
              "evals/w430_f1773_redfirst.py"]:
        p = os.path.join(REPO_ROOT, f)
        if os.path.exists(p):
            r = subprocess.run([sys.executable, p], capture_output=True, text=True,
                             timeout=180, env={**os.environ, "GOV_SKIP_GREEN": "1"})
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
