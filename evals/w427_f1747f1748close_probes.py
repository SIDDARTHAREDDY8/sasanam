#!/usr/bin/env python3
"""Wave-427 lane D close battery: F1747, F1748.

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
    # N_STMTDEC_LOOPS = 116 (115 base + 1 new dispatch loop, wave-427 lane D)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-loops", m and m.group(1) == "116",
                "N_STMTDEC_LOOPS=%s" % (m.group(1) if m else "missing")) and ok
    # Both hooks + the zero-expr helper defined
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1747_stmt_decode", "_js_f1748_stmt_decode",
              "_js_f1747f1748_parse_zero_expr"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    # Pin 2143 (in FINDINGS.md)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    # re.compile count = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Footer: F1747-F1748 stamped CLOSED by wave-427 lane D
    for n in (1747, 1748):
        c = bool(re.search(r"\(F%d filed .*?\[CLOSED 2026-10-12 wave-427 lane D" % n, ftxt))
        ok = _check("p0-f%d-closed" % n, c, "stamped" if c else "missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    shapes = [
        ("f1747", 'var C={I};var D=C.slice();D.copyWithin(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1748", 'var C={I};var D=C.slice();D.fill(0,C.length-C.length,C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, whitespace, zero-expr
    variants, literal-zero fill/copyWithin forms HIT."""
    ok = True
    cases = [
        # let/const + renamed idents
        'let C={I};let D=C.slice();D.copyWithin(C.length-C.length,0);let S=String.fromCharCode.apply(null,D);let RESULT=S;',
        'const CC={I};const DD=CC.slice();DD.fill(0,CC.length-CC.length,CC.length-CC.length);const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;',
        # whitespace variants
        'var C = {I} ; var D = C.slice() ; D.copyWithin( C.length - C.length , 0 ) ; var S = String.fromCharCode.apply( null , D ) ; var RESULT = S ;',
        'var C={I};var D=C.slice();D.fill(0, C.length - C.length , C.length - C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        # zero-expr on a different ident (self-subtraction still 0)
        'var C={I};var D=C.slice();D.copyWithin(D.length-D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        # literal-zero args (node-exact identity / empty range)
        'var C={I};var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        'var C={I};var D=C.slice();D.fill(0,0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        # nonzero literal fill value with empty range (still a no-op)
        'var C={I};var D=C.slice();D.fill(5,C.length-C.length,C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
        'var C={I};var D=C.slice();D.fill(-3,0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
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
    from gov.dlp import (_js_f1747_stmt_decode, _js_f1748_stmt_decode)
    cs = _codes(SECRET_S)
    bad = [
        # F1747: non-identity target (real mutation -- must not match)
        (_js_f1747_stmt_decode,
         'var C=%s;var D=C.slice();D.copyWithin(1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1747: 3-arg form (partial copy -- not identity)
        (_js_f1747_stmt_decode,
         'var C=%s;var D=C.slice();D.copyWithin(0,0,5);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1747: differing idents in the subtraction (not provably zero)
        (_js_f1747_stmt_decode,
         'var C=%s;var D=C.slice();D.copyWithin(C.length-D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1747: non-zero computed target
        (_js_f1747_stmt_decode,
         'var C=%s;var D=C.slice();D.copyWithin(C.length-1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1747: `00` / `0x0` zero lookalikes
        (_js_f1747_stmt_decode,
         'var C=%s;var D=C.slice();D.copyWithin(00,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1748: non-empty range (real fill -- must not match)
        (_js_f1748_stmt_decode,
         'var C=%s;var D=C.slice();D.fill(9,0,2);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1748: F1745's per-index shape (sibling -- our hook must not match)
        (_js_f1748_stmt_decode,
         'var C=%s;var D=C.slice();D.fill(D[i],i,i+1);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1748: 2-arg fill (fills to end -- not a no-op)
        (_js_f1748_stmt_decode,
         'var C=%s;var D=C.slice();D.fill(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1748: non-zero start
        (_js_f1748_stmt_decode,
         'var C=%s;var D=C.slice();D.fill(0,1,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
        # F1748: string fill value (outside the admitted int-literal domain)
        (_js_f1748_stmt_decode,
         'var C=%s;var D=C.slice();D.fill("x",0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;' % cs),
    ]
    for hook, payload in bad:
        try:
            r = hook(payload)
        except Exception:
            r = "EXC"
        ok = _check("p3-failclosed", r is None, "%s -> %s" % (hook.__name__, "None" if r is None else "MATCHED")) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: F820 (IIFE copyWithin), F1733 (slice/splice) still HIT
    via their own hooks."""
    ok = True
    cs = _codes(SECRET_S)
    sibs = [
        ("f820", "(function(){var a=['xoxb-0123','z','456789abcdef'];a.copyWithin(1,0,1);return a[0]+a[2];})()"),
        ("f1733", 'var C={I};var D=C.slice();C.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1712", 'var C={I};var D=C.slice();D.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
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
        "var C=[1,2,3];var D=C.slice();D.copyWithin(0,0);var S=D.join(',');",
    ]:
        v = _scan(junk)
        ok = _check("p5-quiet", v == "MISS", "got %s for %r" % (v, junk[:30])) and ok
    return ok

def test_p6_other_opens():
    """Other open findings still MISS (not accidentally closed)."""
    ok = True
    opens = [
        ("f1735", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length+(C.length-C.length),' ');var RESULT=T;"),
        ("f1736", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+(C.length-C.length),' ');var RESULT=T;"),
        ("f1737", 'var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;'),
        ("f1738", 'var C={I};var U=new Uint8Array(C.length);U.set(C,C.length-C.length);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;'),
        ("f1739", 'var C={I};var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;'),
        ("f1740", 'var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1741", 'var C={I};var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;'),
        ("f1742", 'var C={I};var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1743", 'var C={I};var n=C.length-C.length+1;var D=[C];var F=D.flat(n);var S=String.fromCharCode.apply(null,F);var RESULT=S;'),
        ("f1744", 'var C={I};var S=String.fromCharCode.apply(null,C);var n=C.length-C.length+1;var T=S.repeat(n);var RESULT=T;'),
        ("f1745", 'var C={I};var D=C.slice();for(var i=0;i<D.length;i++){D.fill(D[i],i,i+1);}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
        ("f1746", 'var C={I};var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ]
    for name, tmpl in opens:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        v = _scan(payload)
        ok = _check("p6-%s-open" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p7_perf():
    """Performance: 200 sites in reasonable time (in-process)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        "var C=%s;var D=C.slice();D.copyWithin(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
        "var C=%s;var D=C.slice();D.fill(0,C.length-C.length,C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
        "var C=%s;var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
        "var C=%s;var D=C.slice();D.fill(9,0,2);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
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
    """Depth-1 green check: the F1747/F1748 red-first batteries still run
    (they now report NO-BREAK on the fixed tree, exit 1)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("g0: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    for f in ["evals/w426_f1747_redfirst.py", "evals/w426_f1748_redfirst.py",
              "evals/w427_f1747_redfirst.py", "evals/w427_f1748_redfirst.py"]:
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
