#!/usr/bin/env python3
"""Wave-441 lane A close battery: F2078-F2086.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 173 -> 174 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged; pin 2143.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w441_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-20261012-abcdefgh"
SECRET_L = "xoxb-20261012-abcdefgh0123456789abcd"

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

# Filed shapes (from FINDINGS.md, attack round 108, first-filing 2026-10-12 22:56 UTC)
F2078_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.join.call([T],'');var RESULT=U;"
F2079_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.join.apply([T],['']);var RESULT=U;"
F2080_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(Array.prototype.join,[T],['']);var RESULT=U;"
F2081_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.concat.apply(T,['']);var RESULT=U;"
F2082_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new String(T).toString();var RESULT=U;"
F2083_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T?.toString();var RESULT=U;"
F2084_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T??'').toString();var RESULT=U;"
F2085_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(0,T).toString();var RESULT=U;"
F2086_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(()=>T)();var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 174."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f2078_stmt_decode", "_js_f2079_stmt_decode",
              "_js_f2080_stmt_decode", "_js_f2081_stmt_decode",
              "_js_f2082_stmt_decode", "_js_f2083_stmt_decode",
              "_js_f2084_stmt_decode", "_js_f2085_stmt_decode",
              "_js_f2086_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f2078_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 173 base + 1 new = 174
    m = re.search(r"def _decode_layer\(text\):", src)
    assert m, "no _decode_layer"
    body = src[m.start():]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = _check("p0-loopcount", len(loops) == 174,
                "%d loops (pin 174)" % len(loops)) and ok
    # re.compile count unchanged
    rc = src.count("re.compile(")
    ok = _check("p0-recompile", rc == 29, "%d (pin 29)" % rc) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    shapes = (
        ("f2078", F2078_FILED), ("f2079", F2079_FILED),
        ("f2080", F2080_FILED), ("f2081", F2081_FILED),
        ("f2082", F2082_FILED), ("f2083", F2083_FILED),
        ("f2084", F2084_FILED), ("f2085", F2085_FILED),
        ("f2086", F2086_FILED),
    )
    for name, tmpl in shapes:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const declarations, renamed identifiers."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f2078-let",
         "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Array.prototype.join.call([TT],'');let RESULT=UU;" % cs),
        ("f2079-const",
         "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=Array.prototype.join.apply([B],['']);const RESULT=Q;" % cs),
        ("f2080-let",
         "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Reflect.apply(Array.prototype.join,[TT],['']);let RESULT=UU;" % cs),
        ("f2081-const",
         "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=String.prototype.concat.apply(B,['']);const RESULT=Q;" % cs),
        ("f2082-let",
         "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=new String(TT).toString();let RESULT=UU;" % cs),
        ("f2083-const",
         "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B?.toString();const RESULT=Q;" % cs),
        ("f2084-let",
         "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(TT??'').toString();let RESULT=UU;" % cs),
        ("f2085-const",
         "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(0,B).toString();const RESULT=Q;" % cs),
        ("f2086-let",
         "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(()=>TT)();let RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed bounds: wrong shapes must MISS (never mis-decode)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # Wrong separator (non-empty) must not decode
        ("f2078-sep",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.join.call([T],',');var RESULT=U;" % cs),
        # Wrong receiver (not T)
        ("f2078-receiver",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.prototype.join.call([C],'');var RESULT=U;" % cs),
        # F2084 with non-empty fallback must not decode
        ("f2084-fallback",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T??'x').toString();var RESULT=U;" % cs),
        # F2085 with non-zero leading element must not decode
        ("f2085-leading",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(1,T).toString();var RESULT=U;" % cs),
        # F2086 with non-T body must not decode
        ("f2086-body",
         "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(()=>C)();var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: neighboring findings still decode (no regression)."""
    ok = True
    cs = _codes(SECRET_S)
    # F2068 (spread join-split-join) should still HIT
    p = ("var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var U=[...T].join('').split('').join('');var RESULT=U;" % cs)
    v = _scan(p)
    ok = _check("p4-f2068", v == "HIT", "got %s" % v) and ok
    # F2076 (map-join concat) should still HIT
    p = ("var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var U=C.map(function(c){return String.fromCharCode(c);}).join('').concat('');var RESULT=U;" % cs)
    v = _scan(p)
    ok = _check("p4-f2076", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text must MISS (no false positives)."""
    ok = True
    cases = [
        "the quick brown fox jumps over the lazy dog",
        "var x = Array.prototype.join.call([1,2,3], ',');",
        "function toString() { return 'hello'; }",
        "const t = data?.toString() ?? 'default';",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-honest%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 20 separate scans in reasonable time."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F2078_FILED.replace("{I}", cs)
    t0 = time.time()
    for i in range(20):
        v = _scan(payload)
        if v != "HIT":
            ok = _check("p6-perf-hit", False, "got %s on iter %d" % (v, i)) and ok
            break
    else:
        ok = _check("p6-perf-hit", True, "20/20 HIT") and ok
    dt = time.time() - t0
    ok = _check("p6-perf-time", dt < 120, "%.1fs for 20 scans" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK skipped (GOV_SKIP_GREEN=1)")
        return True
    import glob
    ok = True
    # Run the red-first batteries as green checks
    for pat in ("evals/w441_f2078_redfirst.py", "evals/w441_f2086_redfirst.py"):
        p = os.path.join(REPO_ROOT, pat)
        if os.path.exists(p):
            env = dict(os.environ)
            env["GOV_SKIP_GREEN"] = "1"
            # Use a fresh TMPDIR for the child
            td = tempfile.mkdtemp(prefix="w441_green_")
            env["TMPDIR"] = td
            r = subprocess.run([sys.executable, p], capture_output=True,
                               text=True, timeout=300, env=env, cwd=REPO_ROOT)
            out = (r.stdout or "") + (r.stderr or "")
            held = "HELD" in out
            ok = _check("green-%s" % os.path.basename(p), held,
                        out.strip().split("\n")[-1] if out.strip() else "no output") and ok
    return ok

def main():
    ok = True
    ok = test_p0_pins() and ok
    ok = test_p1_filed() and ok
    ok = test_p2_generalizations() and ok
    ok = test_p3_failclosed() and ok
    ok = test_p4_siblings() and ok
    ok = test_p5_honest() and ok
    ok = test_p6_perf() and ok
    ok = _green_check() and ok
    nhit = sum(1 for _, o, _ in _results if o)
    ntot = len(_results)
    print("CLOSE BATTERY: %d/%d HELD" % (nhit, ntot))
    for name, o, detail in _results:
        if not o:
            print("  FAIL %s: %s" % (name, detail))
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
