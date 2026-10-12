#!/usr/bin/env python3
"""Wave-439 lane E close battery: F2014-F2017.

Pins the closures. F2014: Array.of(...T).join(''); F2015: [...T].slice().join('');
F2016: statement-interaction composition (T+U in either order); F2017: F1920
astral-pad mis-decode fix (hook now requires one UTF-16 code unit).
All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 161 -> 162 (real code-count change: one new dispatch
loop for F2014-F2016); re.compile(29 in gov/dlp.py unchanged.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w439_close_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-aaaa-bbbb-ccccc"
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

# Filed shapes (from FINDINGS.md)
F2014_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.of(...T).join('');var RESULT=U;"
F2015_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].slice().join('');var RESULT=U;"
F2016_T_ASM = "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
F2016_U_ASM = "var U=String.fromCharCode.apply(null,C);"
F2017_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='\U0001F600'.concat(T).slice(1);var RESULT=U;"

def test_p0_pins():
    """Pin/footer pins."""
    ok = True
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    # New hooks present
    ok = _check("p0-hooks", "_js_f2014_stmt_decode" in src and
                "_js_f2015_stmt_decode" in src and
                "_js_f2016_stmt_decode" in src,
                "hooks missing") and ok
    # Dispatch loop present
    ok = _check("p0-dispatch", "for _stmtdec in (_js_f2014_stmt_decode," in src,
                "loop missing") and ok
    # N_STMTDEC_LOOPS count
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    ok = _check("p0-loopcount", len(loops) == 162,
                "%d loops (pin 162)" % len(loops)) and ok
    # re.compile count unchanged
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Pin 2143 (in footer)
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _check("p0-pin2143", "pin 2143" in footer.lower() or
                "Pin 2143" in footer, "pin") and ok
    # F1920 hook has the UTF-16 fix
    ok = _check("p0-f1920-fix", "ord(pad) > 0xFFFF" in src,
                "F1920 astral fix missing") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    filed = (
        ("f2014", F2014_FILED),
        ("f2015", F2015_FILED),
    )
    for name, tmpl in filed:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "%s got %s" % (name, v)) and ok
    # F2016: both orders
    for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
        ci = _codes(secret)
        t_then_u = "var C=%s;%s%svar RESULT=U;" % (ci, F2016_T_ASM, F2016_U_ASM)
        u_then_t = "var C=%s;%s%svar RESULT=T;" % (ci, F2016_U_ASM, F2016_T_ASM)
        for pname, p in (("t-then-u", t_then_u), ("u-then-t", u_then_t)):
            v = _scan(p)
            ok = _check("p1-f2016-%s-%s" % (pname, label), v == "HIT",
                        "f2016 %s got %s" % (pname, v)) and ok
    # F2017: astral pad must NOT hit (fail closed)
    for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
        payload = F2017_FILED.replace("{I}", _codes(secret))
        v = _scan(payload)
        ok = _check("p1-f2017-%s" % label, v == "MISS",
                    "f2017 astral should MISS, got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, whitespace variations."""
    ok = True
    for secret, label in ((SECRET_S, "short"),):
        ci = _codes(secret)
        # F2014 with let and extra whitespace
        p = "let C=%s; let T = C.map(function(c){return String.fromCharCode(c);}).join(''); let U = Array.of(...T).join(''); let RESULT = U;" % ci
        v = _scan(p)
        ok = _check("p2-f2014-let-ws", v == "HIT", "got %s" % v) and ok
        # F2015 with const
        p = "const C=%s;const T=C.map(function(c){return String.fromCharCode(c);}).join('');const U=[...T].slice().join('');const RESULT=U;" % ci
        v = _scan(p)
        ok = _check("p2-f2015-const", v == "HIT", "got %s" % v) and ok
        # F2016 with let
        t_asm = "let T=C.map(function(c){return String.fromCharCode(c);}).join('');"
        u_asm = "let U=String.fromCharCode.apply(null,C);"
        p = "let C=%s;%s%slet RESULT=U;" % (ci, t_asm, u_asm)
        v = _scan(p)
        ok = _check("p2-f2016-let", v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed bounds: wrong shapes must MISS."""
    ok = True
    ci = _codes(SECRET_S)
    # F2014: Array.of without spread must MISS
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.of(T).join('');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p3-f2014-no-spread", v == "MISS", "got %s" % v) and ok
    # F2014: Array.of with non-empty join sep must MISS
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.of(...T).join(',');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p3-f2014-join-sep", v == "MISS", "got %s" % v) and ok
    # F2015: slice with args must MISS
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].slice(0).join('');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p3-f2015-slice-args", v == "MISS", "got %s" % v) and ok
    # F2015: spread of wrong var must MISS
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...C].slice().join('');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p3-f2015-wrong-var", v == "MISS", "got %s" % v) and ok
    # F2016: single-shape controls (T-only/U-only HIT via their own hooks)
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=T;" % ci
    v = _scan(p)
    # T-only should HIT via the single-shape hook, not F2016
    ok = _check("p3-f2016-single", v == "HIT", "got %s" % v) and ok
    # F2016: RESULT bound to wrong var must MISS
    t_asm = "var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
    u_asm = "var U=String.fromCharCode.apply(null,C);"
    p = "var C=%s;%s%svar RESULT=T;" % (ci, t_asm, u_asm)
    v = _scan(p)
    ok = _check("p3-f2016-wrong-result", v == "MISS", "got %s" % v) and ok
    # F2017: BMP pad (single UTF-16 unit) must still HIT via F1920
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(1);var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p3-f1920-bmp-pad", v == "HIT", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: neighboring findings still work."""
    ok = True
    ci = _codes(SECRET_S)
    # F1971: Array.from with map fn (sibling, should HIT)
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T,function(c){return c;}).join('');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p4-f1971", v == "HIT", "got %s" % v) and ok
    # F1972: spread toString split-join (sibling, should HIT)
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].toString().split(',').join('');var RESULT=U;" % ci
    v = _scan(p)
    ok = _check("p4-f1972", v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in (
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; var z = x + y;",
        "Hello, world! This is a test.",
    ):
        v = _scan(txt)
        ok = _check("p5-honest", v == "MISS", "got %s for %r" % (v, txt[:30])) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time."""
    ok = True
    ci = _codes(SECRET_S)
    payload = F2014_FILED.replace("{I}", ci)
    # Build a text with 200 sites
    big = " ".join([payload] * 200)
    t0 = time.time()
    v = _scan(big)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "%.1fs" % dt) and ok
    return ok

def _green_check():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("GREENCHECK SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import glob
    ok = True
    # Run the wave-438 lane D battery (sibling) with green checks skipped
    candidates = sorted(glob.glob(os.path.join(REPO_ROOT, "evals",
                                                "w438_f1968f1975close_probes.py")))
    for bat in candidates:
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        r = subprocess.run([sys.executable, bat], capture_output=True,
                           text=True, timeout=600, env=env)
        passed = "FAIL" not in r.stdout and r.returncode == 0
        ok = _check("green-%s" % os.path.basename(bat), passed,
                    "rc=%d" % r.returncode) and ok
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
    print("\n=== RESULTS ===")
    nfail = 0
    for name, passed, detail in _results:
        status = "PASS" if passed else "FAIL"
        if not passed:
            nfail += 1
            print("%s %s: %s" % (status, name, detail))
    print("Total: %d checks, %d failures" % (len(_results), nfail))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
