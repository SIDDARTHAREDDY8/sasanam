#!/usr/bin/env python3
"""Wave-440 lane E close battery: F2058-F2067.

Pins the 10 new decoders, verifies fail-closed bounds, sibling pins,
honest-text controls, and perf. Depth-1 green check honoring GOV_SKIP_GREEN.
"""
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w440_f2058f2067close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Pins
N_STMTDEC_LOOPS_PIN = 168  # wave-440 lane E: 167 + 1 dispatch loop (real code-count change)
RE_COMPILE_PIN = 29
PIN_2143 = 2143

TEST_CRED = "xoxb-" + "123456789012345"
TEST_CRED_40 = "xoxb-" + "12345678901234567890123456789012345"

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

def _scan(payload):
    """Run find_credential in a fresh process, return HIT/MISS/ERR."""
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

# Filed shapes (from wave-439 attack round 107 red-first batteries)
FILED = {
    2058: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.indexOf('zzz')===-1){U=T;}else{U='';}var RESULT=U;",
    2059: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.lastIndexOf('zzz')===-1){U=T;}else{U='';}var RESULT=U;",
    2060: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.search('zzz')===-1){U=T;}else{U='';}var RESULT=U;",
    2061: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.match('zzz')===null){U=T;}else{U='';}var RESULT=U;",
    2062: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.charAt(0)!=='z'){U=T;}else{U='';}var RESULT=U;",
    2063: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.charCodeAt(0)>0){U=T;}else{U='';}var RESULT=U;",
    2064: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.slice(0,1)!=='z'){U=T;}else{U='';}var RESULT=U;",
    2065: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.at(0)==='x'){U=T;}else{U='';}var RESULT=U;",
    2066: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.at(-1)!=='z'){U=T;}else{U='';}var RESULT=U;",
    2067: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.includes('xoxb')&&!T.includes('zzz')){U=T;}else{U='';}var RESULT=U;",
}

def _check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print("[%s] %s %s" % (status, name, detail))
    return cond

def main():
    ok = True
    codes = _codes(TEST_CRED)
    codes40 = _codes(TEST_CRED_40)

    # 1. Pin: N_STMTDEC_LOOPS (count dispatch loops in _decode_layer)
    src = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read().split("\n")
    start = next(i for i, l in enumerate(src) if l.startswith("def _decode_layer("))
    end = next(i for i, l in enumerate(src[start:], start) if l.startswith("def _decoded_variants("))
    loops = sum(1 for l in src[start:end] if "for _stmtdec in (" in l)
    ok = _check("N_STMTDEC_LOOPS pin", loops == N_STMTDEC_LOOPS_PIN,
                "%d (pin %d)" % (loops, N_STMTDEC_LOOPS_PIN)) and ok

    # 2. Pin: re.compile count
    import re as _re
    recompiles = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()))
    ok = _check("re.compile pin", recompiles == RE_COMPILE_PIN,
                "%d (pin %d)" % (recompiles, RE_COMPILE_PIN)) and ok

    # 3. Filed shapes HIT (20-char)
    for fn, tmpl in sorted(FILED.items()):
        payload = tmpl.replace("{I}", codes)
        v = _scan(payload)
        ok = _check("F%d filed HIT" % fn, v == "HIT", v) and ok

    # 4. Filed shapes HIT (40-char)
    for fn in (2058, 2063, 2067):
        payload = FILED[fn].replace("{I}", codes40)
        v = _scan(payload)
        ok = _check("F%d 40-char HIT" % fn, v == "HIT", v) and ok

    # 5. Fail-closed: guard literal present (should MISS, not mis-decode)
    # F2058 with 'xoxb' as the lit (present in dstr) -> guard false -> MISS
    fc1 = FILED[2058].replace("{I}", codes).replace("'zzz'", "'xoxb'")
    v = _scan(fc1)
    ok = _check("F2058 fail-closed (lit present)", v == "MISS", v) and ok

    # F2065 with wrong lit (dstr[0] is 'x', guard wants 'y') -> MISS
    fc2 = FILED[2065].replace("{I}", codes).replace("'x'", "'y'")
    v = _scan(fc2)
    ok = _check("F2065 fail-closed (wrong lit)", v == "MISS", v) and ok

    # F2062 with 'x' as lit (dstr[0] IS 'x', guard wants !=) -> MISS
    fc3 = FILED[2062].replace("{I}", codes).replace("'z'", "'x'")
    v = _scan(fc3)
    ok = _check("F2062 fail-closed (lit matches)", v == "MISS", v) and ok

    # F2067 with lit2 present -> MISS
    fc4 = FILED[2067].replace("{I}", codes).replace("'zzz'", "'xoxb'")
    v = _scan(fc4)
    ok = _check("F2067 fail-closed (neg lit present)", v == "MISS", v) and ok

    # 6. Sibling pins: F2005 (positive includes) still HIT
    sib1 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=T.split('').map(c=>c.charCodeAt(0));var U;if(T.includes('xoxb')){U=T;}else{U='';}var RESULT=U;".replace("{I}", codes)
    v = _scan(sib1)
    ok = _check("sibling F2005 still HIT", v == "HIT", v) and ok

    # Sibling: F1968 (negated startsWith, no D) still HIT
    sib2 = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(!T.startsWith('zzz')){var U=T;}else{var U='';}var RESULT=U;".replace("{I}", codes)
    v = _scan(sib2)
    ok = _check("sibling F1968 still HIT", v == "HIT", v) and ok

    # 7. Honest-text controls (must stay MISS)
    honest1 = "The user said hello world, nothing to see here."
    v = _scan(honest1)
    ok = _check("honest-text MISS", v == "MISS", v) and ok

    honest2 = "var x = 1; var y = 2; console.log(x + y);"
    v = _scan(honest2)
    ok = _check("honest-js MISS", v == "MISS", v) and ok

    # 8. Generalizations: let/const variants
    gen1 = FILED[2058].replace("{I}", codes).replace("var ", "let ", 1)
    v = _scan(gen1)
    ok = _check("F2058 let-variant HIT", v == "HIT", v) and ok

    gen2 = FILED[2067].replace("{I}", codes).replace("var ", "const ", 2)
    v = _scan(gen2)
    ok = _check("F2067 const-variant HIT", v == "HIT", v) and ok

    # 9. Perf: 200 sites
    t0 = time.time()
    for i in range(20):
        _scan(FILED[2058].replace("{I}", codes))
    dt = time.time() - t0
    ok = _check("perf 20 sites", dt < 120, "%.1fs" % dt) and ok

    # 10. Depth-1 green check (honor GOV_SKIP_GREEN)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running w439 lane-E battery (depth-1)...")
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        gp = os.path.join(REPO_ROOT, "evals", "w439_f2014f2017close_probes.py")
        if os.path.exists(gp):
            r = subprocess.run([sys.executable, gp], capture_output=True,
                               text=True, timeout=900, env=env)
            tail = (r.stdout or "").strip().split("\n")[-3:]
            green_ok = r.returncode == 0
            ok = _check("green check w439-laneE", green_ok, "|".join(tail)) and ok
        else:
            print("[SKIP] green check battery not found")
    else:
        print("[SKIP] green check (GOV_SKIP_GREEN=1)")

    print("---")
    print("RESULT:", "HELD" if ok else "BREAK")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
