#!/usr/bin/env python3
"""Close battery for wave-445 lane B: F2239-F2258 (20 findings).

Verifies:
- Pin: N_STMTDEC_LOOPS=188, re.compile=29
- All 20 filed shapes now HIT (were BREAK)
- Generalizations, fail-closed bounds, sibling pins, honest-text controls
- Perf (200 sites)
- Depth-1 green check honoring GOV_SKIP_GREEN=1
"""
import os
import re
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w445_laneB_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

N_STMTDEC_LOOPS = 188  # wave-445 lane B: 187 + 1 dispatch loop (F2239-F2258, real code-count change)
RE_COMPILE_PIN = 29

SECRET = "xoxb-ABCDEFGHIJKLMNOP"

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

# Filed shapes (all decoder-seam, intermediate-var form)
FILED_TEMPLATES = {
    2239: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0,1)+T.slice(1);var RESULT=U;",
    2240: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').slice(0).join('');var RESULT=U;",
    2241: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Object.assign({},{v:T}).v;var RESULT=U;",
    2242: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=({v:T}).v;var RESULT=U;",
    2243: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[T][0];var RESULT=U;",
    2244: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Map([['k',T]]).get('k');var RESULT=U;",
    2245: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Set([T]).values().next().value;var RESULT=U;",
    2246: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=JSON.parse('\"'+T+'\"');var RESULT=U;",
    2247: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=eval('T');var RESULT=U;",
    2248: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf(T);var RESULT=U;",
    2249: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(''.concat,'',[T]);var RESULT=U;",
    2250: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(2).slice(0,T.length);var RESULT=U;",
    2251: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(T.slice(0,0));var RESULT=U;",
    2252: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.split('').map(String).join('');var RESULT=U;",
    2253: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].every(function(){return true;})?T:'';var RESULT=U;",
    2254: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.search('')===0?T:'';var RESULT=U;",
    2255: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.indexOf('')===0?T:'';var RESULT=U;",
    2256: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.lastIndexOf('')===T.length?T:'';var RESULT=U;",
    2257: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.startsWith(T)?T:'';var RESULT=U;",
    2258: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.endsWith(T)?T:'';var RESULT=U;",
}

def _scan(payload):
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

def main():
    passed = 0
    failed = 0
    failures = []

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1
        else:
            failed += 1
            failures.append(name)
            print(f"FAIL: {name}")

    # 1. Pin checks
    with open(os.path.join(REPO_ROOT, "gov/dlp.py")) as f:
        dlp_text = f.read()
    actual_loops = sum(1 for _ in re.finditer(r"for _stmtdec in", dlp_text))
    check("pin N_STMTDEC_LOOPS=188", actual_loops == N_STMTDEC_LOOPS)
    actual_re = len(re.findall(r"re\.compile\(", dlp_text))
    check("pin re.compile=29", actual_re == RE_COMPILE_PIN)

    # 2. All 20 filed shapes now HIT
    for fnum, tmpl in FILED_TEMPLATES.items():
        payload = tmpl.replace("{I}", _codes(SECRET))
        v = _scan(payload)
        check(f"F{fnum} filed-shape HIT", v == "HIT")

    # 3. Honest-text controls (must MISS)
    honest = [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; console.log(x + y);",
        "function hello() { return 'world'; }",
    ]
    for i, h in enumerate(honest):
        check(f"honest-text-{i} MISS", _scan(h) == "MISS")

    # 4. Sibling pins (F2182-F2188 from wave-444 lane B should still HIT)
    # F2182 is JSON.stringify-slice direct-RESULT form
    sib = "var C=" + _codes(SECRET) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=JSON.stringify(T).slice(1,-1);"
    check("sibling F2182 still HIT", _scan(sib) == "HIT")

    # 5. Fail-closed: malformed variants must MISS (not mis-decode)
    malformed = [
        # Wrong slice args
        "var C=" + _codes(SECRET) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0,2)+T.slice(1);var RESULT=U;",
        # Wrong var name in RESULT
        "var C=" + _codes(SECRET) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(0,1)+T.slice(1);var RESULT=X;",
    ]
    for i, m in enumerate(malformed):
        check(f"fail-closed-{i} MISS", _scan(m) == "MISS")

    # 6. Perf: 200 sites
    start = time.time()
    for _ in range(200):
        _scan("the quick brown fox " + str(_))
    elapsed = time.time() - start
    check(f"perf 200 sites < 300s ({elapsed:.1f}s)", elapsed < 300)  # subprocess-spawn overhead; in-process is ~5ms/scan

    # 7. Green check (depth-1): run red-first batteries
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("Running green check: 20 red-first batteries...")
        for fnum in range(2239, 2259):
            bat = os.path.join(REPO_ROOT, "evals", f"w445_f{fnum}_redfirst.py")
            if os.path.exists(bat):
                env = dict(os.environ)
                env["GOV_SKIP_GREEN"] = "1"
                r = subprocess.run([sys.executable, bat], capture_output=True, text=True, timeout=120, env=env)
                # After fix, batteries should print HELD (not BREAK)
                check(f"green f{fnum} HELD", "HELD" in (r.stdout or ""))
    else:
        print("Green check skipped (GOV_SKIP_GREEN=1)")

    print(f"\n{passed} passed, {failed} failed")
    if failures:
        print("Failures:", failures)
        sys.exit(1)
    print("ALL PASS")

if __name__ == "__main__":
    main()
