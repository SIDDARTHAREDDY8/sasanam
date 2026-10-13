#!/usr/bin/env python3
"""Close battery for wave-446 lane B: F2325-F2342 (18 findings).

Verifies:
- Pin: N_STMTDEC_LOOPS=190, re.compile=29
- All 18 filed shapes now HIT (were BREAK), on 20-char and 40-char secrets
- Generalizations (renamed vars, let/const, repeat counts)
- Fail-closed bounds (malformed / non-identity variants MISS, never mis-decode)
- Sibling pins (F2258, F2249, F2213 still HIT)
- Honest-text controls MISS
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
_TMPD = tempfile.mkdtemp(prefix="w446_laneB_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

N_STMTDEC_LOOPS = 190  # wave-446 lane B: 189 + 1 dispatch loop (F2325-F2342, real code-count change)
RE_COMPILE_PIN = 29

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "a" * 35


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


# Filed shapes (all decoder-seam, intermediate-var form) -- byte-identical to
# the wave-445 attack round 113 red-first batteries.
FILED_TEMPLATES = {
    2325: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=escape(T);var RESULT=U;",
    2326: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.slice,T,[0]);var RESULT=U;",
    2327: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String.prototype.concat,T,[]);var RESULT=U;",
    2328: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');G=T;var U=Function('return G')();var RESULT=U;",
    2329: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');G=T;var U=(0,eval)('G');var RESULT=U;",
    2330: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(3).slice(0,T.length);var RESULT=U;",
    2331: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.indexOf(T[0]));var RESULT=U;",
    2332: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(T.length-T.length);var RESULT=U;",
    2333: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.lastIndexOf(T));var RESULT=U;",
    2334: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substring(T.search(''),T.length);var RESULT=U;",
    2335: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0,undefined);var RESULT=U;",
    2336: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Set([T]).has(T)?T:'';var RESULT=U;",
    2337: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.includes(T)?T:'';var RESULT=U;",
    2338: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T===T?T:'';var RESULT=U;",
    2339: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=typeof T==='string'?T:'';var RESULT=U;",
    2340: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.length>0?T:'';var RESULT=U;",
    2341: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.trim.call(T);var RESULT=U;",
    2342: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.replace.call(T,/z/,'');var RESULT=U;",
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
    check("pin N_STMTDEC_LOOPS=190", actual_loops == N_STMTDEC_LOOPS)
    actual_re = len(re.findall(r"re\.compile\(", dlp_text))
    check("pin re.compile=29", actual_re == RE_COMPILE_PIN)
    # All 18 decoder functions present and registered in the new loop
    for fnum in range(2325, 2343):
        check(f"fn _js_f{fnum}_stmt_decode defined",
              f"def _js_f{fnum}_stmt_decode(text):" in dlp_text)
        check(f"fn _js_f{fnum}_stmt_decode in dispatch",
              f"_js_f{fnum}_stmt_decode," in dlp_text or f"_js_f{fnum}_stmt_decode):" in dlp_text)

    # 2. All 18 filed shapes now HIT (20-char and 40-char secrets)
    for fnum, tmpl in FILED_TEMPLATES.items():
        v20 = _scan(tmpl.replace("{I}", _codes(SECRET20)))
        v40 = _scan(tmpl.replace("{I}", _codes(SECRET40)))
        check(f"F{fnum} filed-shape HIT (20c)", v20 == "HIT")
        check(f"F{fnum} filed-shape HIT (40c)", v40 == "HIT")

    # 3. Generalizations (renamed vars, let/const, variant counts)
    c20 = _codes(SECRET20)
    gen = [
        # renamed vars + let/const (F2325 escape)
        ("gen-2325-renamed",
         "let A=" + c20 + ";const B=A.map(function(c){return String.fromCharCode(c);}).join('');var D=escape(B);let RESULT=D;",
         "HIT"),
        # repeat(5) instead of repeat(3) (F2330)
        ("gen-2330-repeat5",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(5).slice(0,T.length);var RESULT=U;",
         "HIT"),
        # renamed ternary (F2338)
        ("gen-2338-renamed",
         "var C=" + c20 + ";var Q=C.map(function(c){return String.fromCharCode(c);}).join('');var W=Q===Q?Q:'';var RESULT=W;",
         "HIT"),
        # renamed substr-lendiff (F2332)
        ("gen-2332-renamed",
         "var C=" + c20 + ";var Q=C.map(function(c){return String.fromCharCode(c);}).join('');var W=Q.substr(Q.length-Q.length);var RESULT=W;",
         "HIT"),
        # Reflect.apply with whitespace (F2326)
        ("gen-2326-ws",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply( T.slice , T , [ 0 ] );var RESULT=U;",
         "HIT"),
        # const RESULT form (F2341)
        ("gen-2341-const",
         "const C=" + c20 + ";const T=C.map(function(c){return String.fromCharCode(c);}).join('');const U=String.prototype.trim.call(T);const RESULT=U;",
         "HIT"),
        # renamed typeof ternary (F2339; sentinel is name-free)
        ("gen-2339-renamed",
         "var C=" + c20 + ";var Q=C.map(function(c){return String.fromCharCode(c);}).join('');var W=typeof Q==='string'?Q:'';var RESULT=W;",
         "HIT"),
    ]
    for name, payload, want in gen:
        check(name + " " + want, _scan(payload) == want)

    # 4. Honest-text controls (must MISS)
    honest = [
        "the quick brown fox jumps over the lazy dog",
        "var x = 1; var y = 2; console.log(x + y);",
        "function hello() { return 'world'; }",
        "var s = escape('hello world');",
        "var ok = typeof x === 'string' ? x : '';",
        "var t = '  padded  '; var u = t.trim();",
    ]
    for i, h in enumerate(honest):
        check(f"honest-text-{i} MISS", _scan(h) == "MISS")

    # 5. Sibling pins (earlier closures still HIT)
    sib = [
        # F2258 endswith-self-ternary (wave-445 lane B)
        ("sib-F2258",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.endsWith(T)?T:'';var RESULT=U;"),
        # F2249 Reflect concat (wave-445 lane B)
        ("sib-F2249",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(''.concat,'',[T]);var RESULT=U;"),
        # F2213 trim (wave-445 lane A)
        ("sib-F2213",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trim();var RESULT=U;"),
        # F2156 direct-RESULT systematic (wave-444 lane A)
        ("sib-F2156",
         "var C=" + c20 + ";var RESULT=C.map(function(c){return String.fromCharCode(c);}).join('');"),
    ]
    for name, payload in sib:
        check(name + " still HIT", _scan(payload) == "HIT")

    # 6. Fail-closed: malformed / non-identity variants must MISS (never mis-decode)
    cz = _codes("xoxb-" + "z" * 15)   # contains 'z'
    cpct = _codes("xoxb-" + "%" * 15)  # escapable char
    csp = _codes(" " + "xoxb-" + "a" * 14)  # leading space
    malformed = [
        # F2325: escapable char -> escape() would transform, fail closed
        ("fc-2325-escapable",
         "var C=" + cpct + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=escape(T);var RESULT=U;"),
        # F2328: body not `return <alias>`
        ("fc-2328-body",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');G=T;var U=Function('return X')();var RESULT=U;"),
        # F2329: eval arg not the alias name
        ("fc-2329-arg",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');G=T;var U=(0,eval)('Y');var RESULT=U;"),
        # F2330: repeat(0) is not identity
        ("fc-2330-repeat0",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(0).slice(0,T.length);var RESULT=U;"),
        # F2331: indexOf(T[1]) not provably 0
        ("fc-2331-idx1",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.indexOf(T[1]));var RESULT=U;"),
        # F2335: substr(0,0) is empty, not identity
        ("fc-2335-len0",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.substr(0,0);var RESULT=U;"),
        # F2336: has(X) not provably true
        ("fc-2336-hasX",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=new Set([T]).has(X)?T:'';var RESULT=U;"),
        # F2341: trimmable leading whitespace -> fail closed
        ("fc-2341-ws",
         "var C=" + csp + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.trim.call(T);var RESULT=U;"),
        # F2342: 'z' present -> replace would transform, fail closed
        ("fc-2342-zpresent",
         "var C=" + cz + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.replace.call(T,/z/,'');var RESULT=U;"),
        # F2326: slice arg not 0
        ("fc-2326-arg1",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.slice,T,[1]);var RESULT=U;"),
        # F2330: repeat past node's RangeError boundary (4096c x N=1114111 > 2^28)
        ("fc-2330-rangeerror",
         "var C=" + _codes("xoxb-" + "b" * 4091) + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(1114111).slice(0,T.length);var RESULT=U;"),
        # wrong RESULT binding
        ("fc-result-name",
         "var C=" + c20 + ";var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=escape(T);var RESULT=X;"),
        # junk still quiet
        ("fc-junk", "the quick brown fox jumps over the lazy dog"),
    ]
    for name, payload in malformed:
        check(name + " MISS", _scan(payload) == "MISS")

    # 7. Perf: 200 sites
    start = time.time()
    for i in range(200):
        _scan("the quick brown fox " + str(i))
    elapsed = time.time() - start
    check(f"perf 200 sites < 300s ({elapsed:.1f}s)", elapsed < 300)

    # 8. Green check (depth-1): run the 18 attack red-first batteries, expect HELD now
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("Running green check: 18 red-first batteries...")
        for fnum in range(2325, 2343):
            bat = os.path.join(REPO_ROOT, "evals", f"w445_f{fnum}_redfirst.py")
            if os.path.exists(bat):
                env = dict(os.environ)
                env["GOV_SKIP_GREEN"] = "1"
                r = subprocess.run([sys.executable, bat], capture_output=True, text=True, timeout=120, env=env)
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
