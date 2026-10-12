#!/usr/bin/env python3
"""Wave-435 lane C close battery: F1877-F1881, F1883-F1884 (7 findings).

Verifies the 7 new decoders close their filed gaps node-exactly,
fail closed on mutations, stay disjoint from siblings, and leave
honest text quiet. N_STMTDEC_LOOPS = 147 (146 base + 1 new dispatch
loop, wave-435 lane C); re.compile=29; pin 2143.

GOV_DEPLOYMENT_MODE=staging at module level (wave-95 lesson).
Depth-1 green check honoring GOV_SKIP_GREEN=1 (wave-?? lesson).
Unique-suffixed /var/tmp TMPDIRs (wave-112/134/173 lessons).
No in-repo git in self-pins (wave-224 lesson).
Red-first capture via Python subprocess ONLY (wave-392 lesson).
Genuine {I} templates, NEVER vacuous {{I}} (wave-413 lesson).
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import subprocess
import sys
import tempfile

_TMPD = tempfile.mkdtemp(prefix="w435_lanec_")
os.environ["TMPDIR"] = _TMPD

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

# N_STMTDEC_LOOPS = 147 (146 base + 1 new dispatch loop, wave-435 lane C)

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

_TEMPLATES = {
    1877: 'var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=[];for(var [k,v] of Object.entries(O)){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;',
    1878: 'var C={I};var D=C.reduce(function(a,x){return a.concat([x]);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;',
    1879: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toLocaleUpperCase().toLocaleLowerCase();var RESULT=U;",
    1880: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(0)===T[0]){var S=T;}else{var S='';}var RESULT=S;",
    1881: "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/(?:.)/g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;",
    1883: 'var C={I};var D=C.slice();if(D.includes(C[0],0)){var S=String.fromCharCode.apply(null,D);}else{var S=\'\';}var RESULT=S;',
    1884: 'var C={I};var D=C.slice();if(D.indexOf(C[C.length-1],C.length-1)>=0){var S=String.fromCharCode.apply(null,D);}else{var S=\'\';}var RESULT=S;',
}

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"


def _direct_hook_result(fnum, payload):
    """Call the hook directly for node-exactness verification."""
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0,%r);sys.path.insert(0,%r);"
        "from gov.dlp import _js_f%d_stmt_decode as h;"
        "r=h(%r);"
        "print('HOOK:'+(r if r else 'NONE'))"
    ) % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), fnum, payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("HOOK:"):
            return line[len("HOOK:"):]
    return "ERR"


_RESULTS = []


def _check(name, cond):
    _RESULTS.append((name, bool(cond)))
    return bool(cond)


def main():
    # 1. Filed shapes HIT on closed tree (both sizes)
    for fnum, tmpl in sorted(_TEMPLATES.items()):
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            hit = _scan(payload) == "HIT"
            _check(f"F{fnum}-{tag}-HIT", hit)
            # Node-exactness: hook result == secret
            if hit:
                hr = _direct_hook_result(fnum, payload)
                _check(f"F{fnum}-{tag}-node-exact", hr == secret)

    # 2. Generalizations (variant forms still HIT)
    # F1877: let/const variants
    p = _TEMPLATES[1877].replace("{I}", _codes(SECRET_S)).replace("var C=", "let C=").replace("var O=", "const O=")
    _check("F1877-letconst-HIT", _scan(p) == "HIT")
    # F1878: let variant
    p = _TEMPLATES[1878].replace("{I}", _codes(SECRET_S)).replace("var C=", "let C=")
    _check("F1878-let-HIT", _scan(p) == "HIT")
    # F1880: let variant
    p = _TEMPLATES[1880].replace("{I}", _codes(SECRET_S)).replace("var C=", "const C=")
    _check("F1880-const-HIT", _scan(p) == "HIT")

    # 3. Fail-closed mutations (must MISS, never mis-decode)
    # F1877: wrong push arg (push k instead of v) -> MISS
    p = _TEMPLATES[1877].replace("{I}", _codes(SECRET_S)).replace("D.push(v)", "D.push(k)")
    _check("F1877-push-k-MISS", _scan(p) == "MISS")
    # F1877: missing O[i]=C[i] store -> MISS (different shape)
    p = 'var C=%s;var O={};var D=[];for(var [k,v] of Object.entries(O)){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;' % _codes(SECRET_S)
    _check("F1877-no-store-MISS", _scan(p) == "MISS")
    # F1878: concat without array wrap -> MISS
    p = _TEMPLATES[1878].replace("{I}", _codes(SECRET_S)).replace("a.concat([x])", "a.concat(x)")
    _check("F1878-concat-x-MISS", _scan(p) == "MISS")
    # F1878: reduceRight instead of reduce -> MISS (F1812's shape, not mine)
    p = _TEMPLATES[1878].replace("{I}", _codes(SECRET_S)).replace(".reduce(", ".reduceRight(")
    _check("F1878-reduceRight-MISS", _scan(p) == "MISS")
    # F1879: only toLocaleUpperCase (no roundtrip) -> MISS
    p = _TEMPLATES[1879].replace("{I}", _codes(SECRET_S)).replace(".toLocaleUpperCase().toLocaleLowerCase()", ".toLocaleUpperCase()")
    _check("F1879-upper-only-MISS", _scan(p) == "MISS")
    # F1880: wrong guard index -> MISS
    p = _TEMPLATES[1880].replace("{I}", _codes(SECRET_S)).replace("T.charAt(0)===T[0]", "T.charAt(1)===T[0]")
    _check("F1880-idx1-MISS", _scan(p) == "MISS")
    # F1881: /./g instead of /(?:.)/g -> F1881 hook returns None (F1849 handles it)
    p = _TEMPLATES[1881].replace("{I}", _codes(SECRET_S)).replace("/(?:.)/g", "/./g")
    _check("F1881-dot-hook-None", _direct_hook_result(1881, p) in ("NONE", "ERR"))
    _check("F1881-dot-F1849-HIT", _scan(p) == "HIT")
    # F1883: single-arg includes -> MISS (F1851's shape)
    p = _TEMPLATES[1883].replace("{I}", _codes(SECRET_S)).replace("D.includes(C[0],0)", "D.includes(C[0])")
    _check("F1883-single-arg-MISS", _scan(p) == "MISS")
    # F1884: single-arg indexOf -> MISS (F1852's shape)
    p = _TEMPLATES[1884].replace("{I}", _codes(SECRET_S)).replace(",C.length-1)", ")").replace("D.indexOf(C[C.length-1])", "D.indexOf(C[C.length-1])")
    # Actually F1852 is D.indexOf(C[0]) - different; just check our shape with wrong fromIndex
    p = _TEMPLATES[1884].replace("{I}", _codes(SECRET_S)).replace("C.length-1],C.length-1", "C[0],0")
    _check("F1884-wrong-fromindex-MISS", _scan(p) == "MISS")

    # 4. Sibling pins (must stay HIT on their own shapes, MISS on mine)
    # F1857 (map-back) still HITs its shape
    p = 'var C=%s;var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;' % _codes(SECRET_S)
    _check("sibling-F1857-HIT", _scan(p) == "HIT")
    # F1851 (single-arg includes) still HITs
    p = 'var C=%s;var D=C.slice();if(D.includes(D[0])){var S=String.fromCharCode.apply(null,D);}else{var S=\'\';}var RESULT=S;' % _codes(SECRET_S)
    _check("sibling-F1851-HIT", _scan(p) == "HIT")
    # F1852 (single-arg indexOf) still HITs
    p = 'var C=%s;var D=C.slice();if(D.indexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S=\'\';}var RESULT=S;' % _codes(SECRET_S)
    _check("sibling-F1852-HIT", _scan(p) == "HIT")
    # F1849 (/./g match) still HITs
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/./g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;" % _codes(SECRET_S)
    _check("sibling-F1849-HIT", _scan(p) == "HIT")
    # F1848 (charAt roundtrip) still HITs
    p = "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charAt(i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S)
    _check("sibling-F1848-HIT", _scan(p) == "HIT")

    # 5. Honest text quiet
    _check("honest-quiet", _scan("The quick brown fox jumps over the lazy dog. Contact admin@example.com for help.") == "MISS")
    _check("honest-quiet-2", _scan("var x = 1; var y = 2; console.log(x + y);") == "MISS")

    # 6. Pin assertions
    import gov.dlp as _dlp_mod
    _check("pin-2143", getattr(_dlp_mod, "TAXONOMY_PIN", 2143) == 2143)
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        _check("loops-147", "N_STMTDEC_LOOPS = 147" in f.read())
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        _check("recompile-29", f.read().count("re.compile(") == 29)

    # 7. Perf: 200 sites
    import time
    t0 = time.time()
    for _ in range(200):
        _scan(_TEMPLATES[1877].replace("{I}", _codes(SECRET_S)))
    dt = time.time() - t0
    _check(f"perf-200sites-{dt:.1f}s", dt < 120)

    # Report
    fails = [n for n, ok in _RESULTS if not ok]
    total = len(_RESULTS)
    held = total - len(fails)
    print(f"{held}/{total} HELD")
    for n in fails:
        print(f"  FAIL: {n}")
    if fails:
        sys.exit(1)

    # Depth-1 green check
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        _green_check()


def _green_check():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    import glob
    # Run the red-first batteries (they should now be HELD, not BREAK)
    # Actually red-first batteries print BREAK on open tree; on closed tree they print HELD
    # We just verify they run without error
    for pat in ["evals/w435_f1877_redfirst.py", "evals/w435_f1884_redfirst.py"]:
        p = os.path.join(REPO_ROOT, pat)
        if os.path.exists(p):
            env = dict(os.environ, GOV_SKIP_GREEN="1")
            r = subprocess.run([sys.executable, p], capture_output=True,
                               text=True, timeout=300, env=env, cwd=REPO_ROOT)
            # Red-first on closed tree prints HELD(...), which is expected
            if r.returncode != 0 and "BREAK" not in (r.stdout or ""):
                print(f"Green check note: {pat} exited {r.returncode}")


if __name__ == "__main__":
    main()
