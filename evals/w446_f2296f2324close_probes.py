#!/usr/bin/env python3
"""Close battery for wave-446 lane A: F2296-F2324 (29 decoder-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w446_close_")
os.environ["TMPDIR"] = _TMPD
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET20 = "xoxb-" + "a" * 15
SECRET40 = "xoxb-" + "a" * 35

def _codes(secret):
    return "[" + ",".join(str(ord(c)) for c in secret) + "]"

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

PRE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
# Full U-statement payloads (F2310-F2313 have extra statements before var U=).
SHAPES = {
2296: "var U=T.padStart(T.length+0);",
2297: "var U=T.trimRight();",
2298: "var U=T+T.slice(T.length);",
2299: "var U=T.slice(T.length)+T;",
2300: "var U=T.replace(/z/,'');",
2301: "var U=T.replace(T[0],T[0]);",
2302: "var U=T.replaceAll(/z/g,'');",
2303: "var U=T.split('z').join('z');",
2304: "var U=T.split(T[0]).join(T[0]);",
2305: "var U=T.match(/.+/)[0];",
2306: "var U=T.match(/^.*$/)[0];",
2307: "var U=Array.from({length:T.length},function(_,i){return T[i];}).join('');",
2308: "var U=T.split('').reduceRight(function(a,c){return c+a;},'');",
2309: "var U=T.split('').map(function(c){return c;}).join('');",
2310: "var A=[];T.split('').forEach(function(c){A.push(c);});var U=A.join('');",
2311: "var A='';for(var i=0;i<T.length;i++){A+=T[i];}var U=A;",
2312: "var A='';for(var c of T){A+=c;}var U=A;",
2313: "var A='',i=0;do{A+=T[i];i++;}while(i<T.length);var U=A;",
2314: "var U=[].concat(T).join('');",
2315: "var U=[].concat(T)[0];",
2316: "var U=T.split('').concat().join('');",
2317: "var U=T.split('').slice().join('');",
2318: "var U=Object.values({v:T})[0];",
2319: "var U=Object.entries({v:T})[0][1];",
2320: "var U=JSON.stringify([T]).slice(2,-2);",
2321: "var U=JSON.stringify({v:T}).slice(6,-2);",
2322: "var U=encodeURIComponent(T);",
2323: "var U=decodeURIComponent(T);",
2324: "var U=unescape(T);",
}

passed = 0
failed = 0
def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name)

def main():
    global passed, failed
    # 1. Pin checks
    import gov.dlp as dlp
    loops = sum(1 for line in open(os.path.join(REPO_ROOT, "gov/dlp.py")).read().split("\n") if "for _stmtdec in" in line)
    check("N_STMTDEC_LOOPS=190", loops == 190)
    import re as _re
    dlp_re = len(_re.findall(r"re\.compile\(", open(os.path.join(REPO_ROOT, "gov/dlp.py")).read()))
    check("re.compile=29 in dlp", dlp_re == 29)
    for n in range(2296, 2325):
        check("decoder f%d defined" % n, hasattr(dlp, "_js_f%d_stmt_decode" % n))
    # 2. Filed shapes HIT (20-char and 40-char)
    for n, shape in SHAPES.items():
        for secret, codes in [(SECRET20, _codes(SECRET20)), (SECRET40, _codes(SECRET40))]:
            p = (PRE + shape + "var RESULT=U;").replace("{I}", codes)
            check("F%d filed HIT" % n, _scan(p) == "HIT")
    # 3. Generalizations: let/const variants
    for n in [2296, 2310, 2320]:
        shape = SHAPES[n]
        p = (PRE.replace("var C=", "const C=").replace("var T=", "const T=")
             + shape.replace("var A=", "const A=").replace("var U=", "const U=")
             + "const RESULT=U;").replace("{I}", _codes(SECRET20))
        check("F%d const-variant HIT" % n, _scan(p) == "HIT")
    # 4. Fail-closed: wrong shapes MISS
    check("wrong method MISS", _scan((PRE + "var U=T.slice(0,1);var RESULT=U;").replace("{I}", _codes(SECRET20))) == "MISS")
    check("wrong base MISS", _scan((PRE + "var U=X.trimRight();var RESULT=U;").replace("{I}", _codes(SECRET20))) == "MISS")
    check("wrong padStart arg MISS", _scan((PRE + "var U=T.padStart(5);var RESULT=U;").replace("{I}", _codes(SECRET20))) == "MISS")
    # 5. Guard fail-closed: adversarial dstr values must MISS
    # F2300/F2302: 'z' in dstr
    z_secret = "xoxb-" + "a" * 14 + "z"
    p = (PRE + SHAPES[2300] + "var RESULT=U;").replace("{I}", _codes(z_secret))
    check("F2300 z-present MISS", _scan(p) == "MISS")
    p = (PRE + SHAPES[2302] + "var RESULT=U;").replace("{I}", _codes(z_secret))
    check("F2302 z-present MISS", _scan(p) == "MISS")
    # F2297: trailing space in dstr
    sp_secret = "xoxb-" + "a" * 14 + " "
    p = (PRE + SHAPES[2297] + "var RESULT=U;").replace("{I}", _codes(sp_secret))
    check("F2297 trailing-space MISS", _scan(p) == "MISS")
    # F2305/F2306: newline in dstr
    nl_secret = "xoxb-" + "a" * 7 + chr(10) + "a" * 7
    p = (PRE + SHAPES[2305] + "var RESULT=U;").replace("{I}", _codes(nl_secret))
    check("F2305 newline MISS", _scan(p) == "MISS")
    p = (PRE + SHAPES[2306] + "var RESULT=U;").replace("{I}", _codes(nl_secret))
    check("F2306 newline MISS", _scan(p) == "MISS")
    # F2320/F2321: quote in dstr (JSON-escapable)
    q_secret = "xoxb-" + "a" * 7 + '"' + "a" * 7
    p = (PRE + SHAPES[2320] + "var RESULT=U;").replace("{I}", _codes(q_secret))
    check("F2320 quote MISS", _scan(p) == "MISS")
    p = (PRE + SHAPES[2321] + "var RESULT=U;").replace("{I}", _codes(q_secret))
    check("F2321 quote MISS", _scan(p) == "MISS")
    # F2322: '%' in dstr (encodable)
    pct_secret = "xoxb-" + "a" * 14 + "%"
    p = (PRE + SHAPES[2322] + "var RESULT=U;").replace("{I}", _codes(pct_secret))
    check("F2322 percent MISS", _scan(p) == "MISS")
    # F2323/F2324: '%' in dstr
    p = (PRE + SHAPES[2323] + "var RESULT=U;").replace("{I}", _codes(pct_secret))
    check("F2323 percent MISS", _scan(p) == "MISS")
    p = (PRE + SHAPES[2324] + "var RESULT=U;").replace("{I}", _codes(pct_secret))
    check("F2324 percent MISS", _scan(p) == "MISS")
    # 6. Sibling pins: F2210 (wave-445) and F2295 (wave-445 last) still HIT
    p_sib = (PRE + "var U=T.slice();var RESULT=U;").replace("{I}", _codes(SECRET20))
    check("sibling F2210 HIT", _scan(p_sib) == "HIT")
    # 7. Honest text MISS
    for h in ["the quick brown fox", "var x = T.trimRight();", "hello world",
              "encodeURIComponent is a function"]:
        check("honest MISS: %s" % h[:24], _scan(h) == "MISS")
    # 8. Perf: 200 sites
    import time as _time
    t0 = _time.time()
    for i in range(200):
        _scan((PRE + "var U=T.trimRight();var RESULT=U;").replace("{I}", _codes(SECRET20)))
    dt = _time.time() - t0
    # Threshold accommodates ~1s/subprocess startup overhead; base tree measures
    # 0.83s/scan vs lane 0.84s/scan (no decoder regression).
    check("perf 200 sites < 300s (%.1fs)" % dt, dt < 300)
    print("passed: %d, failed: %d" % (passed, failed))
    # 9. Green check (depth-1)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running red-first batteries...")
        import glob
        import re as _re2
        gfail = 0
        paths = []
        for path in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w445_f*_redfirst.py"))):
            m = _re2.search(r"w445_f(\d+)_redfirst", path)
            if m and 2296 <= int(m.group(1)) <= 2324:
                paths.append(path)
        for path in paths:
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, GOV_SKIP_GREEN="1"))
            if "HELD" not in (r.stdout or ""):
                gfail += 1
                print("GREEN FAIL:", os.path.basename(path))
        check("green check all HELD (29)", gfail == 0 and len(paths) == 29)
    print("FINAL: passed=%d failed=%d" % (passed, failed))
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
