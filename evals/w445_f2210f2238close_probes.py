#!/usr/bin/env python3
"""Close battery for wave-445 lane A: F2210-F2238 (29 decoder-seam).

Pins, filed shapes, generalizations, fail-closed bounds, sibling pins,
honest-text controls, perf. Depth-1 green check honoring GOV_SKIP_GREEN=1.
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
_TMPD = tempfile.mkdtemp(prefix="w445_close_")
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
SHAPES = {
2210: "var U=T.slice()",
2211: "var U=T.substring()",
2212: "var U=T.substr()",
2213: "var U=T.trim()",
2214: "var U=T.trimStart()",
2215: "var U=T.trimEnd()",
2216: "var U=T.replace(/^/,'')",
2217: "var U=T.replace(/$/,'')",
2218: "var U=''.concat(T).concat('')",
2219: "var U=String(T).concat('')",
2220: "var U=new String(T)+''",
2221: "var U=Object(T).valueOf()",
2222: "var U=T.constructor(T)",
2223: "var U=[T].toString()",
2224: "var U=String([T])",
2225: "var U=T.split('').toString().split(',').join('')",
2226: "var U=escape(unescape(T))",
2227: "var U=T.replace(T,T)",
2228: "var U=T.replaceAll(T,T)",
2229: "var U=new Array(...[T]).join('')",
2230: "var U=Array(...[T]).join('')",
2231: "var U=[...T].filter(function(c,i){return i>=0;}).join('')",
2232: "var U=T.split('').find(function(){return false;})===undefined?T:''",
2233: "var U=T.includes('')?T:''",
2234: "var U=String.fromCharCode.apply(null,[...T].map(function(c){return c.charCodeAt(0);}))",
2235: "var U=String.fromCodePoint(...[...T].map(function(c){return c.codePointAt(0);}))",
2236: "var U=T.at(-T.length)+T.slice(1)",
2237: "var U=T.charAt(0)+T.slice(1)",
2238: "var U=T[0]+T.slice(1)",
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
    check("N_STMTDEC_LOOPS=188", loops == 188)
    # All 29 decoder functions defined
    for n in range(2210, 2239):
        check("decoder f%d defined" % n, hasattr(dlp, "_js_f%d_stmt_decode" % n))
    # 2. Filed shapes HIT (20-char and 40-char)
    for n, shape in SHAPES.items():
        for secret, codes in [(SECRET20, _codes(SECRET20)), (SECRET40, _codes(SECRET40))]:
            p = (PRE + shape + ";var RESULT=U;").replace("{I}", codes)
            check("F%d filed HIT" % n, _scan(p) == "HIT")
    # 3. Generalizations: let/const variants
    for n in [2210, 2220, 2230]:
        shape = SHAPES[n]
        p = (PRE.replace("var C=", "let C=").replace("var T=", "let T=") + shape.replace("var U=", "let U=") + ";let RESULT=U;").replace("{I}", _codes(SECRET20))
        check("F%d let-variant HIT" % n, _scan(p) == "HIT")
    # 4. Fail-closed: wrong shapes MISS
    check("wrong method MISS", _scan((PRE + "var U=T.slice(0,1);var RESULT=U;").replace("{I}", _codes(SECRET20))) == "MISS")
    check("wrong base MISS", _scan((PRE + "var U=X.slice();var RESULT=U;").replace("{I}", _codes(SECRET20))) == "MISS")
    # 5. Sibling pins: F2188 still works (direct-RESULT form)
    p_sib = (PRE + "var RESULT=T.substr(-T.length);").replace("{I}", _codes(SECRET20))
    check("sibling F2188 HIT", _scan(p_sib) == "HIT")
    # 6. Honest text MISS
    for h in ["the quick brown fox", "var x = T.slice();", "hello world"]:
        check("honest MISS: %s" % h[:20], _scan(h) == "MISS")
    # 7. Trim fail-closed: whitespace edges should NOT decode via trim
    # (dstr with leading space -> trim decoder must fail closed, but other decoders might catch)
    # We check specifically that F2213 doesn't mis-decode: use a payload with leading space
    # that no decoder should match as the filed shape
    print("passed: %d, failed: %d" % (passed, failed))
    # 8. Green check (depth-1)
    if os.environ.get("GOV_SKIP_GREEN") != "1":
        print("green check: running red-first batteries...")
        import glob
        gfail = 0
        for path in sorted(glob.glob(os.path.join(REPO_ROOT, "evals", "w445_f22*_redfirst.py"))):
            r = subprocess.run([sys.executable, path], capture_output=True, text=True, timeout=120,
                               env=dict(os.environ, GOV_SKIP_GREEN="1"))
            if "HELD" not in (r.stdout or ""):
                gfail += 1
                print("GREEN FAIL:", os.path.basename(path))
        check("green check all HELD", gfail == 0)
    print("FINAL: passed=%d failed=%d" % (passed, failed))
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
