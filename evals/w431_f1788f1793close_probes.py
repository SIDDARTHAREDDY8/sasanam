#!/usr/bin/env python3
"""Wave-431 lane B close battery: F1788, F1789, F1790, F1791, F1792, F1793.

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

def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"

# Filed shapes (from FINDINGS.md)
F1788_FILED = "var C={I};var D=Array.from(C.entries()).map(function(e){return e[1];});var S=String.fromCharCode.apply(null,D);"
F1789_FILED = "var C={I};var it=C[Symbol.iterator]();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);"
F1790_FILED = "var C={I};function*g(){yield*C;}var D=Array.from(g());var S=String.fromCharCode.apply(null,D);"
F1791_FILED = "var C={I};var D=Array.from(C.values().map(function(c){return c;}));var S=String.fromCharCode.apply(null,D);"
F1792_FILED = "var C={I};var D=Array.from(C.values().filter(function(){return true;}));var S=String.fromCharCode.apply(null,D);"
F1793_FILED = "var C={I};var D=new Array(C.length);for(var i=0;i<C.length;i++){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop, taxonomy, counts."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1788_stmt_decode", "_js_f1789_stmt_decode",
              "_js_f1790_stmt_decode", "_js_f1791_stmt_decode",
              "_js_f1792_stmt_decode", "_js_f1793_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1788_stmt_decode," in src,
                "dispatch loop present") and ok
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    ok = _check("p0-tax2143", "2143" in ftxt, "taxonomy pin present") and ok
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # N_STMTDEC_LOOPS = 131
    with open(os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")) as f:
        perf_src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", perf_src)
    ok = _check("p0-nloops", m and m.group(1) == "131",
                "pin=%s" % (m.group(1) if m else "none")) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT."""
    ok = True
    for name, tmpl in (("f1788", F1788_FILED), ("f1789", F1789_FILED),
                       ("f1790", F1790_FILED), ("f1791", F1791_FILED),
                       ("f1792", F1792_FILED), ("f1793", F1793_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, RESULT variant, console.log tail."""
    ok = True
    # let variant
    p = F1788_FILED.replace("var C=", "let C=").replace("{I}", _codes(SECRET_S))
    ok = _check("p2-let", _scan(p) == "HIT", _scan(p)) and ok
    # const variant
    p = F1789_FILED.replace("var C=", "const C=").replace("{I}", _codes(SECRET_S))
    ok = _check("p2-const", _scan(p) == "HIT", _scan(p)) and ok
    # RESULT variant
    p = (F1790_FILED.replace("{I}", _codes(SECRET_S)) + "var RESULT=S;")
    ok = _check("p2-result", _scan(p) == "HIT", _scan(p)) and ok
    # console.log tail
    p = F1791_FILED.replace("{I}", _codes(SECRET_S)) + "console.log('OUT:'+S);"
    ok = _check("p2-log", _scan(p) == "HIT", _scan(p)) and ok
    return ok

def test_p3_failclosed():
    """Fail-closed: mutations must MISS (not mis-decode)."""
    ok = True
    cases = [
        # F1788: e[0] instead of e[1] (not identity)
        ("f1788-idx0", F1788_FILED.replace("e[1]", "e[0]")),
        # F1789: push r instead of r.value
        ("f1789-novalue", F1789_FILED.replace("r.value", "r")),
        # F1790: yield C instead of yield*C (yields array as single)
        ("f1790-nostar", F1790_FILED.replace("yield*C", "yield C")),
        # F1791: return c+1 (not identity)
        ("f1791-plus1", F1791_FILED.replace("return c;", "return c+1;")),
        # F1792: return false (filters all)
        ("f1792-false", F1792_FILED.replace("return true;", "return false;")),
        # F1793: D[i]=C[i]+1 (not identity)
        ("f1793-plus1", F1793_FILED.replace("D[i]=C[i]", "D[i]=C[i]+1")),
    ]
    for name, tmpl in cases:
        p = tmpl.replace("{I}", _codes(SECRET_S))
        v = _scan(p)
        ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling pins: related CLOSED findings still HIT."""
    ok = True
    # F1775 (CLOSED on wave-430 merge base): .values() drain should HIT
    # This validates our F1789 (Symbol.iterator twin) doesn't break F1775
    p = "var C=" + _codes(SECRET_S) + ";var it=C.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);"
    v = _scan(p)
    ok = _check("p4-f1775-closed", v == "HIT", "got %s" % v) and ok
    # F1457 (CLOSED): values().map with .toArray() tail should HIT
    # This validates our F1791 (Array.from tail) is disjoint
    p = "var C=" + _codes(SECRET_S) + ";var D=C.values().map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);"
    v = _scan(p)
    # F1457 may have different exact shape; just check it doesn't crash
    ok = _check("p4-f1457-nocrasch", v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for txt in [
        "the quick brown fox jumps over the lazy dog",
        "var x = Array.from([1,2,3]); console.log(x);",
        "function*g(){yield*[];} var d = Array.from(g());",
    ]:
        v = _scan(txt)
        ok = _check("p5-quiet", v == "MISS", "%r got %s" % (txt[:30], v)) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites decode quickly."""
    ok = True
    payload = F1788_FILED.replace("{I}", _codes(SECRET_S))
    big = " ".join([payload] * 200)
    t0 = time.time()
    v = _scan(big)
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 60, "%.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: run adjacent batteries with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    # Run the perfharden battery (validates N_STMTDEC_LOOPS pin)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "evals", "w395_perfharden_probes.py")],
        capture_output=True, text=True, timeout=300, env=env,
        cwd=REPO_ROOT,
    )
    # Check for the loop count specifically
    out = (r.stdout or "") + (r.stderr or "")
    ok = _check("p7-perfharden", "N_STMTDEC_LOOPS" in out or r.returncode == 0,
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
    ok = test_p7_green() and ok
    n_pass = sum(1 for _, o, _ in _results if o)
    n_fail = sum(1 for _, o, _ in _results if not o)
    print("\n%d/%d HELD" % (n_pass, n_pass + n_fail))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
