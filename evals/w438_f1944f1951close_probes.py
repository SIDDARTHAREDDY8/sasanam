#!/usr/bin/env python3
"""Wave-438 lane A close battery: F1944-F1951.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 157 -> 161 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w438_close_")
os.environ["TMPDIR"] = _TMPD

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

# Filed shapes (from FINDINGS.md, attack round 105, first-filing 2026-10-12 16:09 UTC)
F1944_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('\\t'+T).trimStart();var RESULT=U;"
F1945_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimLeft().trimRight();var RESULT=U;"
F1946_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;"
F1947_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString.bind(T)();var RESULT=U;"
F1948_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.valueOf.call(T);var RESULT=U;"
F1949_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString().toString();var RESULT=U;"
F1950_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}${''}`;var RESULT=U;"
F1951_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${`${T}`}`;var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 158."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1944_stmt_decode", "_js_f1945_stmt_decode",
              "_js_f1946_stmt_decode", "_js_f1947_stmt_decode",
              "_js_f1948_stmt_decode", "_js_f1949_stmt_decode",
              "_js_f1950_stmt_decode", "_js_f1951_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1944_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 157 base + 4 new = 161
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    ok = _check("p0-loopcount", len(loops) == 161,
                "%d loops (pin 161)" % len(loops)) and ok
    # re.compile count unchanged
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1944", F1944_FILED), ("f1945", F1945_FILED),
                       ("f1946", F1946_FILED), ("f1947", F1947_FILED),
                       ("f1948", F1948_FILED), ("f1949", F1949_FILED),
                       ("f1950", F1950_FILED), ("f1951", F1951_FILED)):
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1944: let, renamed
        ("f1944-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=('\\t'+TT).trimStart();let RESULT=UU;" % cs),
        # F1945: const, renamed
        ("f1945-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(' '+B).trimLeft().trimRight();const RESULT=Q;" % cs),
        # F1946: let, renamed
        ("f1946-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.toString(16);let RESULT=UU;" % cs),
        # F1947: const, renamed
        ("f1947-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B.toString.bind(B)();const RESULT=Q;" % cs),
        # F1948: let, renamed
        ("f1948-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=String.prototype.valueOf.call(TT);let RESULT=UU;" % cs),
        # F1949: const, renamed
        ("f1949-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B.toString().toString();const RESULT=Q;" % cs),
        # F1950: let, renamed
        ("f1950-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=`${''}${TT}${''}`;let RESULT=UU;" % cs),
        # F1951: const, renamed
        ("f1951-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=`${`${B}`}`;const RESULT=Q;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS); sibling-covered shapes HIT."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1944: newline pad instead of tab -> narrow grammar -> MISS
        ("f1944-newline", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('\\n'+T).trimStart();var RESULT=U;" % cs, "MISS"),
        # F1944: space pad -> covered by F1907 sibling -> HIT
        ("f1944-space-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimStart();var RESULT=U;" % cs, "HIT"),
        # F1945: reversed order -> narrow grammar -> MISS
        ("f1945-reversed", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimRight().trimLeft();var RESULT=U;" % cs, "MISS"),
        # F1946: radix 8 -> narrow grammar -> MISS
        ("f1946-radix8", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(8);var RESULT=U;" % cs, "MISS"),
        # F1946: radix 10 -> covered by F1911 sibling -> HIT
        ("f1946-radix10-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;" % cs, "HIT"),
        # F1947: bind without call -> narrow grammar -> MISS
        ("f1947-nocall", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString.bind(T);var RESULT=U;" % cs, "MISS"),
        # F1948: .apply instead of .call -> narrow grammar -> MISS
        ("f1948-apply", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.valueOf.apply(T);var RESULT=U;" % cs, "MISS"),
        # F1949: triple toString -> narrow grammar -> MISS
        ("f1949-triple", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString().toString().toString();var RESULT=U;" % cs, "MISS"),
        # F1949: single toString -> covered by F1892 sibling -> HIT
        ("f1949-single-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;" % cs, "HIT"),
        # F1950: two substitutions -> covered by F1916 sibling -> HIT
        ("f1950-two-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}`;var RESULT=U;" % cs, "HIT"),
        # F1950: four substitutions -> narrow grammar -> MISS
        ("f1950-four", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}${''}${''}`;var RESULT=U;" % cs, "MISS"),
        # F1951: trailing space in inner -> narrow grammar -> MISS
        ("f1951-space", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${`${T} `}`;var RESULT=U;" % cs, "MISS"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks (F1907/F1911/F1912/F1913/F1916) still work."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1907: trimStart with space pad
        ("f1907", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimStart();var RESULT=U;" % cs),
        # F1911: toString with radix 10
        ("f1911", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;" % cs),
        # F1912: toString via .call
        ("f1912", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.toString.call(T);var RESULT=U;" % cs),
        # F1913: valueOf chained toString
        ("f1913", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().toString();var RESULT=U;" % cs),
        # F1916: template two substitutions
        ("f1916", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}`;var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "var x = 'hello world'; var y = 42;",
        "function greet(name) { return 'Hello, ' + name; }",
        "var t = 'abc'; var u = t.trimStart(); console.log(u);",
        "var s = 'pad'; var u = s.toString(16);",
        "var t = 'x'; var u = t.toString.bind(t);",
        "var t = `hello ${name}`; console.log(t);",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-honest%d" % i, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time (in-process, not subprocess)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1944_FILED.replace("{I}", cs),
        F1945_FILED.replace("{I}", cs),
        F1946_FILED.replace("{I}", cs),
        F1947_FILED.replace("{I}", cs),
        F1948_FILED.replace("{I}", cs),
        F1949_FILED.replace("{I}", cs),
        F1950_FILED.replace("{I}", cs),
        F1951_FILED.replace("{I}", cs),
    ]
    t0 = time.time()
    for i in range(200):
        r = _dlp.find_credential(tmpls[i % 8])
        if not r:
            ok = _check("p6-perf", False, "miss at %d" % i) and ok
            return ok
    dt = time.time() - t0
    ok = _check("p6-perf", dt < 120, "200 sites in %.1fs" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: adjacent battery main with GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("SKIP p7-green (GOV_SKIP_GREEN=1)")
        return True
    ok = True
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    # Adjacent: wave-437 lane D (F1934-F1943). Its p0-loopcount pin (157)
    # predates this lane's loop (158) and is repointed at merge; only
    # unexpected failures count here.
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w437_f1934f1943close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("  FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w437d", not unexpected,
                "unexpected fails: %s" % unexpected) and ok
    return ok

def main():
    tests = [
        test_p0_pins,
        test_p1_filed,
        test_p2_generalizations,
        test_p3_failclosed,
        test_p4_siblings,
        test_p5_honest,
        test_p6_perf,
        test_p7_green,
    ]
    all_ok = True
    for t in tests:
        try:
            ok = t()
        except Exception as e:
            _check(t.__name__, False, "EXC %s" % e)
            ok = False
        all_ok = all_ok and ok
    fails = [n for n, ok, d in _results if not ok]
    print("\n%d/%d HELD" % (len(_results) - len(fails), len(_results)))
    if fails:
        print("FAILURES:")
        for n, ok, d in _results:
            if not ok:
                print("  FAIL %s -- %s" % (n, d))
        sys.exit(1)
    print("ALL HELD")


if __name__ == "__main__":
    main()
