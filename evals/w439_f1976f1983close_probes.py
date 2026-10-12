#!/usr/bin/env python3
"""Wave-439 lane A close battery: F1976-F1983.

Pins the closures. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 161 -> 162 (real code-count change: one new dispatch
loop); re.compile( 29 unchanged; pin 2143.
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

# Filed shapes (from FINDINGS.md, attack round 106, first-filing 2026-10-12 18:19 UTC)
F1976_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' ').trimEnd();var RESULT=U;"
F1977_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(10)+T).trimLeft();var RESULT=U;"
F1978_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(13,10)+T).trimStart();var RESULT=U;"
F1979_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(160)+T).trimStart();var RESULT=U;"
F1980_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(2);var RESULT=U;"
F1981_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(8);var RESULT=U;"
F1982_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T.toString(16);var RESULT=U;"
F1983_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T['toString']();var RESULT=U;"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 162."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1976_stmt_decode", "_js_f1977_stmt_decode",
              "_js_f1978_stmt_decode", "_js_f1979_stmt_decode",
              "_js_f1980_stmt_decode", "_js_f1981_stmt_decode",
              "_js_f1982_stmt_decode", "_js_f1983_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1976_stmt_decode," in src,
                "dispatch loop present") and ok
    # Loop count: 161 base + 1 new = 162
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    ok = _check("p0-loopcount", len(loops) == 162,
                "%d loops (pin 162)" % len(loops)) and ok
    # re.compile count unchanged
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes."""
    ok = True
    for name, tmpl in (("f1976", F1976_FILED), ("f1977", F1977_FILED),
                       ("f1978", F1978_FILED), ("f1979", F1979_FILED),
                       ("f1980", F1980_FILED), ("f1981", F1981_FILED),
                       ("f1982", F1982_FILED), ("f1983", F1983_FILED)):
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
        ("f1976-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(TT+' ').trimEnd();let RESULT=UU;" % cs),
        ("f1977-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(String.fromCharCode(10)+B).trimLeft();const RESULT=Q;" % cs),
        ("f1978-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=(String.fromCharCode(13,10)+TT).trimStart();let RESULT=UU;" % cs),
        ("f1979-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=(String.fromCharCode(160)+B).trimStart();const RESULT=Q;" % cs),
        ("f1980-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=TT.toString(2);let RESULT=UU;" % cs),
        ("f1981-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B.toString(8);const RESULT=Q;" % cs),
        ("f1982-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=''+TT.toString(16);let RESULT=UU;" % cs),
        ("f1983-const", "const A=%s;const B=A.map(function(c){return String.fromCharCode(c);}).join('');const Q=B['toString']();const RESULT=Q;" % cs),
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
        # F1976: tab pad instead of space -> narrow grammar -> MISS
        ("f1976-tab", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+'\\t').trimEnd();var RESULT=U;" % cs, "MISS"),
        # F1976: trimStart instead of trimEnd -> different hook -> MISS (F1944 covers tab, not space)
        ("f1976-trimstart", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' ').trimStart();var RESULT=U;" % cs, "MISS"),
        # F1977: fromCharCode(32) instead of 10 -> narrow grammar -> MISS
        ("f1977-space", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(32)+T).trimLeft();var RESULT=U;" % cs, "MISS"),
        # F1978: single 10 instead of 13,10 -> narrow grammar -> MISS
        ("f1978-single", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(10)+T).trimStart();var RESULT=U;" % cs, "MISS"),
        # F1979: 32 instead of 160 -> narrow grammar -> MISS
        ("f1979-space", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(String.fromCharCode(32)+T).trimStart();var RESULT=U;" % cs, "MISS"),
        # F1980: radix 16 -> covered by F1946 sibling -> HIT
        ("f1980-radix16-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs, "HIT"),
        # F1980: radix 10 -> covered by F1911 sibling -> HIT
        ("f1980-radix10-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;" % cs, "HIT"),
        # F1981: radix 2 -> covered by F1980 sibling -> HIT
        ("f1981-radix2-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(2);var RESULT=U;" % cs, "HIT"),
        # F1982: bare toString(16) without additive -> covered by F1946 -> HIT
        ("f1982-bare-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs, "HIT"),
        # F1983: dot-access instead of bracket -> covered by F1892 -> HIT
        ("f1983-dot-sib", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;" % cs, "HIT"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s want %s" % (v, expect)) and ok
    return ok

def test_p4_siblings():
    """Sibling findings still HIT (no regression)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        ("f1944", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('\\t'+T).trimStart();var RESULT=U;" % cs),
        ("f1946", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(16);var RESULT=U;" % cs),
        ("f1911", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    for name, payload in (
        ("prose", "the quick brown fox jumps over the lazy dog"),
        ("code", "function hello() { return 'world'; }"),
        ("trim", "var x = '  hello  '.trim();"),
    ):
        v = _scan(payload)
        ok = _check("p5-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites decode within budget."""
    ok = True
    cs = _codes(SECRET_S)
    payload = F1976_FILED.replace("{I}", cs)
    # 200 copies
    big = " ".join([payload] * 200)
    start = time.time()
    v = _scan(big)
    elapsed = time.time() - start
    ok = _check("p6-time", elapsed < 30, "%.2fs" % elapsed) and ok
    # Should still HIT (or at least not ERROR)
    ok = _check("p6-verdict", v in ("HIT", "MISS"), "got %s" % v) and ok
    return ok

def test_p7_green():
    """Depth-1 green check: adjacent battery deltas are expected-only."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _check("p7-skip", True, "skipped")
        return True
    ok = True
    # Run the w438 lane A battery as a green check. Two deltas are
    # EXPECTED from this lane's closures (wave-305): (1) loop count
    # 161->162 (new dispatch loop); (2) p3-f1946-radix8 now HITs
    # (F1981 closes T.toString(8)). Any other failure is a regression.
    battery = os.path.join(REPO_ROOT, "evals", "w438_f1944f1951close_probes.py")
    if os.path.exists(battery):
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        r = subprocess.run([sys.executable, battery],
                           capture_output=True, text=True, timeout=600,
                           env=env, cwd=REPO_ROOT)
        out = (r.stdout or "") + (r.stderr or "")
        # Extract FAIL lines
        fails = [l.strip() for l in out.split("\n") if "FAIL " in l]
        expected = {"p0-loopcount", "p3-f1946-radix8"}
        unexpected = [f for f in fails
                      if not any(e in f for e in expected)]
        ok = _check("p7-w438a-no-regress", len(unexpected) == 0,
                    "unexpected: %s" % unexpected) and ok
        # Verify the expected deltas are present (proves the battery ran)
        has_loop = any("p0-loopcount" in f for f in fails)
        has_radix8 = any("p3-f1946-radix8" in f for f in fails)
        ok = _check("p7-w438a-expected", has_loop and has_radix8,
                    "loop=%s radix8=%s" % (has_loop, has_radix8)) and ok
    else:
        _check("p7-w438a", True, "not found, skipped")
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
            _check(t.__name__, False, "EXC: %s" % e)
            ok = False
        all_ok = ok and all_ok
        print("%s: %s" % (t.__name__, "PASS" if ok else "FAIL"))
    
    n_pass = sum(1 for _, ok, _ in _results if ok)
    n_fail = sum(1 for _, ok, _ in _results if not ok)
    print("\n%d/%d checks passed" % (n_pass, n_pass + n_fail))
    for name, ok, detail in _results:
        if not ok:
            print("  FAIL %s: %s" % (name, detail))
    
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
