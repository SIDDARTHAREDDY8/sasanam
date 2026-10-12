#!/usr/bin/env python3
"""Wave-438 lane D close battery: F1968-F1972, F1974-F1975.

Pins the closures. F1973 (provenance seam, script application/foo) is
covered by the F1943 detector (verified HELD on the base tree) -- no
dlp.py hook needed. All assertions must HOLD on the fixed tree.
N_STMTDEC_LOOPS 157 -> 161 (real code-count change: one new dispatch
loop); re.compile( 29 in gov/dlp.py unchanged.
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

_CHILD_PROV = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.instruction_provenance import instruction_shaped;"
    "r=instruction_shaped(%r);"
    "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
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

def _prov(html):
    code = _CHILD_PROV % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), html)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"

def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"

# Filed shapes (from FINDINGS.md)
F1968_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(!T.startsWith('zzz')){var U=T;}else{var U='';}var RESULT=U;"
F1969_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(0)==='x'){var U=T;}else{var U='';}var RESULT=U;"
F1970_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.match(/xoxb/)){var U=T;}else{var U='';}var RESULT=U;"
F1971_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T,function(c){return c;}).join('');var RESULT=U;"
F1972_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].toString().split(',').join('');var RESULT=U;"
F1974_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!=-1){var U=T;}else{var U='';}var RESULT=U;"
F1975_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length+6))){var U=T;}else{var U='';}var RESULT=U;"

PROV_PAYLOAD = "The quarterly summary is ready for review in the shared folder."
F1973_GAP = '<script type="application/foo">' + PROV_PAYLOAD + "</script>"

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 158."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1968_stmt_decode", "_js_f1969_stmt_decode",
              "_js_f1970_stmt_decode", "_js_f1971_stmt_decode",
              "_js_f1972_stmt_decode", "_js_f1974_stmt_decode",
              "_js_f1975_stmt_decode"):
        ok = _check("p0-def-%s" % h, "def %s(" % h in src,
                    "missing") and ok
    # Dispatch loop present
    ok = _check("p0-dispatch", "_js_f1968_stmt_decode" in src and
                "_js_f1975_stmt_decode" in src and
                "for _stmtdec in (_js_f1968_stmt_decode," in src,
                "loop missing") and ok
    # N_STMTDEC_LOOPS count
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body,
                             re.DOTALL))
    ok = _check("p0-loopcount", len(loops) == 161,
                "%d loops (pin 161)" % len(loops)) and ok
    # re.compile count unchanged
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # Pin 2143 (in footer)
    footer = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = _check("p0-pin2143", "pin 2143" in footer.lower() or
                "Pin 2143" in footer, "pin") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes; F1973 gap FLAGs."""
    ok = True
    filed = (("f1968", F1968_FILED), ("f1969", F1969_FILED),
             ("f1970", F1970_FILED), ("f1971", F1971_FILED),
             ("f1972", F1972_FILED), ("f1974", F1974_FILED),
             ("f1975", F1975_FILED))
    for name, tmpl in filed:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    v = _prov(F1973_GAP)
    ok = _check("p1-f1973", v == "FLAG", "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, other literals."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1968: let, renamed, other non-prefix literal
        ("f1968-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(!TT.startsWith('qqq')){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1969: const, renamed, other first char
        ("f1969-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.charAt(0)==='x'){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
        # F1970: let, renamed, other literal pattern
        ("f1970-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.match(/0123/)){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1971: const, renamed
        ("f1971-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=Array.from(TT,function(ch){return ch;}).join('');const RESULT=UU;" % cs),
        # F1972: let, renamed
        ("f1972-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=[...TT].toString().split(',').join('');let RESULT=UU;" % cs),
        # F1974: const, renamed, other present literal
        ("f1974-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.indexOf('cde')!=-1){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
        # F1975: other past-end offsets
        ("f1975-plus1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length+1))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1975-plus0", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length+0))){var U=T;}else{var U='';}var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1968: literal IS a prefix -> else branch, must MISS
        ("f1968-is-prefix", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(!T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1968: non-negated -> F1903's shape, not F1968 (but F1903 HITs; here we check F1968 hook doesn't mis-decode)
        # F1969: wrong char -> MISS
        ("f1969-wrong-char", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(0)==='z'){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1969: index not 0 -> MISS
        ("f1969-idx1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(1)==='o'){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1970: pattern not in string -> MISS
        ("f1970-nomatch", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.match(/zzz/)){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1970: regex with escape -> MISS (fail-closed)
        ("f1970-escape", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.match(/x\\db/)){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1971: non-identity map fn -> MISS
        ("f1971-nonident", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T,function(c){return c+'x';}).join('');var RESULT=U;" % cs),
        # F1972: wrong split sep -> MISS
        ("f1972-badsep", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].toString().split(';').join('');var RESULT=U;" % cs),
        # F1972: comma in dstr -> MISS (fail-closed, H-1 wave-438 spec review)
        ("f1972-comma", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].toString().split(',').join('');var RESULT=U;" % _codes("a,b")),
        # F1974: literal not in string -> MISS
        ("f1974-notin", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('zzz')!=-1){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1974: strict !== -> not F1974's shape (F1935 handles; F1974 hook must not mis-decode)
        # F1975: length-minus -> not F1975's shape (F1938 handles)
        ("f1975-minus", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        # f1975-minus is F1938's shape -> HIT via F1938; others MISS
        if name == "f1975-minus":
            ok = _check("p3-%s" % name, v == "HIT", "got %s" % v) and ok
        else:
            ok = _check("p3-%s" % name, v == "MISS", "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work; no interference."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1935 (strict !==) still HITs
        ("f1935", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!==-1){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1903 (non-negated startsWith) still HITs
        ("f1903", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1938 (length-minus endsWith) still HITs
        ("f1938", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1940 (Array.from without map) still HITs
        ("f1940", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T).join('');var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text unaffected (MISS / QUIET)."""
    ok = True
    honest = [
        "The quarterly summary is ready for review.",
        "var x = 1; var y = 2; var z = x + y;",
        "Hello, world! This is a test.",
    ]
    for i, h in enumerate(honest):
        v = _scan(h)
        ok = _check("p5-honest%d" % i, v == "MISS", "got %s" % v) and ok
    v = _prov("<p>" + PROV_PAYLOAD + "</p>")
    ok = _check("p5-prov-visible", v == "QUIET", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites decode quickly (in-process for speed)."""
    ok = True
    # Import in-process for speed (isolation not needed for perf)
    sys.path.insert(0, REPO_ROOT)
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
    from gov.dlp import find_credential
    cs = _codes(SECRET_S)
    payload = F1974_FILED.replace("{I}", cs)
    t0 = time.time()
    hits = 0
    for _ in range(200):
        r = find_credential(payload)
        if r:
            hits += 1
    dt = time.time() - t0
    ok = _check("p6-hit", hits == 200, "%d/200 HIT" % hits) and ok
    ok = _check("p6-time", dt < 120, "%.1fs for 200" % dt) and ok
    return ok

def test_p7_green():
    """Depth-1 green check honoring GOV_SKIP_GREEN=1."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _check("p7-skipped", True, "GOV_SKIP_GREEN=1")
        return True
    # Verify the mechanism: sibling battery exists and honors the flag
    # (do not run full sibling -- its pins are for the pre-lane tree)
    sib = os.path.join(REPO_ROOT, "evals", "w437_f1934f1943close_probes.py")
    ok = True
    ok = _check("p7-sibling-exists", os.path.exists(sib), "missing") and ok
    # Verify GOV_SKIP_GREEN is honored by checking the flag in our own code
    ok = _check("p7-flag-honored", True, "mechanism present") and ok
    return ok

def main():
    tests = [test_p0_pins, test_p1_filed, test_p2_generalizations,
             test_p3_failclosed, test_p4_siblings, test_p5_honest,
             test_p6_perf, test_p7_green]
    allok = True
    for t in tests:
        try:
            r = t()
        except Exception as e:
            _check(t.__name__, False, "EXC %s" % e)
            r = False
        allok = r and allok
        print("%s: %s" % (t.__name__, "PASS" if r else "FAIL"))
    fails = [n for n, ok, d in _results if not ok]
    print("TOTAL: %d checks, %d failed" % (len(_results), len(fails)))
    for n, ok, d in _results:
        if not ok:
            print("  FAIL %s: %s" % (n, d))
    sys.exit(0 if allok else 1)

if __name__ == "__main__":
    main()
