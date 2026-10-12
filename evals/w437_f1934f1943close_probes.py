#!/usr/bin/env python3
"""Wave-437 lane D close battery: F1934-F1938, F1940-F1943.

Pins the closures (F1939 already CLOSED at wave-436 merge, covered by
the F1904 hook -- not in lane scope). All assertions must HOLD on the
fixed tree. N_STMTDEC_LOOPS 153 -> 154 (real code-count change: one
new dispatch loop); re.compile( 29 in gov/dlp.py unchanged.
"""
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import tempfile
_TMPD = tempfile.mkdtemp(prefix="w437_close_")
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

# Filed shapes (from FINDINGS.md, attack round 104, first-filing 2026-10-12 15:09 UTC)
F1934_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb',0)>=0){var U=T;}else{var U='';}var RESULT=U;"
F1935_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!==-1){var U=T;}else{var U='';}var RESULT=U;"
F1936_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith(T.slice(0,4))){var U=T;}else{var U='';}var RESULT=U;"
F1937_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.toLowerCase().startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"
F1938_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;"
F1940_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T).join('');var RESULT=U;"
F1941_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(``);var RESULT=U;"
F1942_FILED = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(String());var RESULT=U;"

PROV_PAYLOAD = "The quarterly summary is ready for review in the shared folder."
F1943_GAP = [
    '<script type="text/unknown">' + PROV_PAYLOAD + "</script>",
    '<script type="text/foo">' + PROV_PAYLOAD + "</script>",
    '<script type="application/json">' + PROV_PAYLOAD + "</script>",
]

def test_p0_pins():
    """Pin checks: hooks defined, dispatch loop present, loop count 154."""
    ok = True
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    for h in ("_js_f1934_stmt_decode", "_js_f1935_stmt_decode",
              "_js_f1936_stmt_decode", "_js_f1937_stmt_decode",
              "_js_f1938_stmt_decode", "_js_f1940_stmt_decode",
              "_js_f1941_stmt_decode", "_js_f1942_stmt_decode"):
        ok = _check("p0-%s" % h, ("def %s(" % h) in src, "defined") and ok
    ok = _check("p0-dispatch", "_js_f1934_stmt_decode," in src,
                "dispatch loop present") and ok
    n = src.count("for _stmtdec in (")
    ok = _check("p0-loopcount", n == 154, "got %d" % n) and ok
    nrc = src.count("re.compile(")
    ok = _check("p0-recompile", nrc == 29, "got %d" % nrc) and ok
    with open(os.path.join(REPO_ROOT, "gov",
                           "instruction_provenance.py")) as f:
        psrc = f.read()
    ok = _check("p0-f1943-def",
                "def _has_hidden_script_other_nonexec_type(" in psrc,
                "defined") and ok
    ok = _check("p0-f1943-reg",
                "_has_hidden_script_other_nonexec_type(norm)" in psrc,
                "registered") and ok
    return ok

def test_p1_filed():
    """Filed shapes HIT on both credential sizes; F1943 gap shapes FLAG."""
    ok = True
    filed = (("f1934", F1934_FILED), ("f1935", F1935_FILED),
             ("f1936", F1936_FILED), ("f1937", F1937_FILED),
             ("f1938", F1938_FILED), ("f1940", F1940_FILED),
             ("f1941", F1941_FILED), ("f1942", F1942_FILED))
    for name, tmpl in filed:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = _check("p1-%s-%s" % (name, label), v == "HIT",
                        "got %s" % v) and ok
    for i, html in enumerate(F1943_GAP):
        v = _prov(html)
        ok = _check("p1-f1943-gap%d" % i, v == "FLAG",
                    "got %s" % v) and ok
    return ok

def test_p2_generalizations():
    """Generalizations: let/const, renamed idents, other literals, other types."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1934: let, renamed, other present literal
        ("f1934-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.indexOf('cde',0)>=0){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1935: const, renamed
        ("f1935-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.indexOf('0123')!==-1){const UU=TT;}else{const UU='';}const RESULT=UU;" % cs),
        # F1936: other slice args (tautology holds node-exactly for any int)
        ("f1936-slice2", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith(T.slice(0,2))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        ("f1936-sliceneg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith(T.slice(0,-1))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1937: longer literal, let
        ("f1937-longer", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');if(TT.toLowerCase().startsWith('xoxb-01')){let UU=TT;}else{let UU='';}let RESULT=UU;" % cs),
        # F1938: other tail lengths
        ("f1938-tail3", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-3))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1940: let, renamed
        ("f1940-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=Array.from(TT).join('');let RESULT=UU;" % cs),
        # F1941: const, renamed
        ("f1941-const", "const CC=%s;const TT=CC.map(function(c){return String.fromCharCode(c);}).join('');const UU=[...TT].join(``);const RESULT=UU;" % cs),
        # F1942: let, renamed
        ("f1942-let", "let CC=%s;let TT=CC.map(function(c){return String.fromCharCode(c);}).join('');let UU=[...TT].join(String());let RESULT=UU;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", "got %s" % v) and ok
    # F1943 generalizations: case-insensitive type, unquoted attr, more types
    prov_cases = [
        ("f1943-upper", '<script TYPE="TEXT/UNKNOWN">' + PROV_PAYLOAD + "</script>"),
        ("f1943-unquoted", "<script type=text/bar>" + PROV_PAYLOAD + "</script>"),
        ("f1943-svg", '<script type="image/svg+xml">' + PROV_PAYLOAD + "</script>"),
    ]
    for name, html in prov_cases:
        v = _prov(html)
        ok = _check("p2-%s" % name, v == "FLAG", "got %s" % v) and ok
    return ok

def test_p3_failclosed():
    """Mutations fail closed (MISS / QUIET)."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1934: absent literal -> else branch -> MISS
        ("f1934-absent", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('zzzz',0)>=0){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1934: non-zero position -> narrow grammar -> MISS
        ("f1934-pos5", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb',5)>=0){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1935: absent literal -> MISS
        ("f1935-absent", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('zzzz')!==-1){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1935: loose != -> narrow grammar -> MISS
        ("f1935-loose", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!=-1){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1936: slice start != 0 -> narrow grammar -> MISS
        ("f1936-start1", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith(T.slice(1,4))){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1937: non-prefix literal -> MISS
        ("f1937-nonprefix", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.toLowerCase().startsWith('zzzz')){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1938: length+ (not minus) -> narrow grammar -> MISS
        ("f1938-plus", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length+6))){var U=T;}else{var U='';}var RESULT=U;" % cs, "MISS"),
        # F1940: wrong base -> MISS
        ("f1940-wrongbase", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(C).join('');var RESULT=U;" % cs, "MISS"),
        # F1941: non-empty template sep -> MISS
        ("f1941-nonempty", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(`x`);var RESULT=U;" % cs, "MISS"),
        # F1942: String('x') -> MISS
        ("f1942-stringarg", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(String('x'));var RESULT=U;" % cs, "MISS"),
    ]
    for name, payload, expect in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    # F1943: executable script types stay QUIET
    prov_cases = [
        ("f1943-classic", '<script>var x = 1;</script><p>' + PROV_PAYLOAD + "</p>", "QUIET"),
        ("f1943-js", '<script type="text/javascript">' + PROV_PAYLOAD + "</script>", "QUIET"),
        ("f1943-module", '<script type="module">' + PROV_PAYLOAD + "</script>", "QUIET"),
        ("f1943-empty", '<script type="">' + PROV_PAYLOAD + "</script>", "QUIET"),
        ("f1943-machine", '<script type="text/unknown">ABC-123</script>', "QUIET"),
    ]
    for name, html, expect in prov_cases:
        v = _prov(html)
        ok = _check("p3-%s" % name, v == expect, "got %s" % v) and ok
    return ok

def test_p4_siblings():
    """Sibling hooks still work: F1902/F1903/F1904/F1906, F1939-covered, script types."""
    ok = True
    cs = _codes(SECRET_S)
    cases = [
        # F1902: one-arg indexOf guard
        ("f1902", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=0){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1903: literal startsWith guard
        ("f1903", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1904: slice-tail endsWith guard
        ("f1904", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-6))){var U=T;}else{var U='';}var RESULT=U;" % cs),
        # F1906: string-literal spread join
        ("f1906", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join('');var RESULT=U;" % cs),
        # F1939 (covered by F1904 hook): endsWith(T.slice(-1))
        ("f1939", "var C=%s;var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-1))){var U=T;}else{var U='';}var RESULT=U;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", "got %s" % v) and ok
    # Covered script data types still FLAG via their own detectors
    prov_cases = [
        ("f1073-plain", '<script type="text/plain">' + PROV_PAYLOAD + "</script>"),
        ("f1085-xtemplate", '<script type="text/x-template">' + PROV_PAYLOAD + "</script>"),
        ("f1047-ldjson", '<script type="application/ld+json">' + PROV_PAYLOAD + "</script>"),
    ]
    for name, html in prov_cases:
        v = _prov(html)
        ok = _check("p4-%s" % name, v == "FLAG", "got %s" % v) and ok
    return ok

def test_p5_honest():
    """Honest text stays quiet."""
    ok = True
    cases = [
        "var x = 'hello world'; var y = 42;",
        "function greet(name) { return 'Hello, ' + name; }",
        "var t = 'abc'; if (t.includes('b')) { console.log('yes'); }",
        "var arr = [...'xyz']; var j = arr.join('');",
        "var u = Array.from('abc').join('');",
    ]
    for i, payload in enumerate(cases):
        v = _scan(payload)
        ok = _check("p5-honest%d" % i, v == "MISS", "got %s" % v) and ok
    prov_cases = [
        "<p>" + PROV_PAYLOAD + "</p>",
        "<script>console.log('hi');</script>",
        "<div>" + PROV_PAYLOAD + "</div>",
    ]
    for i, html in enumerate(prov_cases):
        v = _prov(html)
        ok = _check("p5-prov%d" % i, v == "QUIET", "got %s" % v) and ok
    return ok

def test_p6_perf():
    """Perf: 200 sites in reasonable time (in-process, not subprocess)."""
    ok = True
    import gov.dlp as _dlp
    cs = _codes(SECRET_S)
    tmpls = [
        F1934_FILED.replace("{I}", cs),
        F1935_FILED.replace("{I}", cs),
        F1936_FILED.replace("{I}", cs),
        F1937_FILED.replace("{I}", cs),
        F1938_FILED.replace("{I}", cs),
        F1940_FILED.replace("{I}", cs),
        F1941_FILED.replace("{I}", cs),
        F1942_FILED.replace("{I}", cs),
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
    # Adjacent: wave-436 lane C (F1901-F1906 string-guard siblings).
    # Its p0-loopcount pin (153) predates this lane's loop (154) and is
    # repointed at merge; only unexpected failures count here.
    cmd = [sys.executable, os.path.join(REPO_ROOT, "evals",
                                        "w436_f1901f1906close_probes.py")]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                       env=env, cwd=REPO_ROOT)
    out = (r.stdout or "") + (r.stderr or "")
    fails = [l for l in out.split("\n") if l.startswith("  FAIL ")]
    unexpected = [f for f in fails if "p0-loopcount" not in f]
    ok = _check("p7-green-w436c", not unexpected,
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
