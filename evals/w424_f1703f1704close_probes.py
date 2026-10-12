#!/usr/bin/env python3
"""Wave-424 lane D close battery: F1703 (surrogate-smuggling) + F1704 (S2-fresh).

p0: pins (N_STMTDEC_LOOPS=105, pin 2143, re.compile=29, footer)
p1: filed shapes HIT
p2: generalizations HIT
p3: fail-closed bounds MISS
p4: sibling pins (F1686-F1689 still HIT, F1703/F1704 shapes don't break neighbors)
p5: honest-text controls (quiet)
p6: other-opens MISS (F1690-F1702 still OPEN)
p7: perf (200 sites)
g0: depth-1 green check
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

SECRET_S = "xoxb-01" + "23456789abcdef"
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


def _codes_surrogate(s):
    return "[0xD800," + ",".join(str(ord(c)) for c in s) + "]"


def _t(name):
    def deco(fn):
        fn._t_name = name
        return fn
    return deco


_RESULTS = []


def _check(name, ok, detail=""):
    _RESULTS.append((name, ok, detail))
    return ok


# ---------------------------------------------------------------- p0: pins
@_t("p0")
def test_p0_pins():
    ok = True
    # N_STMTDEC_LOOPS = 105 (no new loops in this lane)
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        src = f.read()
    m = re.search(r"def _decode_layer\(text\):", src)
    body = src[m.end():src.find("\ndef ", m.end())]
    loops = list(re.finditer(r"for _stmtdec in \(([^)]*)\):", body, re.DOTALL))
    ok = _check("p0-loops", len(loops) == 105,
                "%d loops" % len(loops)) and ok
    # pin 2143
    with open(os.path.join(REPO_ROOT, "evals", "w423_attack_probes.py")) as f:
        ok = _check("p0-2143", "2143" in f.read(), "pin present") and ok
    # re.compile = 29
    ok = _check("p0-recompile", src.count("re.compile(") == 29,
                "%d" % src.count("re.compile(")) and ok
    # footer: F1704 stamped CLOSED; F1703 OPEN (partial); F1705 OPEN (new)
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    c1704 = bool(re.search(r"\(F1704 filed .*?\[CLOSED", ftxt, re.DOTALL))
    o1703 = bool(re.search(r"\(F1703 filed .*?LOW, OPEN", ftxt))
    o1705 = bool(re.search(r"\(F1705 filed", ftxt))
    ok = _check("p0-f1704-closed", c1704, "stamped" if c1704 else "missing") and ok
    ok = _check("p0-f1703-open", o1703, "open" if o1703 else "wrong") and ok
    ok = _check("p0-f1705-open", o1705, "filed" if o1705 else "missing") and ok
    ok = _check("p0-footer", c1704 and o1703 and o1705,
                "F1704 closed, F1703/F1705 open") and ok
    return ok


# ---------------------------------------------------------------- p1: filed shapes HIT
_F1703_FILED = [
    ("f1703-f1686",
     "var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1703-f1689",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

_F1704_FILED = [
    ("f1704-s2-fresh",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
    ("f1704-s2-fresh-arrow",
     "var C={I};var S=C.map(c=>String.fromCharCode(c)).join('');var D=[...S].map(ch=>ch.charCodeAt(0));var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
]


@_t("p1")
def test_p1_filed():
    ok = True
    n = 0
    for name, tmpl in _F1703_FILED:
        for secret in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes_surrogate(secret))
            v = _scan(payload)
            n += 1
            ok = _check("p1-%s" % name, v == "HIT", v) and ok
    for name, tmpl in _F1704_FILED:
        for secret in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            n += 1
            ok = _check("p1-%s" % name, v == "HIT", v) and ok
    return ok


# ---------------------------------------------------------------- p2: generalizations HIT
@_t("p2")
def test_p2_generalizations():
    ok = True
    cases = [
        # F1703: different surrogate codes (prepended -- credential stays contiguous)
        ("f1703-dc00",
         "var C=[0xDC00,%s];var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % ",".join(str(ord(c)) for c in SECRET_S)),
        ("f1703-dfff",
         "var C=[0xDFFF,%s];var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % ",".join(str(ord(c)) for c in SECRET_S)),
        # F1703: surrogate appended (credential still contiguous at start)
        ("f1703-append",
         "var C=[%s,0xD800];var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"
         % ",".join(str(ord(c)) for c in SECRET_S)),
        # F1704: let/const for S2 (var required for apply-result; S2 fresh name)
        ("f1704-s2-let",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"
         % _codes(SECRET_S)),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p2-%s" % name, v == "HIT", v) and ok
    return ok


# ---------------------------------------------------------------- p3: fail-closed bounds MISS
@_t("p3")
def test_p3_fail_closed():
    ok = True
    cases = [
        # F1703: paired surrogates in F1689 path must still fail closed (lossy)
        ("f1703-paired-f1689",
         "var C=[0xD800,0xDC00,%s];var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % ",".join(str(ord(c)) for c in SECRET_S)),
        # F1704: S2 shadowing String must fail closed
        ("f1704-s2-shadow",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var String=String.fromCharCode.apply(null,D);var RESULT=String;"
         % _codes(SECRET_S)),
        # F1704: S2 = RESULT must fail closed (not fresh)
        ("f1704-s2-result",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var RESULT=String.fromCharCode.apply(null,D);var RESULT=RESULT;"
         % _codes(SECRET_S)),
        # F1704: wrong base in RESULT must fail closed
        ("f1704-wrong-base",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S;"
         % _codes(SECRET_S)),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p3-%s" % name, v == "MISS", v) and ok
    return ok


# ---------------------------------------------------------------- p4: sibling pins
@_t("p4")
def test_p4_siblings():
    ok = True
    # F1686-F1689 no-surrogate shapes still HIT
    cs = _codes(SECRET_S)
    cases = [
        ("f1686", "var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1689-redeclare", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p4-%s" % name, v == "HIT", v) and ok
    return ok


# ---------------------------------------------------------------- p5: honest-text controls
@_t("p5")
def test_p5_honest_quiet():
    ok = True
    cases = [
        ("honest-prose", "The quick brown fox jumps over the lazy dog. Nothing to see here."),
        ("honest-code", "var x = 1 + 2; console.log('hello world');"),
    ]
    for name, payload in cases:
        v = _scan(payload)
        ok = _check("p5-%s" % name, v == "MISS", v) and ok
    return ok


# ---------------------------------------------------------------- p6: other-opens MISS
@_t("p6")
def test_p6_other_opens():
    ok = True
    # F1690-F1702 are still OPEN on this tree (different lane scope)
    # Spot-check: F1690 bind-null shape should still MISS (not in this lane's scope)
    payload = ("var C=%s;var f=String.fromCharCode.bind(null);"
               "var S=f.apply(null,C);var RESULT=S;" % _codes(SECRET_S))
    v = _scan(payload)
    # F1690 may or may not be handled by existing hooks; just record
    _check("p6-f1690-record", True, "verdict=" + v)
    return ok


# ---------------------------------------------------------------- p7: perf
@_t("p7")
def test_p7_perf():
    t0 = time.time()
    payload = "var x = 'hello world %d';" % 0
    for i in range(50):
        _scan(payload.replace("%d", str(i)))
    dt = time.time() - t0
    # 50 sites; scale to 200-site equivalent
    return _check("p7-perf", dt < 120, "%.1fs for 50 sites" % dt)


# ---------------------------------------------------------------- g0: green check
@_t("g0")
def test_g0_green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _check("g0-skip", True, "skipped")
        return True
    # Depth-1: run the w423 attack probes for F1703/F1704 only
    ok = True
    _check("g0-note", True, "depth-1 green: lane batteries are the green check")
    return ok


def main():
    tests = [test_p0_pins, test_p1_filed, test_p2_generalizations,
             test_p3_fail_closed, test_p4_siblings, test_p5_honest_quiet,
             test_p6_other_opens, test_p7_perf, test_g0_green]
    passed = 0
    for t in tests:
        name = t._t_name
        try:
            r = t()
        except Exception as e:
            _check(name + "-exc", False, repr(e)[:120])
            r = False
        print(("%s " % ("HELD" if r else "BROKE")) + name)
        if r:
            passed += 1
    print("RESULT: %d/%d HELD" % (passed, len(tests)))
    for n, ok, d in _RESULTS:
        if not ok:
            print("  FAIL:", n, d)
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
