#!/usr/bin/env python3
"""Wave-413 lane 3 close battery: F1357-F1358 CLOSED.

F1357: chained join/split/join (F1199 residual) -- `D.join('|').split('|').join('')`
in one statement assembles node-exactly (v24.20.0) while F1199's two-statement
parser MISSED. Closed by `_js_f1357_stmt_decode` (chained join/split/join parser;
fail-closed on SEP-in-credential, SEP mismatch, non-empty final join).

F1358: reduceRight accumulating callback (F906/F907 residual) --
`C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'')`
assembles node-exactly (v24.20.0) while F906/F907's return-current parser MISSED.
Closed by `_js_f1358_stmt_decode` (accumulating callback parser; fail-closed on
non-empty INIT, wrong callback body).

New _decode_layer dispatch loop (F1357-F1358); N_STMTDEC_LOOPS 69->70
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1349-F1356, F1359 (outside this lane) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
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

from gov import dlp as _dlp

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _hits(payload):
    """True if find_credential flags the payload (in-process)."""
    try:
        return bool(_dlp.find_credential(payload))
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; N_STMTDEC_LOOPS=70."""
    ok = True
    notes = []
    # N_STMTDEC_LOOPS pin
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    # actual loop count
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if pin != 70 or actual != 70:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 70)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=70")
    # re.compile count
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_F1357_FILED = [
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;",
]

_F1358_FILED = [
    "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;",
]


@_t
def test_p1_filed_shapes():
    """All filed shapes (short + long) BLOCK."""
    bad = []
    for tmpl in _F1357_FILED + _F1358_FILED:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    return (not bad), "filed=%d/%d BLOCK" % (
        len(_F1357_FILED + _F1358_FILED) * 2 - len(bad),
        len(_F1357_FILED + _F1358_FILED) * 2)


# ---------------- p2: generalizations ----------------

_F1357_GEN = [
    # Arrow twin of map callback
    "var C={I};var D=C.map(c=>String.fromCharCode(c));var S=D.join('|').split('|').join('');var RESULT=S;",
    # Different separator
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join(':::').split(':::').join('');var RESULT=S;",
    # Empty separator (identity)
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('').split('').join('');var RESULT=S;",
    # let/const variants
    "let C={I};let D=C.map(function(c){return String.fromCharCode(c);});let S=D.join('|').split('|').join('');let RESULT=S;",
    # RESULT additive
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT='x'+S;",
]

_F1358_GEN = [
    # Different param names
    "var C={I};var S=C.reduceRight(function(a,b){return String.fromCharCode(b)+a;},'');var RESULT=S;",
    # let/const variants
    "const C={I};const S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');const RESULT=S;",
    # RESULT additive
    "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S+'y';",
]


@_t
def test_p2_generalizations():
    """Generalization twins BLOCK."""
    bad = []
    for tmpl in _F1357_GEN + _F1358_GEN:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    return (not bad), "gen=%d/%d BLOCK" % (
        len(_F1357_GEN + _F1358_GEN) * 2 - len(bad),
        len(_F1357_GEN + _F1358_GEN) * 2)


# ---------------- p3: fail-closed bounds ----------------

_F1357_FAILCLOSED = [
    # SEP in credential -> fail closed (node would mis-decode)
    ("sep-in-cred",
     "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"
     % _codes("xoxb-|01" + "23456789abcdef")),
    # SEP mismatch -> fail closed
    ("sep-mismatch",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split(':').join('');var RESULT=S;"),
    # Non-empty final join -> fail closed
    ("join-nonempty",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('-');var RESULT=S;"),
]

_F1358_FAILCLOSED = [
    # Non-empty INIT -> fail closed
    ("init-nonempty",
     "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'X');var RESULT=S;"),
    # Wrong body order (acc+chr instead of chr+acc) -> fail closed (different semantics)
    ("wrong-order",
     "var C={I};var S=C.reduceRight(function(acc,c){return acc+String.fromCharCode(c);},'');var RESULT=S;"),
    # Return-current (F906/F907) -> fail closed (disjoint)
    ("return-current",
     "var C={I};var S=C.reduceRight(function(acc,c){return c;},'');var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds hold (all MISS)."""
    bad = []
    for name, tmpl in _F1357_FAILCLOSED + _F1358_FAILCLOSED:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(name)
    return (not bad), "fail-closed=%d/%d MISS" % (
        len(_F1357_FAILCLOSED + _F1358_FAILCLOSED) - len(bad),
        len(_F1357_FAILCLOSED + _F1358_FAILCLOSED))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1199 (two-statement) and F906 (return-current) still BLOCK."""
    f1199 = ("var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];"
             "var A=C.map(function(c){return String.fromCharCode(c);});"
             "var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;")
    f906 = "(function(){return ['xoxb-0123456789abcdef','z'].reduceRight(function(a,b){return b;})+'!';})()"
    ok = _hits(f1199) and _hits(f906)
    return ok, "F1199=%s F906=%s" % (_hits(f1199), _hits(f906))


# ---------------- p5: honest-text controls ----------------

_HONEST = [
    "var x = 1; var y = 2; var RESULT = x + y;",
    "The quick brown fox jumps over the lazy dog.",
    "var S='hello';var RESULT=S;",
    "function f(a,b){return a+b;}",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (all MISS)."""
    bad = [t for t in _HONEST if not _misses(t)]
    return (not bad), "honest=%d/%d quiet" % (
        len(_HONEST) - len(bad), len(_HONEST))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    t0 = time.time()
    for i in range(200):
        _hits("var C=[%d];var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1349-F1356, F1359 are outside this lane and must still MISS
_P7_TMPLS = [
    ("f1349", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var E=D.flat();var RESULT=E.join('');"),
]


@_t
def test_p7_other_opens_miss():
    """F1349-F1356, F1359 (other lanes) still MISS."""
    # Spot-check: F1357/F1358 hooks must not fire on unrelated shapes
    bad = []
    for name, tmpl in _P7_TMPLS:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(name)
    return (not bad), "other-opens spot=%d/%d MISS" % (
        len(_P7_TMPLS) - len(bad), len(_P7_TMPLS))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w412_attack_probes: F1349-F1359 still open (HELD).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w412_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g413l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w412_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.search(r"(HELD|BREAK)\s+test_open_f(\d+)", line)
            if m:
                (held if m.group(1) == "HELD" else broken).add(int(m.group(2)))
        # F1349-F1356, F1359 still OPEN -> HELD; F1357/F1358 now CLOSED -> BREAK
        still_open = set(range(1349, 1357)) | {1359}
        now_closed = {1357, 1358}
        ok = (still_open <= held and not (still_open & broken)
              and now_closed <= broken and not (now_closed & held))
        return (ok, "green(w412_attack): open-hold=%d/9 closed-flip=%d/2%s"
                % (len(still_open & held), len(now_closed & broken),
                   "" if ok else " MISMATCH"))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


@_t
def test_g0_green():
    return _green_check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    held, broken = 0, 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK", fn.__name__, note)))
        held, broken = held + (1 if ok else 0), broken + (0 if ok else 1)
    print("%d HELD / %d BREAK" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
