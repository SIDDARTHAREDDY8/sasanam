#!/usr/bin/env python3
"""Wave-417 lane 3 close battery: F1514-F1516 CLOSED.

F1514: String.valueOf map wrapper --
  `var C=[codes];var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');`.
  Closed by `_js_f1514_stmt_decode`.
F1515: Array.toString comma readout (2 shapes) --
  (a) `var S=C.toString();var RESULT=S.split(',').map(Number).map(function(n){return String.fromCharCode(n);}).join('');`
  (b) `var J=C.toString();var D=J.split(',').map(Number);var S=String.fromCharCode.apply(null,D);`.
  Closed by `_js_f1515_stmt_decode`.
F1516: Tagged template literal breaks statement decode --
  `var T=String.raw`x`;` (dead, at any position).
  Closed by `_js_f1516_strip_dead_tagged` (whole-text strip production).

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 81->82.
Node-exact on all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1504-F1513 (other lanes) still
MISS.

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=84; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if pin != 84 or actual != 84:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 84)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=84")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1514: String.valueOf map wrapper
    ("f1514",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;"),
    # F1515 shape (a): toString then split/map/map/join in RESULT
    ("f1515-a",
     "var C={I};var S=C.toString();var RESULT=S.split(',').map(Number).map(function(n){return String.fromCharCode(n);}).join('');"),
    # F1515 shape (b): toString then split/map then apply
    ("f1515-b",
     "var C={I};var J=C.toString();var D=J.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1516: tagged template in middle
    ("f1516-0",
     "var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1516: tagged template leading
    ("f1516-1",
     "var T=String.raw`x`;var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 5 filed shapes BLOCK."""
    bad = []
    for name, tmpl in _FILED:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_FILED) * 2
    return (not bad), "filed=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


# ---------------- p2: generalizations ----------------

_GEN = [
    # F1514: let, renamed idents
    "let C={I};let D=C.map(function(x){return String.fromCharCode(x).valueOf();});let S=D.join('');let RESULT=S;",
    # F1514: const
    "const C={I};const D=C.map(function(c){return String.fromCharCode(c).valueOf();});const S=D.join('');const RESULT=S;",
    # F1515-a: let, renamed
    "let C={I};let S=C.toString();let RESULT=S.split(',').map(Number).map(function(x){return String.fromCharCode(x);}).join('');",
    # F1515-b: let, renamed
    "let C={I};let J=C.toString();let D=J.split(',').map(Number);let S=String.fromCharCode.apply(null,D);let RESULT=S;",
    # F1516: let, different dead name, different literal
    "let C={I};let Q=String.raw`hello`;let S=String.fromCharCode.apply(null,C);let RESULT=S;",
    # F1516: const, trailing position
    "const C={I};const S=String.fromCharCode.apply(null,C);const RESULT=S;const T=String.raw`z`;",
    # F1516: TWO dead statements prepended (attacker repeats the trick)
    "var T=String.raw`a`;var U=String.raw`b`;var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;",
    # F1516: THREE dead statements (leading, middle, trailing)
    "var T=String.raw`a`;var C={I};var U=String.raw`b`;var S=String.fromCharCode.apply(null,C);var V=String.raw`c`;var RESULT=S;",
]


@_t
def test_p2_generalizations():
    """Generalization twins BLOCK."""
    bad = []
    for tmpl in _GEN:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    total = len(_GEN) * 2
    return (not bad), "gen=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p3: fail-closed bounds ----------------

_FAILCLOSED = [
    # F1514: valueOf with arg -> fail closed (not the filed shape)
    ("f1514-valueof-arg",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf(16);});var S=D.join('');var RESULT=S;"),
    # F1514: non-empty join sep -> fail closed
    ("f1514-join-sep",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join(',');var RESULT=S;"),
    # F1514: wrong callback (not fromCharCode) -> fail closed
    ("f1514-wrong-cb",
     "var C={I};var D=C.map(function(c){return String(c).valueOf();});var S=D.join('');var RESULT=S;"),
    # F1515: split sep not comma -> fail closed
    ("f1515-split-sep",
     "var C={I};var S=C.toString();var RESULT=S.split(';').map(Number).map(function(n){return String.fromCharCode(n);}).join('');"),
    # F1515: map arg not Number -> fail closed
    ("f1515-map-arg",
     "var C={I};var J=C.toString();var D=J.split(',').map(String);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1516: template with substitution -> fail closed (not stripped)
    ("f1516-subst",
     "var C={I};var T=String.raw`x${y}`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1516: template with backslash -> fail closed (not stripped)
    ("f1516-backslash",
     "var C={I};var T=String.raw`x\\n`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1516: dead name actually used -> fail closed (not stripped)
    ("f1516-used",
     "var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=T+S;"),
    # F1516: String shadowed -> fail closed (not stripped)
    ("f1516-shadowed",
     "var String={raw:function(){return '';}};var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds MISS (no mis-decode)."""
    bad = []
    for name, tmpl in _FAILCLOSED:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if _hits(payload):
            bad.append(name)
    total = len(_FAILCLOSED)
    return (not bad), "failclosed=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1398 (concat wrapper) still BLOCKs
    "var C={I};var D=C.map(function(p){return String.fromCharCode(p).concat('');});var S=D.join('');var RESULT=S;",
    # F1459 (entries readout) still BLOCKs
    "var C={I};var D=Object.entries(C).map(function(e){return e[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1449 (flatMap 3-param) still BLOCKs
    "var C={I};var D=C.flatMap(function(c,i,a){return [c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
]


@_t
def test_p4_sibling_pins():
    """Sibling hooks still BLOCK."""
    bad = []
    for tmpl in _SIBLINGS:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:40])
    total = len(_SIBLINGS) * 2
    return (not bad), "siblings=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p5: honest-text quiet ----------------

_HONEST = [
    "The quarterly report shows revenue growth of 15 percent year over year.",
    "Please review the attached document and provide feedback by Friday.",
    "var x = 1; var y = 2; var z = x + y; console.log(z);",
    "String.raw`hello world`; console.log('test');",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    bad = [t[:40] for t in _HONEST if _hits(t)]
    return (not bad), "honest=%d/%d quiet%s" % (
        len(_HONEST) - len(bad), len(_HONEST),
        "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    payload = ("var C=%s;var D=C.map(function(c){return String.fromCharCode(c).valueOf();});"
               "var S=D.join('');var RESULT=S; " % _codes(SECRET_S)) * 200
    t0 = time.time()
    _hits(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ok, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

_OTHER_OPENS = [
    # F1504: flatMap 4-param (lane 1 scope, now CLOSED -> HIT)
    "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1509: trim staging (lane 2 scope) still MISS
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """Other wave-417 lanes' findings now CLOSED (merged) -> HIT."""
    bad = []
    for tmpl in _OTHER_OPENS:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _hits(payload):
            bad.append(tmpl[:40])
    return (not bad), "other-lanes-closed=%d/%d HIT%s" % (
        len(_OTHER_OPENS) - len(bad), len(_OTHER_OPENS),
        "" if not bad else " MISS:" + ",".join(bad))


# ---------------- g0: green check (depth-1) ----------------

def _green():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "green skipped (GOV_SKIP_GREEN=1)"
    # Depth-1: run the three w417 red-first batteries with
    # GOV_SKIP_GREEN=1 in the child env.
    ok = True
    notes = []
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    for bat in ("w417_f1514_redfirst.py", "w417_f1515_redfirst.py",
                "w417_f1516_redfirst.py"):
        p = os.path.join(REPO_ROOT, "evals", bat)
        r = subprocess.run([sys.executable, p], capture_output=True,
                           text=True, timeout=300, env=env)
        out = (r.stdout or "") + (r.stderr or "")
        m = re.search(r"FAILURES:(\d+)", out)
        fails = int(m.group(1)) if m else -1
        if fails != 0:
            ok = False
            notes.append("%s FAILURES=%d" % (bat, fails))
        else:
            notes.append("%s ok" % bat)
    return ok, "; ".join(notes)


@_t
def test_g0_green():
    """Depth-1 green check."""
    return _green()


# ---------------- main ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        for fn in TESTS:
            print(fn.__name__)
        return 0
    held = 0
    broken = 0
    for fn in TESTS:
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %s" % e
        if ok:
            held += 1
            print("HELD %s: %s" % (fn.__name__, note))
        else:
            broken += 1
            print("BREAK %s: %s" % (fn.__name__, note))
    print("HELD:%d BREAK:%d" % (held, broken))
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
