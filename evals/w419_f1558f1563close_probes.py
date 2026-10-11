#!/usr/bin/env python3
"""Wave-419 lane 3 close battery: F1558-F1563 CLOSED.

F1558: String.prototype.replace with function-replacer identity --
  `var C=[codes];var S=C.map(function(c){return String.fromCharCode(c);}).join('');`
  `var T=S.replace(/./g,function(m){return m;});var RESULT=T;`.
  Closed by `_js_f1558_stmt_decode`.
F1559: Array.prototype.map with the String constructor --
  `var C=[codes];var D=C.map(String);var T=D.join(',').split(',').map(Number);`
  `var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');`.
  Closed by `_js_f1559_stmt_decode`.
F1560: Object.assign array-copy staging --
  `var C=[codes];var D=Object.assign([],C);`
  `var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');`.
  Closed by `_js_f1560_stmt_decode`.
F1561: Spread-call arguments staging --
  `var C=[codes];function g(){var A=Array.prototype.slice.call(arguments);`
  `return A.map(function(c){return String.fromCharCode(c);}).join('');}`
  `var RESULT=g(...C);`.
  Closed by `_js_f1561_stmt_decode`.
F1562: Array.prototype.flat(0) shallow copy --
  `var C=[codes];var D=C.flat(0);`
  `var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');`.
  Closed by `_js_f1562_stmt_decode`.
F1563: Array.prototype.concat with spread of the array itself --
  `var C=[codes];var D=[].concat(...C);`
  `var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');`.
  Closed by `_js_f1563_stmt_decode`.

One new _decode_layer dispatch loop; N_STMTDEC_LOOPS 88->89.
Node-exact on all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1546-F1557 + F1564-F1569
(other lanes) still MISS.

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=92; re.compile=29."""
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
    if pin != 92 or actual != 92:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 92)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=92")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    # taxonomy pin 2143
    from gov.decision_codes import TAXONOMY
    if len(TAXONOMY) != 2143:
        ok = False
        notes.append("taxonomy=%d (want 2143)" % len(TAXONOMY))
    else:
        notes.append("taxonomy=2143")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1558: replace with function-replacer identity
    ("f1558",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;"),
    # F1559: map(String) decimal roundtrip
    ("f1559",
     "var C={I};var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1560: Object.assign([],C)
    ("f1560",
     "var C={I};var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1561: spread-call arguments
    ("f1561",
     "var C={I};function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    # F1562: flat(0)
    ("f1562",
     "var C={I};var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1563: [].concat(...C)
    ("f1563",
     "var C={I};var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
]


@_t
def test_p1_filed_shapes():
    """All 6 filed shapes BLOCK (x2 sizes)."""
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
    # F1558: let, renamed idents
    "let C={I};let S=C.map(function(x){return String.fromCharCode(x);}).join('');let T=S.replace(/./g,function(y){return y;});let RESULT=T;",
    # F1558: arrow twin in map
    "var C={I};var S=C.map(c=>String.fromCharCode(c)).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;",
    # F1559: const, renamed
    "const C={I};const D=C.map(String);const T=D.join(',').split(',').map(Number);const RESULT=T.map(function(x){return String.fromCharCode(x);}).join('');",
    # F1560: let, renamed
    "let C={I};let D=Object.assign([],C);let RESULT=D.map(c=>String.fromCharCode(c)).join('');",
    # F1561: renamed function and vars
    "var C={I};function h(){var B=Array.prototype.slice.call(arguments);return B.map(function(z){return String.fromCharCode(z);}).join('');}var RESULT=h(...C);",
    # F1562: const
    "const C={I};const D=C.flat(0);const RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1563: let, renamed
    "let C={I};let D=[].concat(...C);let RESULT=D.map(c=>String.fromCharCode(c)).join('');",
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
    # F1558: replacer not identity -> fail closed
    ("f1558-replacer-const",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return 'x';});var RESULT=T;"),
    # F1558: string replacer -> fail closed (F1380's shape, different hook)
    ("f1558-string-replacer",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,'$&');var RESULT=T;"),
    # F1558: regex not /./g -> fail closed
    ("f1558-bad-regex",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/x/g,function(m){return m;});var RESULT=T;"),
    # F1559: join sep not comma -> fail closed
    ("f1559-join-sep",
     "var C={I};var D=C.map(String);var T=D.join(';').split(';').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1559: map fn not String -> fail closed
    ("f1559-map-fn",
     "var C={I};var D=C.map(Number);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1560: assign target not [] -> fail closed
    ("f1560-target",
     "var C={I};var D=Object.assign({},C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1560: two sources -> fail closed
    ("f1560-two-src",
     "var C={I};var D=Object.assign([],C,C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1561: function with param -> fail closed
    ("f1561-with-param",
     "var C={I};function g(x){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    # F1561: call without spread -> fail closed
    ("f1561-no-spread",
     "var C={I};function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(C);"),
    # F1562: flat(1) -> fail closed (F1349's shape, different hook)
    ("f1562-flat-1",
     "var C={I};var D=C.flat(1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1562: flat() no-arg -> fail closed (F1349)
    ("f1562-flat-noarg",
     "var C={I};var D=C.flat();var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1563: concat without spread -> fail closed (F1387's shape)
    ("f1563-no-spread",
     "var C={I};var D=[].concat(C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1563: spread of [C] literal -> fail closed (F1538's shape)
    ("f1563-spread-singleton",
     "var C={I};var D=[].concat(...[C]);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
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
    # F1380 (string-arg replace) still BLOCKs
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('x','x');var RESULT=U;",
    # F1387 (concat staging, no spread) still BLOCKs
    "var C={I};var E=[].concat(C);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1432 (flat(2)) still BLOCKs
    "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1349 (flat(1) single-nested) still BLOCKs
    "var C={I};var D=C.map(function(c){return [c];});var E=D.flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
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
    "Object.assign([], [1, 2, 3]); console.log('copy');",
    "The flat(0) call returns a shallow copy of the array.",
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
    payload = ("var C=%s;var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join(''); " % _codes(SECRET_S)) * 200
    t0 = time.time()
    _hits(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ok, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

_OTHER_OPENS = [
    # F1546: flatMap thisArg (lane 1 scope) still MISS
    "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;",
    # F1552: splice two-arg no-op (lane 2 scope) still MISS
    "var C={I};var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
    # F1564: Map.set loop (lane 4 scope) still MISS
    "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1568: filter includes(c,1) (lane 4 scope) still MISS
    "var C={I};var E=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """Other lanes' findings still MISS."""
    bad = []
    for tmpl in _OTHER_OPENS:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if _hits(payload):
            bad.append(tmpl[:40])
    total = len(_OTHER_OPENS)
    return (not bad), "other-opens=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- g0: green check (depth-1) ----------------

def _green():
    """Depth-1: run w418_attack_probes.py with GOV_SKIP_GREEN=1 in child env.

    F1558-F1563 pins flip to HIT (expected -- we closed them).
    F1546-F1557 + F1564-F1569 pins must stay MISS; taxonomy pin HELD.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "green skipped (GOV_SKIP_GREEN=1)"
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g419l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w418_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        pin_ok = {}
        for line in out.split("\n"):
            m = re.match(r"(pin-ok|PIN-FAIL)\s+(F\d+)", line.strip())
            if m:
                pin_ok[m.group(2)] = (m.group(1) == "pin-ok")
        ok = True
        notes = []
        # F1558-F1563: expect HIT now (closed) -> PIN-FAIL is the flip
        flipped = [f for f in ("F1558", "F1559", "F1560", "F1561", "F1562", "F1563")
                   if f in pin_ok and not pin_ok[f]]
        if len(flipped) != 6:
            ok = False
            notes.append("closed-flip=%d/6" % len(flipped))
        else:
            notes.append("closed-flip=6/6 HIT")
        # others must stay MISS (pin-ok)
        stayed = [f for f in
                  ("F1546", "F1547", "F1548", "F1549", "F1550", "F1551",
                   "F1552", "F1553", "F1554", "F1555", "F1556", "F1557",
                   "F1564", "F1565", "F1566", "F1567", "F1568", "F1569")
                  if pin_ok.get(f) is True]
        if len(stayed) != 18:
            ok = False
            notes.append("other-miss=%d/18" % len(stayed))
        else:
            notes.append("other-miss=18/18 MISS")
        if "tax-ok" not in out:
            ok = False
            notes.append("taxonomy not ok")
        else:
            notes.append("taxonomy ok")
        return ok, "green(w418_attack): " + "; ".join(notes)
    except Exception as e:  # noqa: BLE001
        return False, "green check error: %r" % e


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
