#!/usr/bin/env python3
"""Wave-420 lane 3 close battery: F1590-F1599 CLOSED.

F1590: optgroup prose-shaped text (provenance seam) --
  `<select><optgroup>the budget spreadsheet requires review by friday afternoon</optgroup></select>`.
  Closed by `_has_hidden_optgroup_text` in gov/instruction_provenance.py.
F1591: replace arrow-function replacer -- `S.replace(/./g,(m)=>m)`.
  Closed by extended `_js_f1558_stmt_decode`.
F1592: replace /./gsu flags -- `S.replace(/./gsu,function(m){return m;})`.
  Closed by extended `_js_f1558_stmt_decode`.
F1593: map(String) join() default separator --
  `D.join().split(',').map(Number)`.
  Closed by extended `_js_f1559_stmt_decode`.
F1594: map(String) arrow Number -- `.map(x=>Number(x))`.
  Closed by extended `_js_f1559_stmt_decode`.
F1595: Object.assign(new Array(),C) --
  Closed by extended `_js_f1560_stmt_decode`.
F1596: spread-call unused param -- `function g(x){...}`.
  Closed by extended `_js_f1561_stmt_decode`.
F1597: spread-call function expression -- `var g=function(){...};`.
  Closed by extended `_js_f1561_stmt_decode`.
F1598: flat(0.0) -- Closed by extended `_js_f1562_stmt_decode`.
F1599: flat(-0) -- Closed by extended `_js_f1562_stmt_decode`.

No new dispatch loops (extensions of existing hooks); N_STMTDEC_LOOPS=92.
Node-exact on all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; other opens still MISS/QUIET.

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
from gov.instruction_provenance import instruction_shaped

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


def _flagged(payload):
    """True if instruction_shaped flags the payload (in-process)."""
    try:
        return bool(instruction_shaped(payload))
    except Exception:
        return False


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
    # F1591: replace arrow replacer
    ("f1591",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,(m)=>m);var RESULT=T;"),
    # F1592: replace /./gsu
    ("f1592",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./gsu,function(m){return m;});var RESULT=T;"),
    # F1593: join() default
    ("f1593",
     "var C={I};var D=C.map(String);var T=D.join().split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1594: arrow Number
    ("f1594",
     "var C={I};var D=C.map(String);var T=D.join(',').split(',').map(x=>Number(x));var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1595: new Array()
    ("f1595",
     "var C={I};var D=Object.assign(new Array(),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1596: unused param
    ("f1596",
     "var C={I};function g(x){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    # F1597: function expression
    ("f1597",
     "var C={I};var g=function(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');};var RESULT=g(...C);"),
    # F1598: flat(0.0)
    ("f1598",
     "var C={I};var D=C.flat(0.0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1599: flat(-0)
    ("f1599",
     "var C={I};var D=C.flat(-0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
]


@_t
def test_p1_filed_shapes():
    """All 9 filed decoder shapes BLOCK (x2 sizes)."""
    bad = []
    for name, tmpl in _FILED:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_FILED) * 2
    return (not bad), "filed=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


@_t
def test_p1b_f1590_provenance():
    """F1590 optgroup text FLAGs at the provenance seam."""
    payload = "<select><optgroup>the budget spreadsheet requires review by friday afternoon</optgroup></select>"
    ok = _flagged(payload)
    return ok, "f1590 optgroup %s" % ("FLAG" if ok else "QUIET")


# ---------------- p2: generalizations ----------------

_GEN = [
    # F1591: arrow with spaces
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g, (m) => m);var RESULT=T;",
    # F1592: /./gi flags
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./gi,function(m){return m;});var RESULT=T;",
    # F1593: let, renamed
    "let C={I};let D=C.map(String);let T=D.join().split(',').map(Number);let RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1594: paren arrow
    "var C={I};var D=C.map(String);var T=D.join(',').split(',').map((x)=>Number(x));var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1595: const, renamed
    "const C={I};const D=Object.assign(new Array(),C);const RESULT=D.map(c=>String.fromCharCode(c)).join('');",
    # F1596: let function, different param name
    "var C={I};function h(unused){var B=Array.prototype.slice.call(arguments);return B.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=h(...C);",
    # F1597: const function expression
    "var C={I};const g=function(){var A=Array.prototype.slice.call(arguments);return A.map(c=>String.fromCharCode(c)).join('');};var RESULT=g(...C);",
    # F1598/F1599: const
    "const C={I};const D=C.flat(0.0);const RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
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


@_t
def test_p2b_f1590_generalizations():
    """F1590 generalizations FLAG; option children stay quiet."""
    ok = True
    notes = []
    # direct text with option children present
    p1 = "<select><optgroup>the budget spreadsheet requires review by friday afternoon<option>label one</option></optgroup></select>"
    if not _flagged(p1):
        ok = False
        notes.append("mixed-content MISS")
    # option-only content stays quiet (not our carrier)
    p2 = "<select><optgroup><option>label one</option><option>label two</option></optgroup></select>"
    if _flagged(p2):
        ok = False
        notes.append("option-only FLAG")
    # machine token in optgroup stays quiet
    p3 = "<select><optgroup>abc123</optgroup></select>"
    if _flagged(p3):
        ok = False
        notes.append("machine-token FLAG")
    return ok, "f1590-gen %s" % ("OK" if ok else "; ".join(notes))


# ---------------- p3: fail-closed bounds ----------------

_FAILCLOSED = [
    # F1591: arrow replacer not identity
    ("f1591-nonident",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,(m)=>m+'x');var RESULT=T;"),
    # F1592: regex without g
    ("f1592-nog",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./,(m)=>m);var RESULT=T;"),
    # F1592: regex not /./
    ("f1592-badpattern",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/x/g,function(m){return m;});var RESULT=T;"),
    # F1593: join sep not comma
    ("f1593-badsep",
     "var C={I};var D=C.map(String);var T=D.join(';').split(';').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1594: arrow not Number
    ("f1594-badfn",
     "var C={I};var D=C.map(String);var T=D.join(',').split(',').map(x=>String(x));var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1595: assign target not empty
    ("f1595-nonempty",
     "var C={I};var D=Object.assign(new Array(5),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    # F1596: param named arguments
    ("f1596-argparam",
     "var C={I};function g(arguments){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    # F1596: two params
    ("f1596-twoparam",
     "var C={I};function g(x,y){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    # F1597: expression not function
    ("f1597-notfn",
     "var C={I};var g=42;var RESULT=g;"),
    # F1598/F1599: non-zero depth
    ("f1598-depth05",
     "var C={I};var D=C.flat(0.5);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("f1599-depth1",
     "var C={I};var D=C.flat(1);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
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
    # F1558 (function replacer) still BLOCKs
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;",
    # F1559 (explicit comma) still BLOCKs
    "var C={I};var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1560 ([] target) still BLOCKs
    "var C={I};var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1561 (zero params) still BLOCKs
    "var C={I};function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);",
    # F1562 (flat(0)) still BLOCKs
    "var C={I};var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1563 (concat spread) still BLOCKs
    "var C={I};var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
]


@_t
def test_p4_sibling_pins():
    """Extended hooks' original shapes still BLOCK."""
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
    "<select><optgroup><option>Choose one</option></optgroup></select>",
    "Meeting notes from the team sync on project milestones.",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    bad = []
    for t in _HONEST:
        if _hits(t) or _flagged(t):
            bad.append(t[:40])
    return (not bad), "honest=%d/%d quiet%s" % (
        len(_HONEST) - len(bad), len(_HONEST),
        "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    payload = ("var C=%s;var D=C.flat(0.0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join(''); " % _codes(SECRET_S)) * 200
    t0 = time.time()
    _hits(payload)
    dt = time.time() - t0
    ok = dt < 30.0
    return ok, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

_OTHER_OPENS = [
    # F1570: flatMap "xy" thisArg (lane 1 scope) still MISS
    'var C={I};var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},"xy");var S=E.join(\'\');var RESULT=S;',
    # F1580: search concat pattern (lane 2 scope) still MISS
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xox'+'b');var T=S.slice(K);var RESULT=T;",
    # F1600: flat(false) (lane 4 scope) still MISS
    "var C={I};var D=C.flat(false);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');",
    # F1603: trim EM SPACE direct (lane 4 scope) still MISS
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('\\u2003'+S+'\\u2003').trim();",
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
    """Depth-1: run w419_attack_probes.py with GOV_SKIP_GREEN=1 in child env.

    F1590 pin flips to FLAG (expected -- we closed it).
    F1570-F1589 pins must stay MISS/QUIET; taxonomy pin HELD.
    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return True, "green skipped (GOV_SKIP_GREEN=1)"
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g420l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w419_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        pin_ok = {}
        for line in out.split("\n"):
            m = re.match(r"(pin-ok|PIN-FAIL)\s+(F\d+)", line.strip())
            if m:
                pin_ok[m.group(2)] = (m.group(1) == "pin-ok")
            m2 = re.match(r"(PROV-OK|PROV-FAIL)\s+(F\d+)", line.strip())
            if m2:
                pin_ok[m2.group(2)] = (m2.group(1) == "PROV-OK")
        ok = True
        notes = []
        # F1590: expect FLAG now (closed) -> PROV-FAIL is the flip
        if pin_ok.get("F1590") is False:
            notes.append("F1590 flipped to FLAG")
        else:
            ok = False
            notes.append("F1590 did not flip (pin_ok=%s)" % pin_ok.get("F1590"))
        # others must stay MISS/QUIET (pin-ok)
        stayed = [f for f in
                  ("F1570", "F1571", "F1572", "F1573", "F1575", "F1576",
                   "F1577", "F1578", "F1579", "F1580", "F1581", "F1582",
                   "F1583", "F1584", "F1585", "F1586", "F1587", "F1588",
                   "F1589")
                  if pin_ok.get(f) is True]
        if len(stayed) != 19:
            ok = False
            notes.append("other-miss=%d/19" % len(stayed))
        else:
            notes.append("other-miss=19/19")
        if "tax-ok" not in out:
            ok = False
            notes.append("taxonomy not ok")
        else:
            notes.append("taxonomy ok")
        return ok, "green(w419_attack): " + "; ".join(notes)
    except Exception as e:  # noqa: BLE001
        return False, "green check error: %r" % e
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)


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
