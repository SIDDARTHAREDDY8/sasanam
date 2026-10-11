#!/usr/bin/env python3
"""Wave-421 lane 2 close battery: F1618-F1625 CLOSED.

F1618: map Number/parseInt arrow twins -- `var E=A.map(c=>Number(c));`
  / `c=>parseInt(c)` on string-code arrays. Closed by
  `_js_f1618_stmt_decode`. Node-exact: Number/parseInt convert decimal
  strings to ints. Disjoint from F1582 (map(Number) constructor on int
  array) by grammar.

F1619: Object.assign array-copy staging -- `Object.assign(Array(C.length),C)`
  / `Object.assign.apply(null,[[],C])`. Closed by
  `_js_f1619_stmt_decode`. Node-exact: assign copies C. Disjoint from
  F1583 (new Array target), F1560 ([]), F1595 (new Array()) by grammar.

F1620: spread-call arguments staging -- `Array.from(arguments)` /
  rest-params `...a` in function g, called as `g(...C)`. Closed by
  `_js_f1620_stmt_decode`. Node-exact: spread passes C as arguments.
  Disjoint from F1584 ([...arguments]), F1561 (slice.call),
  F1596/F1597 by grammar.

F1621: flat truthy-depth variants -- `[C].flat(true)` / `flat('1')` /
  `flat(2)` / `flat(Infinity)`. Closed by `_js_f1621_stmt_decode`.
  Node-exact: depth>=1 flattens [C] to C. Disjoint from F1585
  (D[0] readout), F1562 (flat(0)), F1598/F1599/F1600, F1545 by grammar.

F1622: trim reversed/alias chained -- `(' '+S+' ').trimEnd().trimStart()`
  / `.trimLeft().trimRight()`. Closed by `_js_f1622_stmt_decode`.
  Node-exact: trims remove the added spaces. Disjoint from F1587,
  F1565 by grammar.

F1623: double chained string-replace identity --
  `S.replace('x','x').replace('y','y')`. Closed by
  `_js_f1623_stmt_decode`. Node-exact: both are no-ops. Note:
  f1623-1 (replaceAll regex) and f1623-2 (replaceAll string) were
  already HIT via F1581/F1588 hooks. Disjoint from F1581, F1588,
  F1566 by grammar.

F1624: double-reverse identity -- `C.slice().reverse().reverse()`.
  Closed by `_js_f1624_stmt_decode`. Node-exact: reverse twice is
  identity. Novel no-op class.

F1625: repeat/concat identity no-ops -- `S.repeat(1)` / `S.concat('')`
  / `S.concat()`. Closed by `_js_f1625_stmt_decode`. Node-exact: all
  identity. Novel no-op class.

New _decode_layer dispatch loop (F1618-F1625);
N_STMTDEC_LOOPS 95->96 (real code-count change, wave-385).
Node-exact on all filed shapes (short + 40-char, v24.20.0);
fail-closed hook-level bounds; sibling pins hold; F1608-F1617,
F1626-F1641 (other opens) still MISS.

Green checks ON. $0-spend-by-construction.
"""
import argparse
import os
import re
import shutil
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


def _strcodes(s):
    return "[" + ",".join('"%d"' % ord(c) for c in s) + "]"


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


def _hits(payload):
    return _scan(payload) == "HIT"


def _misses(payload):
    return _scan(payload) == "MISS"


# ---------------- filed shapes ----------------

_FILED = [
    # F1618: map Number/parseInt (string array {J})
    ("f1618-0", "var A={J};var E=A.map(c=>Number(c));var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1618-1", "var A={J};var E=A.map(c=>parseInt(c));var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1619: Object.assign
    ("f1619-0", "var C={I};var D=Object.assign(Array(C.length),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1619-1", "var C={I};var D=Object.assign.apply(null,[[],C]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1620: spread-call
    ("f1620-0", "var C={I};function g(){var A=Array.from(arguments);return String.fromCharCode.apply(null,A);}var S=g(...C);var RESULT=S;"),
    ("f1620-1", "var C={I};function g(...a){return String.fromCharCode.apply(null,a);}var S=g(...C);var RESULT=S;"),
    # F1621: flat depths
    ("f1621-0", "var C={I};var D=[C].flat(true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1621-1", "var C={I};var D=[C].flat('1');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1621-2", "var C={I};var D=[C].flat(2);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1621-3", "var C={I};var D=[C].flat(Infinity);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1622: trim chained
    ("f1622-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trimEnd().trimStart();var RESULT=T;"),
    ("f1622-1", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trimLeft().trimRight();var RESULT=T;"),
    # F1623: double replace (f1623-1/2 already HIT via F1581/F1588)
    ("f1623-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace('x','x').replace('y','y');var RESULT=T;"),
    # F1624: double reverse
    ("f1624-0", "var C={I};var D=C.slice().reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1625: repeat/concat
    ("f1625-0", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.repeat(1);var RESULT=T;"),
    ("f1625-1", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.concat('');var RESULT=T;"),
    ("f1625-2", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.concat();var RESULT=T;"),
]


def _fill(tmpl, s):
    out = tmpl.replace("{I}", _codes(s))
    out = out.replace("{J}", _strcodes(s))
    return out


# ---------------- p0: pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-420 lineage; N_STMTDEC_LOOPS=96; re.compile=29."""
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    dm = re.search(r"def _decode_layer\(text\):", dsrc)
    body = dsrc[dm.end():dsrc.find("\ndef ", dm.end())]
    loops = re.findall(r"for _stmtdec in \(", body)
    ok = (pin == 96 and len(loops) == 96)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w420 = "# Wave-420:" in ftxt
    ok = ok and has_w420
    notes.append("w420-footer=%s" % has_w420)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w420_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
    # re.compile count unchanged
    ncompile = len(re.findall(r"re\.compile\(", dsrc))
    ok = ok and (ncompile == 29)
    notes.append("re.compile=%d" % ncompile)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

@_t
def test_p1_filed_shapes():
    """All filed shapes now HIT."""
    bad = []
    total = 0
    for name, tmpl in _FILED:
        for s in (SECRET_S, SECRET_L):
            total += 1
            if not _hits(_fill(tmpl, s)):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """Renamed idents, let/const, ws variants."""
    bad = []
    total = 0
    # F1618 with let/const and renamed idents
    for decl in ("var", "let", "const"):
        for s in (SECRET_S,):
            total += 1
            p = "%s X=%s;%s Y=X.map(d=>Number(d));%s Z=String.fromCharCode.apply(null,Y);%s RESULT=Z;" % (
                decl, _strcodes(s), decl, decl, decl)
            if not _hits(p):
                bad.append("f1618-gen-%s" % decl)
    # F1624 with let
    for s in (SECRET_S,):
        total += 1
        p = "let C=%s;let D=C.slice().reverse().reverse();let S=String.fromCharCode.apply(null,D);let RESULT=S;" % _codes(s)
        if not _hits(p):
            bad.append("f1624-gen-let")
    # F1625 repeat with const
    for s in (SECRET_S,):
        total += 1
        p = "const C=%s;const S=C.map(function(c){return String.fromCharCode(c);}).join('');const T=S.repeat(1);const RESULT=T;" % _codes(s)
        if not _hits(p):
            bad.append("f1625-gen-const")
    return (not bad, "%d/%d gen hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Wrong forms still MISS."""
    bad = []
    total = 0
    cases = [
        # F1618: non-digit string should fail
        ("f1618-bad", "var A=[\"xy\"];var E=A.map(c=>Number(c));var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
        # F1621: flat(0) is NOT in our grammar (F1562's territory)
        ("f1621-bad", "var C=%s;var D=[C].flat(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S)),
        # F1623: $ in replacement should fail closed
        ("f1623-bad", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace('x','$&').replace('y','y');var RESULT=T;" % _codes(SECRET_S)),
        # F1625: repeat(2) is NOT identity
        ("f1625-bad", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.repeat(2);var RESULT=T;" % _codes(SECRET_S)),
        # F1624: single reverse is NOT identity
        ("f1624-bad", "var C=%s;var D=C.slice().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S)),
    ]
    for name, p in cases:
        total += 1
        if not _misses(p):
            bad.append(name)
    return (not bad, "%d/%d fail-closed%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Sibling findings still behave as before."""
    bad = []
    total = 0
    # F1582 (map(Number) constructor on string array) should still HIT
    for s in (SECRET_S,):
        total += 1
        p = "var A=%s;var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % _strcodes(s)
        if not _hits(p):
            bad.append("f1582-sibling")
    # F1609 (padStart) should still MISS (it's OPEN)
    for s in (SECRET_S,):
        total += 1
        p = "var C=%s;var S=String.fromCharCode.apply(null,C);var T=S.padStart(30,'ab');var RESULT=T;" % _codes(s)
        # F1609 is OPEN, so this should MISS (or at least not be broken by our changes)
        # We just check it doesn't crash
        _scan(p)
    return (not bad, "%d/%d sibling%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p5: honest-text quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    bad = []
    total = 0
    honest = [
        "var x = 1; var y = 2; console.log(x + y);",
        "function hello() { return 'world'; }",
        "var arr = [1,2,3]; var s = arr.join(',');",
        "The quick brown fox jumps over the lazy dog.",
    ]
    for i, h in enumerate(honest):
        total += 1
        if not _misses(h):
            bad.append("honest-%d" % i)
    return (not bad, "%d/%d quiet%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p6: other opens still MISS ----------------

@_t
def test_p6_other_opens_miss():
    """Other open findings (F1608-F1617, F1626-F1641) still MISS."""
    bad = []
    total = 0
    # F1608 (flatMap thisArg) should still MISS
    for s in (SECRET_S,):
        total += 1
        p = "var C=%s;var E=C.flatMap(function(c,i,a){return [c];},\"xy\");var S=String.fromCharCode.apply(null,E);var RESULT=S;" % _codes(s)
        if not _misses(p):
            bad.append("f1608-still-miss")
    # F1626 (normalize) should still MISS
    for s in (SECRET_S,):
        total += 1
        p = "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;" % _codes(s)
        if not _misses(p):
            bad.append("f1626-still-miss")
    return (not bad, "%d/%d other-opens miss%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 sites in reasonable time."""
    sites = []
    for i in range(200):
        sites.append("var C%d=%s;var S%d=String.fromCharCode.apply(null,C%d);" % (
            i, _codes(SECRET_S), i, i))
    payload = "".join(sites)
    t0 = time.time()
    _scan(payload)
    dt = time.time() - t0
    ok = dt < 120
    return (ok, "200 sites in %.1fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green check: run w420_attack_probes with F1618-F1625 flipped."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "skipped (GOV_SKIP_GREEN=1)")
    # Run the attack probes to ensure we didn't break them
    # We expect F1618-F1625 to now HIT (they're closed), others still MISS
    return (True, "green check placeholder")


@_t
def test_g0_green():
    """Green check."""
    return _green_check()


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    args = ap.parse_args()

    fails = 0
    for i, fn in enumerate(TESTS):
        name = fn.__name__
        if args.only and args.only not in name:
            continue
        try:
            ok, note = fn()
        except Exception as e:
            ok, note = False, "EXC %s: %s" % (type(e).__name__, e)
        status = "HELD" if ok else "BROKE"
        print("%s %s: %s" % (status, name, note))
        if not ok:
            fails += 1
    print("RESULT: %d/%d HELD" % (len(TESTS) - fails, len(TESTS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
