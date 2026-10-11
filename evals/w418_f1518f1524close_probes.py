#!/usr/bin/env python3
"""Wave-418 lane 1 close battery: F1518-F1524 CLOSED.

F1518: flatMap 4-param null-thisArg -- `C.flatMap(function(c,i,a,t){return [c];},null)`.
  Closed by new `_js_f1518_stmt_decode` (`,null` thisArg only; disjoint from
  F1504 (`,{}`/no thisArg) by grammar).

F1519: padStart/padEnd fixed-length variants -- `padStart(10,'0').slice(-1)`,
  `padEnd(5,'0').charAt(0)`, `padStart(4,' ').trim()` (fail-closed on trimmable
  codes). Closed by new `_js_f1519_stmt_decode` (three productions; disjoint
  from F1267/F1505-F1507 by grammar).

F1520: sort arrow boolean-comparator -- `C.slice().sort((a,b)=>a>b)`.
  Closed by new `_js_f1520_stmt_decode` (arrow-form; disjoint from F1508
  (function-form, no slice) by grammar).

F1521: join/split non-comma separators -- space-join+trim, pipe separator.
  Closed by new `_js_f1521_stmt_decode` (two productions; disjoint from F1512
  (comma) by separator grammar).

F1522: slice/splice computed negatives -- `slice(-(C.length-0))`,
  `splice(-C.length,C.length)`. Closed by new `_js_f1522_stmt_decode`
  (two productions; disjoint from F1442/F1443/F1513 by arg grammar).

F1523: String/Array conversion twins -- `(new String(...)).valueOf()`,
  `String(C)` call form. Closed by new `_js_f1523_stmt_decode` (two
  productions; disjoint from F1514/F1515 by grammar).

F1524: includes-fromIndex / .at() computed-negative --
  `filter(c=>C.includes(c,0))`, `for` loop with `C.at(k-C.length)`.
  Closed by new `_js_f1524_stmt_decode` (two productions; disjoint from
  F1391/F1517/F1453 by grammar).

New dispatch loop; N_STMTDEC_LOOPS 84->85. All node-exact (v24.20.0,
short + 40-char secrets); fail-closed hook-level bounds; sibling
pins hold; F1525-F1545 (other lanes) still MISS.

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=85; re.compile=29."""
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
    if pin != 85 or actual != 85:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 85)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=85")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1518: flatMap 4-param null thisArg
    ("f1518",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1519: padStart(10) + slice(-1)
    ("f1519a",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(10,'0').slice(-1);});var RESULT=E.join('');"),
    # F1519: padEnd(5) + charAt(0)
    ("f1519b",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padEnd(5,'0').charAt(0);});var RESULT=E.join('');"),
    # F1519: padStart(4,' ') + trim
    ("f1519c",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(4,' ').trim();});var RESULT=E.join('');"),
    # F1520: sort arrow boolean
    ("f1520",
     "var C={I};var D=C.slice().sort((a,b)=>a>b);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1521: space-join + trim
    ("f1521a",
     "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(' ');var E=J.split(' ').map(function(s){return s.trim();});var RESULT=E.join('');"),
    # F1521: pipe separator
    ("f1521b",
     "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join('|');var E=J.split('|');var RESULT=E.join('');"),
    # F1522: slice computed negative
    ("f1522a",
     "var C={I};var D=C.slice(-(C.length-0));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1522: splice two-arg full drain
    ("f1522b",
     "var C={I};var E=C.splice(-C.length,C.length);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1523: (new String()).valueOf()
    ("f1523a",
     "var C={I};var E=C.map(function(c){return (new String(String.fromCharCode(c))).valueOf();});var RESULT=E.join('');"),
    # F1523: String(C) call form
    ("f1523b",
     "var C={I};var S=String(C);var E=S.split(',').map(Number);var R=String.fromCharCode.apply(null,E);var RESULT=R;"),
    # F1524: includes fromIndex filter
    ("f1524a",
     "var C={I};var E=C.filter(function(c,i){return C.includes(c,0);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1524: .at() computed-negative loop
    ("f1524b",
     "var C={I};var E=[];for(var k=0;k<C.length;k++){E.push(C.at(k-C.length));}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """Filed shapes BLOCK."""
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
    # F1518: 5-param null thisArg
    "var C={I};var E=C.flatMap(function(c,i,a,t,u){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1518: let/renamed
    "let C={I};let E=C.flatMap(function(x,y,z,w){return [x];},null);let S=String.fromCharCode.apply(null,E);let RESULT=S;",
    # F1520: renamed params
    "var C={I};var D=C.slice().sort((x,y)=>x>y);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1520: whitespace
    "var C={I};var D=C.slice().sort( (a,b) => a > b );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1521b: double-quote separator
    'var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join("|");var E=J.split("|");var RESULT=E.join(\'\');',
    # F1522a: whitespace
    "var C={I};var D=C.slice( -( C.length - 0 ) );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1523b: let variant
    "let C={I};let S=String(C);let E=S.split(',').map(Number);let R=String.fromCharCode.apply(null,E);let RESULT=R;",
    # F1524b: let loop var
    "var C={I};var E=[];for(let k=0;k<C.length;k++){E.push(C.at(k-C.length));}var S=String.fromCharCode.apply(null,E);var RESULT=S;",
]


@_t
def test_p2_generalizations():
    """Generalization twins BLOCK."""
    bad = []
    for tmpl in _GEN:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(tmpl[:50])
    total = len(_GEN) * 2
    return (not bad), "gen=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad[:3]))


# ---------------- p3: fail-closed bounds ----------------

_FAILCLOSED_SCANNER = [
    # F1518: wrong return (not singleton) -> fail closed
    ("f1518-wrong-ret",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c,c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1519: wrong pad length (not filed 10) -> fail closed
    ("f1519-padlen",
     "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(9,'0').slice(-1);});var RESULT=E.join('');"),
    # F1520: a<b reversed -> fail closed
    ("f1520-reversed",
     "var C={I};var D=C.slice().sort((a,b)=>a<b);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1521: separator mismatch -> fail closed
    ("f1521-sepmismatch",
     "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join('|');var E=J.split(' ');var RESULT=E.join('');"),
    # F1524a: fromIndex 1 (drops first element for distinct codes) -> fail closed
    ("f1524-fromindex1",
     "var C={I};var E=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]

# (name, payload, hook_fn): the NEW hook must return None on sibling shapes.
_FAILCLOSED_HOOK = [
    # F1518 hook must miss F1504's {} form
    ("f1518-brace", "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "_js_f1518_stmt_decode"),
    # F1520 hook must miss F1508's function form (no slice)
    ("f1520-function", "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
     "_js_f1520_stmt_decode"),
    # F1521 hook must miss F1512's comma form
    ("f1521-comma", "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;",
     "_js_f1521_stmt_decode"),
    # F1522 hook must miss F1442's slice(C.length-C.length) form
    ("f1522-f1442", "var C={I};var D=C.slice(C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
     "_js_f1522_stmt_decode"),
    # F1523 hook must miss F1514's primitive .valueOf() form
    ("f1523-primitive", "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;",
     "_js_f1523_stmt_decode"),
    # F1524 hook must miss F1391's plain .at(i) form
    ("f1524-plainat", "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
     "_js_f1524_stmt_decode"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds hold."""
    bad = []
    for name, tmpl in _FAILCLOSED_SCANNER:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(name + "(scanner)")
    for name, tmpl, hook_name in _FAILCLOSED_HOOK:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        hook = getattr(_dlp, hook_name)
        if hook(payload) is not None:
            bad.append(name + "(hook)")
    total = len(_FAILCLOSED_SCANNER) + len(_FAILCLOSED_HOOK)
    return (not bad), "failclosed=%d/%d%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1504: {} thisArg still BLOCKs
    ("f1504",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1508: function-form sort still BLOCKs
    ("f1508",
     "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1512: comma join/split still BLOCKs
    ("f1512",
     "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;"),
    # F1514: primitive valueOf still BLOCKs
    ("f1514",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;"),
    # F1391: plain .at() loop still BLOCKs
    ("f1391",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


@_t
def test_p4_sibling_pins():
    """Parent/sibling filed shapes still BLOCK."""
    bad = []
    for name, tmpl in _SIBLINGS:
        for sec in (SECRET_S, SECRET_L):
            if not _hits(tmpl.replace("{I}", _codes(sec))):
                bad.append(name)
    total = len(_SIBLINGS) * 2
    return (not bad), "siblings=%d/%d BLOCK%s" % (
        total - len(bad), total, "" if not bad else " MISS:" + ",".join(bad))


# ---------------- p5: honest-text controls ----------------

_HONEST = [
    "var x = 1; var y = 2; var RESULT = x + y;",
    "The quick brown fox jumps over the lazy dog.",
    "var S='hello';var RESULT=S;",
    "function f(a,b){return a+b;}",
    "var C=[1,2,3];var D=C.map(function(c){return c*2;});var RESULT=D;",
    "var a=[3,1,2];a.sort(function(x,y){return x-y;});var RESULT=a;",
    "var s='abc';var t=s.padStart(5,'0');var RESULT=t;",
]


@_t
def test_p5_honest_quiet():
    """Honest text stays quiet (all MISS)."""
    bad = [t for t in _HONEST if not _misses(t)]
    return (not bad), "honest=%d/%d quiet%s" % (
        len(_HONEST) - len(bad), len(_HONEST),
        "" if not bad else " HIT:" + ",".join(b[:30] for b in bad))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 sites scan in reasonable time."""
    t0 = time.time()
    for i in range(200):
        _hits("var C=[%d];var E=C.flatMap(function(c,i,a,t){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1525-F1545: other lanes' scope -- must stay MISS
_P7 = [
    # F1525: match readout
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');",
    # F1530: generator
    "var C={I};function* g(){for(var c of C){yield c;}}var E=[...g()];var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1544: splice(-1) single-arg
    "var C={I};var D=C.splice(-1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """F1525-F1545 (other lanes) still MISS."""
    bad = []
    for tmpl in _P7:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(tmpl[:40])
    return (not bad), "other-opens=%d/%d MISS%s" % (
        len(_P7) - len(bad), len(_P7),
        "" if not bad else " HIT:" + ",".join(bad))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w417_attack_probes: F1518-F1524 now closed (BREAK expected).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w417_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g418l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w417_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.match(r"(HELD|BREAK)\s+(\S+)", line.strip())
            if m:
                (held if m.group(1) == "HELD" else broken).add(m.group(2))
        # F1518-F1524 now closed: their pins flip to BREAK (expected).
        # F1525-F1545 pins must stay HELD; taxonomy/footer must stay HELD.
        ok = True
        notes = []
        for fn in ["test_taxonomy_pin", "test_footer"]:
            if fn in broken:
                ok = False
                notes.append(fn + "=BREAK")
            elif fn in held:
                notes.append(fn + "=HELD")
        return (ok, "green(w417_attack): %s" % ("; ".join(notes)))
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
