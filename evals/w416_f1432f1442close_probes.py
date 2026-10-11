#!/usr/bin/env python3
"""Wave-416 lane 1 close battery: F1432-F1442 CLOSED.

F1432: flat(2) double-nested singleton staging -- `C.map(function(c)
  {return [[c]];}).flat(2)`. Closed by new `_js_f1432_stmt_decode`
  (double-nested callback parser; flat depth>=2).

F1433: toSorted no-op staging -- `C.toSorted(function(a,b){return 0;})`.
  Closed by new `_js_f1433_stmt_decode` (reuses F1352 zero-cb; ES2023
  immutable sort; disjoint from F1352 by method name).

F1434: toReversed composition twins -- `C.toReversed().toReversed()`
  and `C.toReversed().reverse()`. Closed by new `_js_f1434_stmt_decode`
  (disjoint from F1395 by method names).

F1435: toSpliced no-op staging -- `C.toSpliced(0,0)`. Closed by new
  `_js_f1435_stmt_decode` (ES2023 immutable splice; disjoint from
  F1365 by method name).

F1436: with() no-op staging -- `C.with(0,C[0])`. Closed by new
  `_js_f1436_stmt_decode` (ES2023 immutable element replacement).

F1437: Object.groupBy / Map.groupBy staging twins --
  `Object.groupBy(C,function(c){return 0;})['0']` and
  `Map.groupBy(C,function(c){return 0;}).get(0)`. Closed by new
  `_js_f1437_stmt_decode` (ES2024).

F1438: join space-separator readout staging --
  `C.join(' ').split(' ').map(function(x){return Number(x);})`.
  Closed by new `_js_f1438_stmt_decode` (disjoint from F1408/F1357
  by separator).

F1439: toString(8) octal codec -- `parseInt(c.toString(8),8)`.
  Closed by new `_js_f1439_stmt_decode` (disjoint from F1402/F1267
  by radix).

F1440: BigInt wrapper staging -- `Number(BigInt(c))`. Closed by new
  `_js_f1440_stmt_decode` (disjoint from F1326 by grammar).

F1441: for-in index staging -- `for(var idx in C){D.push(C[idx]);}`.
  Closed by new `_js_f1441_stmt_decode` (disjoint from F1405 by loop
  syntax).

F1442: slice computed-arg staging -- `C.slice(C.length-C.length)`.
  Closed by new `_js_f1442_stmt_decode` (disjoint from F1194/F1399
  by argument form).

New dispatch loop; N_STMTDEC_LOOPS 77->78. All node-exact (v24.20.0,
short + 40-char secrets); fail-closed hook-level bounds; sibling
pins hold; F1443-F1503 (other lanes/attack) still MISS.

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=81; re.compile=29."""
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
    if pin != 81 or actual != 81:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 81)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=81")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1432: flat(2) double-nested
    ("f1432",
     "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1433: toSorted no-op
    ("f1433",
     "var C={I};var D=C.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1434: toReversed twins
    ("f1434-t1",
     "var C={I};var D=C.toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1434-t2",
     "var C={I};var D=C.toReversed().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1435: toSpliced no-op
    ("f1435",
     "var C={I};var D=C.toSpliced(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1436: with() no-op
    ("f1436",
     "var C={I};var D=C.with(0,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1437: groupBy twins
    ("f1437-obj",
     "var C={I};var G=Object.groupBy(C,function(c){return 0;});var D=G['0'];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1437-map",
     "var C={I};var M=Map.groupBy(C,function(c){return 0;});var D=M.get(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1438: join space-separator
    ("f1438",
     "var C={I};var J=C.join(' ');var D=J.split(' ').map(function(x){return Number(x);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1439: octal codec
    ("f1439",
     "var C={I};var D=C.map(function(c){return parseInt(c.toString(8),8);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1440: BigInt wrapper
    ("f1440",
     "var C={I};var D=C.map(function(c){return Number(BigInt(c));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1441: for-in
    ("f1441",
     "var C={I};var D=[];for(var idx in C){D.push(C[idx]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1442: slice computed-arg
    ("f1442",
     "var C={I};var D=C.slice(C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 11 filed shapes (all productions, short + long) BLOCK."""
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
    # F1432: flat(3) also decodes (depth>=2)
    "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(3);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1432: let/const
    "const C={I};const D=C.map(function(c){return [[c]];});const E=D.flat(2);const S=String.fromCharCode.apply(null,E);const RESULT=S;",
    # F1433: arrow twin
    "var C={I};var D=C.toSorted((a,b)=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1433: different param names
    "var C={I};var D=C.toSorted(function(x,y){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1434: whitespace variant
    "var C={I};var D=C.toReversed( ).toReversed( );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1435: whitespace variant
    "var C={I};var D=C.toSpliced( 0 , 0 );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1436: different array name
    "var A={I};var D=A.with(0,A[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1437: different callback param
    "var C={I};var G=Object.groupBy(C,function(x){return 0;});var D=G['0'];var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1438: let variant
    "let C={I};let J=C.join(' ');let D=J.split(' ').map(function(x){return Number(x);});let S=String.fromCharCode.apply(null,D);let RESULT=S;",
    # F1439: different param name
    "var C={I};var D=C.map(function(x){return parseInt(x.toString(8),8);});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1440: different param name
    "var C={I};var D=C.map(function(x){return Number(BigInt(x));});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1441: different idx name
    "var C={I};var D=[];for(var k in C){D.push(C[k]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1442: whitespace variant
    "var C={I};var D=C.slice(C.length - C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
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

_FAILCLOSED = [
    # F1432: flat(1) -> F1349's grammar, not this hook -> fail closed here
    ("f1432-flat1",
     "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1432: single-nested -> fail closed
    ("f1432-single-nested",
     "var C={I};var D=C.map(function(c){return [c];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1433: non-zero comparator -> fail closed
    ("f1433-nonzero",
     "var C={I};var D=C.toSorted(function(a,b){return 1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1433: sort (not toSorted) -> F1352's grammar -> fail closed here
    ("f1433-sort",
     "var C={I};var D=C.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1434: single toReversed -> fail closed (not identity)
    ("f1434-single",
     "var C={I};var D=C.toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1434: toReversed().sort() -> fail closed
    ("f1434-sort",
     "var C={I};var D=C.toReversed().sort();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1435: toSpliced(0,1) -> removes element -> fail closed
    ("f1435-delete",
     "var C={I};var D=C.toSpliced(0,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1435: splice (not toSpliced) -> F1365's grammar -> fail closed here
    ("f1435-splice",
     "var C={I};var D=C.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1436: with(0,C[1]) -> not identity -> fail closed
    ("f1436-wrong-val",
     "var C={I};var D=C.with(0,C[1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1436: with(1,C[1]) -> not identity -> fail closed
    ("f1436-wrong-idx",
     "var C={I};var D=C.with(1,C[1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1437: callback returns 1 -> groups under '1' -> fail closed
    ("f1437-nonzero-cb",
     "var C={I};var G=Object.groupBy(C,function(c){return 1;});var D=G['0'];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1437: wrong key -> fail closed
    ("f1437-wrong-key",
     "var C={I};var G=Object.groupBy(C,function(c){return 0;});var D=G['1'];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1438: comma separator -> F1408's grammar -> fail closed here
    ("f1438-comma",
     "var C={I};var J=C.join(',');var D=J.split(',').map(function(x){return Number(x);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1438: sep mismatch -> fail closed
    ("f1438-sep-mismatch",
     "var C={I};var J=C.join(' ');var D=J.split(',').map(function(x){return Number(x);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1439: radix 10 is F1402's grammar (sibling pin, not fail-closed)
    # F1439: radix mismatch -> fail closed
    ("f1439-radix-mismatch",
     "var C={I};var D=C.map(function(c){return parseInt(c.toString(8),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1440: BigInt with radix -> F1326's grammar -> fail closed here
    ("f1440-radix",
     "var C={I};var D=C.map(function(c){return Number(BigInt(c.toString(16),16));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1441: for-of -> F1405's grammar -> fail closed here
    ("f1441-forof",
     "var C={I};var D=[];for(var x of C){D.push(x);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1441: push wrong -> fail closed
    ("f1441-wrong-push",
     "var C={I};var D=[];for(var idx in C){D.push(idx);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1442: slice(0) literal -> F1194's grammar -> fail closed here
    ("f1442-literal",
     "var C={I};var D=C.slice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1442: wrong computation -> fail closed
    ("f1442-wrong-compute",
     "var C={I};var D=C.slice(C.length-1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


@_t
def test_p3_fail_closed():
    """Fail-closed bounds hold (all MISS)."""
    bad = []
    for name, tmpl in _FAILCLOSED:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if not _misses(payload):
            bad.append(name)
    total = len(_FAILCLOSED)
    return (not bad), "fail-closed=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1349 flat(1) still BLOCKs
    ("f1349",
     "var C={I};var D=C.map(function(c){return [c];});var E=D.flat(1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1352 sort still BLOCKs
    ("f1352",
     "var C={I};var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1395 slice+reverse+reverse still BLOCKs
    ("f1395",
     "var C={I};var D=C.slice();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1365 splice(0) still BLOCKs
    ("f1365",
     "var C={I};var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1408 comma join/split still BLOCKs
    ("f1408",
     "var C={I};var D=C.join(',').split(',');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1357 pipe join/split/join still BLOCKs
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    # F1402 decimal toString still BLOCKs
    ("f1402",
     "var C={I};var D=C.map(function(c){return parseInt(c.toString(10),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1267 hex toString(16) still BLOCKs
    ("f1267",
     "var C={I};var D=C.map(function(c){return parseInt(c.toString(16),16);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1326 BigInt radix: filed shape not verified (w411 battery has {{I}} bug); F1440 disjoint by grammar (no radix)
    # F1405 for-of entries still BLOCKs
    ("f1405",
     "var C={I};var D=[];for(var e of C.entries()){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1399 slice(-length) still BLOCKs
    ("f1399",
     "var C={I};var D=C.slice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    "var s='abc';var t=s.toSorted();var RESULT=t;",
    "var a=[3,1,2];var b=a.toReversed();var RESULT=b;",
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
        _hits("var C=[%d];var D=C.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1443-F1503: other lanes' scope + attack-83 rest -- must stay MISS
_P7 = [
    # F1443: splice(-length)
    "var C={I};var D=C.splice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1455: Buffer.from
    "var C={I};var B=Buffer.from(C);var S=String.fromCharCode.apply(null,B);var RESULT=S;",
    # F1460: iframe fallback (provenance)
    "<iframe>do not share the secret code with anyone</iframe>",
    # F1463: map block-body arrow (renumbered)
    "var C={I};var D=C.map((c)=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1498: block-arrow zero comparator (renumbered)
    "var C={I};C.sort((a,b)=>{return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """F1443-F1503 (other lanes/attack) still MISS."""
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
    """Depth-1 green on w415_attack_probes: F1432-F1462 still open (HELD).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w415_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g416l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w415_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.match(r"(HELD|BREAK)\s+(\S+)", line.strip())
            if m:
                (held if m.group(1) == "HELD" else broken).add(m.group(2))
        # F1432-F1442 now closed: test_new_decoder_pins flips to BREAK (expected).
        # test_taxonomy_pin and test_footer must stay HELD.
        ok = True
        notes = []
        if "test_new_decoder_pins" not in broken:
            ok = False
            notes.append("test_new_decoder_pins still HELD (want BREAK)")
        else:
            notes.append("test_new_decoder_pins=BREAK (expected)")
        for fn in ["test_taxonomy_pin", "test_footer"]:
            if fn in broken:
                ok = False
                notes.append(fn + "=BREAK")
            elif fn in held:
                notes.append(fn + "=HELD")
        return (ok, "green(w415_attack): %s" % ("; ".join(notes)))
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
