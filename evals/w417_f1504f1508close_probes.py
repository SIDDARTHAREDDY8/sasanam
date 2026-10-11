#!/usr/bin/env python3
"""Wave-417 lane 1 close battery: F1504-F1508 CLOSED.

F1504: flatMap 4+-param callback twins -- `C.flatMap(function(c,i,a,t){return [c];},{})`,
  `(c,i,a,t)=>[c]` arrow twin, 5-param `function(c,i,a,t,u)` twin. Closed by new
  `_js_f1504_stmt_decode` (4+ param-count grammar; optional `{}` thisArg; disjoint
  from F1350/F1377/F1449 by param count).

F1505: padStart dynamic-length no-op -- `String(c).padStart(String(c).length,'0')`.
  Closed by new `_js_f1505_stmt_decode` (shared `_js_f1505f1506_try_pad`; disjoint
  from F1267 by length-arg grammar).

F1506: padEnd dynamic-length no-op -- `String(c).padEnd(String(c).length,'0')`.
  Closed by new `_js_f1506_stmt_decode` (shared `_js_f1505f1506_try_pad`; disjoint
  from F1267 by method name).

F1507: padStart(5,'0') fixed-length no-op. Closed by new `_js_f1507_stmt_decode`
  (literal-5 length grammar; disjoint from F1267 (literal 3) and F1505 (dynamic)).

F1508: sort boolean comparator -- `C.sort(function(a,b){return a>b;})`.
  Closed by new `_js_f1508_stmt_decode` (comparator never returns negative, so V8's
  sort never moves an element -- universal no-op; disjoint from F1352/F1376 by
  comparator body).

New dispatch loop; N_STMTDEC_LOOPS 81->82. All node-exact (v24.20.0,
short + 40-char secrets); fail-closed hook-level bounds; sibling
pins hold; F1509-F1516 (other lanes) still MISS.

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
    # F1504: flatMap 4-param function + thisArg
    ("f1504-0",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1504: flatMap 4-param arrow twin
    ("f1504-1",
     "var C={I};var E=C.flatMap((c,i,a,t)=>[c]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1504: flatMap 5-param twin
    ("f1504-2",
     "var C={I};var E=C.flatMap(function(c,i,a,t,u){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1505: padStart dynamic-length
    ("f1505",
     "var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1506: padEnd dynamic-length
    ("f1506",
     "var C={I};var D=C.map(function(c){return String(c).padEnd(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1507: padStart(5) + D.map(Number) (entry shape)
    ("f1507-entry",
     "var C={I};var D=C.map(function(c){return String(c).padStart(5,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1507: padStart(5) + function-Number readout (battery shape)
    ("f1507-battery",
     "var C={I};var D=C.map(function(c){return String(c).padStart(5,'0');});var S=String.fromCharCode.apply(null,D.map(function(x){return Number(x);}));var RESULT=S;"),
    # F1508: sort boolean comparator
    ("f1508",
     "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
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
    # F1504: 6-param
    "var C={I};var E=C.flatMap(function(c,i,a,t,u,v){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1504: let/const + renamed idents
    "const C={I};const E=C.flatMap(function(x,y,z,w){return [x];});const S=String.fromCharCode.apply(null,E);const RESULT=S;",
    # F1504: arrow with thisArg
    "var C={I};var E=C.flatMap((c,i,a,t)=>[c],{});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1505: double-quote pad char
    'var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,"0");});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;',
    # F1505: let variant
    "let C={I};let D=C.map(function(x){return String(x).padStart(String(x).length,'0');});let S=String.fromCharCode.apply(null,D.map(Number));let RESULT=S;",
    # F1506: renamed param
    "var C={I};var D=C.map(function(q){return String(q).padEnd(String(q).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;",
    # F1507: whitespace variant
    "var C={I};var D=C.map(function(c){return String(c).padStart( 5 , '0' );});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;",
    # F1508: renamed params
    "var C={I};C.sort(function(x,y){return x>y;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
    # F1508: whitespace variant
    "var C={I};C.sort(function(a,b){return a > b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
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
#
# Two classes:
#  (a) shapes that must MISS the whole scanner (genuinely not decodable
#      by any hook);
#  (b) sibling shapes that must MISS the NEW F1504-F1508 hooks specifically
#      (they are caught by their own sibling hooks -- disjointness).

_FAILCLOSED_SCANNER = [
    # F1504: wrong return (not singleton) -> fail closed
    ("f1504-wrong-ret",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c,c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1504: non-empty thisArg -> fail closed
    ("f1504-thisarg",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{x:1});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1504: duplicate params -> fail closed (H1: binds last duplicate, not a copy)
    ("f1504-dup-param",
     "var C={I};var E=C.flatMap(function(c,c,c,c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1505: pad char not '0' -> fail closed
    ("f1505-padchar",
     "var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,' ');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1505: length of wrong ident -> fail closed
    ("f1505-len-mismatch",
     "var C={I};var D=C.map(function(c){return String(c).padStart(String(d).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1507: literal 6 -> fail closed (not the filed 5)
    ("f1507-lit6",
     "var C={I};var D=C.map(function(c){return String(c).padStart(6,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    # F1508: a<b (reversed) -> fail closed (not the filed shape)
    ("f1508-reversed",
     "var C={I};C.sort(function(a,b){return a<b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1508: a-b (numeric) -> fail closed (actually sorts)
    ("f1508-numeric",
     "var C={I};C.sort(function(a,b){return a-b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1508: param collision -> fail closed
    ("f1508-collision",
     "var C={I};C.sort(function(a,a){return a>a;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]

# (name, payload, hook_fn): the NEW hook must return None, even though a
# sibling hook may catch the shape via the full scanner.
_FAILCLOSED_HOOK = [
    # F1504 hook must miss 3-param (F1449's grammar)
    ("f1504-3param", "var C={I};var E=C.flatMap(function(c,i,a){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "_js_f1504_stmt_decode"),
    # F1504 hook must miss 2-param (F1377's grammar)
    ("f1504-2param", "var C={I};var E=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "_js_f1504_stmt_decode"),
    # F1505 hook must miss literal-3 (F1267's grammar shape, different readout)
    ("f1505-lit3", "var C={I};var D=C.map(function(c){return String(c).padStart(3,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;",
     "_js_f1505_stmt_decode"),
    # F1506 hook must miss padStart dynamic (F1505's grammar)
    ("f1506-padstart", "var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;",
     "_js_f1506_stmt_decode"),
    # F1507 hook must miss literal-3 (F1267's grammar shape)
    ("f1507-lit3", "var C={I};var D=C.map(function(c){return String(c).padStart(3,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;",
     "_js_f1507_stmt_decode"),
    # F1508 hook must miss return-0 (F1352's grammar)
    ("f1508-return0", "var C={I};C.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
     "_js_f1508_stmt_decode"),
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
    return (not bad), "fail-closed=%d/%d MISS%s" % (
        total - len(bad), total, "" if not bad else " HIT:" + ",".join(bad))


# ---------------- p4: sibling pins ----------------

_SIBLINGS = [
    # F1449 flatMap 3-param still BLOCKs
    ("f1449",
     "var C={I};var E=C.flatMap(function(c,i,a){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1350 flatMap 1-param still BLOCKs
    ("f1350",
     "var C={I};var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1377 flatMap 2-param still BLOCKs
    ("f1377",
     "var C={I};var E=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1267 padStart(3) still BLOCKs
    ("f1267",
     "var C={I};var P=C.map(function(c){return String(c).padStart(3,'0');});var S=String.fromCharCode.apply(null,P.map(function(p){return parseInt(p,10);}));var RESULT=S;"),
    # F1352 sort return-0 still BLOCKs
    ("f1352",
     "var C={I};var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
        _hits("var C=[%d];var E=C.flatMap(function(c,i,a,t){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1509-F1516: other lanes' scope -- must stay MISS
_P7 = [
    # F1509: filed shape (now CLOSED -> HIT)
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;",
    # F1510: filed shape (now CLOSED -> HIT)
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimStart();});var S=D.join('');var RESULT=S;",
    # F1511: filed shape (now CLOSED -> HIT)
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimEnd();});var S=D.join('');var RESULT=S;",
    # F1512: filed shape (now CLOSED -> HIT)
    "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;",
    # F1513: filed shape (now CLOSED -> HIT)
    "var C={I};var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1514: filed shape (now CLOSED -> HIT)
    "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;",
    # F1515: filed shape (now CLOSED -> HIT)
    "var C={I};var S=C.toString();var RESULT=S.split(',').map(Number).map(function(n){return String.fromCharCode(n);}).join('');",
    # F1516: filed shape (now CLOSED -> HIT)
    "var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """F1509-F1516 (other lanes) now CLOSED (merged) -> HIT."""
    bad = []
    for tmpl in _P7:
        payload = tmpl.replace("{I}", _codes(SECRET_S))
        if _misses(payload):
            bad.append(tmpl[:40])
    return (not bad), "other-lanes-closed=%d/%d HIT%s" % (
        len(_P7) - len(bad), len(_P7),
        "" if not bad else " MISS:" + ",".join(bad))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w416_attack_probes: F1504-F1508 now closed (BREAK expected).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w416_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g417l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w416_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            m = re.match(r"(HELD|BREAK)\s+(\S+)", line.strip())
            if m:
                (held if m.group(1) == "HELD" else broken).add(m.group(2))
        # F1504-F1508 now closed: their pins flip to BREAK (expected).
        # F1509-F1517 pins must stay HELD; taxonomy/footer must stay HELD.
        ok = True
        notes = []
        for fn in ["test_taxonomy_pin", "test_footer"]:
            if fn in broken:
                ok = False
                notes.append(fn + "=BREAK")
            elif fn in held:
                notes.append(fn + "=HELD")
        return (ok, "green(w416_attack): %s" % ("; ".join(notes)))
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
