#!/usr/bin/env python3
"""Wave-419 lane 1 close battery: F1546-F1551 CLOSED.

F1546: flatMap thisArg twins -- 1-param callback with `[]` thisArg and
  arrow callback with `"x"` thisArg. Closed by new `_js_f1546_stmt_decode`
  (1-param only; thisArg `[]` or string literal; disjoint from F1350
  (no thisArg), F1377 (2-param), F1449 (3-param), F1504 (4+ param, {}
  thisArg), F1518 (4-param null thisArg) by grammar).

F1547: padStart/padEnd multi-char padString -- `padStart(S.length+10,'ab')`
  + `slice(-S.length)`, `padEnd(S.length+10,'xy')` + `slice(0,S.length)`.
  Closed by new `_js_f1547_stmt_decode` (narrow target-length grammar;
  disjoint from F1505/F1506 (per-char dynamic), F1507 (fixed-5), F1519
  (per-char pad+slice(-1)) by grammar).

F1548: sort reversed-boolean comparator -- `C.slice().sort(function(a,b){
  return b<a;})`. Closed by new `_js_f1548_stmt_decode` (disjoint from
  F1508 (`a>b`, no slice), F1520 (arrow), F1352/F1376 (return-0) by grammar).

F1549: two-statement trim wrapper -- `var T='\\u2003'+S+'\\u2003';`
  `var RESULT=T.trim();`. Closed by new `_js_f1549_stmt_decode`
  (disjoint from F1272 (one-statement wrapper) by grammar).

F1550: join multi-char separator + split readout -- `join('<>')` +
  `split('<>').join('')`. Closed by new `_js_f1550_stmt_decode`
  (literal roundtrip identity check; disjoint from F1357 (one-statement),
  F1408 (apply readout), F1512 (comma), F1521 (space/pipe) by grammar).

F1551: String identity-method readout twins -- `S.slice(0)`,
  `S.substring(S.length,0)`, `S.valueOf()`. Closed by new
  `_js_f1551_stmt_decode` (disjoint from F1543
  (repeat/normalize/toWellFormed) by grammar).

New dispatch loop; N_STMTDEC_LOOPS 88->89. All node-exact (v24.20.0,
short + 40-char secrets); fail-closed hook-level bounds; sibling
pins hold; F1552-F1569 (other lanes) still MISS.

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=89; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if actual != 89:
        ok = False
        notes.append("N_STMTDEC_LOOPS actual=%d (want 89)" % actual)
    else:
        notes.append("N_STMTDEC_LOOPS=89")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    # taxonomy pin
    from gov.decision_codes import TAXONOMY
    if len(TAXONOMY) != 2143:
        ok = False
        notes.append("taxonomy=%d (want 2143)" % len(TAXONOMY))
    else:
        notes.append("taxonomy=2143")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1546: flatMap function-form with [] thisArg
    ("f1546-0",
     "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;"),
    # F1546: flatMap arrow-form with "x" thisArg
    ("f1546-1",
     'var C={I};var E=C.flatMap(c=>[String.fromCharCode(c)],"x");var S=E.join(\'\');var RESULT=S;'),
    # F1547: padStart multi-char
    ("f1547-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);"),
    # F1547: padEnd multi-char
    ("f1547-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padEnd(S.length+10,'xy');var RESULT=P.slice(0,S.length);"),
    # F1548: sort reversed-boolean
    ("f1548-0",
     "var C={I};var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    # F1549: two-statement trim with EM SPACE
    ("f1549-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\\u2003'+S+'\\u2003';var RESULT=T.trim();"),
    # F1550: join multi-char separator
    ("f1550-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('<>');var T=S.split('<>').join('');var RESULT=T;"),
    # F1551: slice(0)
    ("f1551-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);"),
    # F1551: substring(S.length,0)
    ("f1551-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.substring(S.length,0);"),
    # F1551: valueOf()
    ("f1551-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.valueOf();"),
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
    # F1546: let/renamed, function-form
    "let C={I};let E=C.flatMap(function(x){return [String.fromCharCode(x)];},[]);let S=E.join('');let RESULT=S;",
    # F1546: parenthesized arrow
    'var C={I};var E=C.flatMap((c)=>[String.fromCharCode(c)],"y");var S=E.join(\'\');var RESULT=S;',
    # F1547: S.length-5 (still identity)
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+5,'abc');var RESULT=P.slice(-S.length);",
    # F1547: const variant
    "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const P=S.padEnd(S.length+10,'xy');const RESULT=P.slice(0,S.length);",
    # F1548: renamed params
    "var C={I};var D=C.slice().sort(function(x,y){return y<x;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
    # F1548: whitespace
    "var C={I};var D=C.slice().sort(function(a,b){ return b < a; });var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
    # F1549: regular spaces
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='  '+S+'  ';var RESULT=T.trim();",
    # F1549: let variant
    "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let T='\\u2003'+S+'\\u2003';let RESULT=T.trim();",
    # F1550: different separator
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('||');var T=S.split('||').join('');var RESULT=T;",
    # F1551: let slice(0)
    "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let RESULT=S.slice(0);",
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
    # F1546: 2-param callback -> fail closed (F1377's shape, different hook)
    ("f1546-2param",
     "var C={I};var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;"),
    # F1546: non-literal thisArg -> fail closed
    ("f1546-varthisarg",
     "var C={I};var T=[];var E=C.flatMap(function(c){return [String.fromCharCode(c)];},T);var S=E.join('');var RESULT=S;"),
    # F1547: padStart with wrong slice (not -S.length) -> fail closed
    ("f1547-wrongslice",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-1);"),
    # F1548: a<b (not reversed) -> fail closed
    ("f1548-notreversed",
     "var C={I};var D=C.slice().sort(function(a,b){return a<b;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    # F1549: non-ws affix -> fail closed
    ("f1549-nonws",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='xx'+S+'xx';var RESULT=T.trim();"),
    # F1550: separator mismatch -> fail closed
    ("f1550-sepmismatch",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('<>');var T=S.split('><').join('');var RESULT=T;"),
    # F1551: slice(1) (not identity) -> fail closed
    ("f1551-slice1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(1);"),
]

# (name, payload, hook_fn): the NEW hook must return None on these shapes.
_FAILCLOSED_HOOK = [
    # F1546 hook must miss F1504's 4-param {} form
    ("f1546-f1504", "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "_js_f1546_stmt_decode"),
    # F1546 hook must miss F1350's no-thisArg form
    ("f1546-f1350", "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];});var S=E.join('');var RESULT=S;",
     "_js_f1546_stmt_decode"),
    # F1547 hook must miss F1507's fixed-5 per-char form
    ("f1547-f1507", "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(5,'0');});var RESULT=E.join('');",
     "_js_f1547_stmt_decode"),
    # F1548 hook must miss F1508's no-slice form
    ("f1548-f1508", "var C={I};C.sort(function(a,b){return b<a;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
     "_js_f1548_stmt_decode"),
    # F1549 hook must miss F1272's one-statement form
    ("f1549-f1272", "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=('  '+J+'  ').trim();var RESULT=S;",
     "_js_f1549_stmt_decode"),
    # F1550 hook must miss F1357's one-statement chained form
    ("f1550-f1357", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('<>').split('<>').join('');var RESULT=S;",
     "_js_f1550_stmt_decode"),
    # F1551 hook must miss F1543's repeat form
    ("f1551-f1543", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.repeat(1);",
     "_js_f1551_stmt_decode"),
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
    # F1504: 4-param {} thisArg still BLOCKs
    ("f1504",
     "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1508: function-form sort still BLOCKs
    ("f1508",
     "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1272: one-statement trim still BLOCKs
    ("f1272",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('');var S=('  '+J+'  ').trim();var RESULT=S;"),
    # F1357: one-statement join/split still BLOCKs
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('<>').split('<>').join('');var RESULT=S;"),
    # F1520: arrow sort still BLOCKs
    ("f1520",
     "var C={I};var D=C.slice().sort((a,b)=>a>b);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    "var s='  hello  ';var RESULT=s.trim();",
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
        _hits("var C=[%d];var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1552-F1569: other lanes' scope -- must stay MISS
_P7 = [
    # F1552: splice two-arg no-op
    "var C={I};var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
    # F1558: replace function-replacer
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;",
    # F1564: Map.set loop
    "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');",
]


@_t
def test_p7_other_opens_miss():
    """F1552-F1569 (other lanes) still MISS."""
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
    """Depth-1 green on w418_attack_probes: F1546-F1551 now closed.

    Honors GOV_SKIP_GREEN. F1546-F1551 pins flip to PIN-FAIL (expected,
    they now HIT). F1552-F1569 pins must stay pin-ok. Taxonomy, footer,
    nopaid must stay ok.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w418_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g419l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w418_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        # Parse pin lines: "pin-ok F1546 MISS" or "PIN-FAIL F1546 HIT"
        pin_status = {}
        for line in out.split("\n"):
            m = re.match(r"(pin-ok|PIN-FAIL)\s+(F\d+)", line.strip())
            if m:
                pin_status[m.group(2)] = m.group(1)
        ok = True
        notes = []
        # F1546-F1551: expect PIN-FAIL (now HIT = closed)
        for fn in ["F1546", "F1547", "F1548", "F1549", "F1550", "F1551"]:
            st = pin_status.get(fn, "?")
            if st != "PIN-FAIL":
                ok = False
                notes.append(fn + "=" + st + "(want PIN-FAIL)")
        # F1552-F1569: expect pin-ok (still MISS = open)
        for fn in ["F1552", "F1553", "F1554", "F1555", "F1556", "F1557",
                   "F1558", "F1559", "F1560", "F1561", "F1562", "F1563",
                   "F1564", "F1565", "F1566", "F1567", "F1568", "F1569"]:
            st = pin_status.get(fn, "?")
            if st != "pin-ok":
                ok = False
                notes.append(fn + "=" + st + "(want pin-ok)")
        # taxonomy, footer, nopaid
        for tag, want in [("tax-ok", True), ("footer-ok", True),
                          ("nopaid-ok", True)]:
            if tag not in out:
                ok = False
                notes.append(tag + " missing")
        if not notes:
            notes.append("F1546-F1551 flipped, F1552-F1569 held, tax/footer/nopaid ok")
        return (ok, "green(w418_attack): %s" % "; ".join(notes))
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
