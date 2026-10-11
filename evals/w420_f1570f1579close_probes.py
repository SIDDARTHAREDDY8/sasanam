#!/usr/bin/env python3
"""Wave-420 lane 1 close battery: F1570-F1573, F1575-F1579 CLOSED (F1574 closed).

F1570: flatMap thisArg twins -- 2-param function callback with "xy"
  thisArg, 1-param arrow with null/0 thisArg. Closed by new
  `_js_f1570_stmt_decode` (disjoint from F1546 (1-param []/string),
  F1569 (4-param arrow null), F1518, F1504, F1350 by grammar).

F1571: padStart/padEnd padString variants with intermediate T --
  `padStart(S.length+6,'abc')`/`padStart(S.length+4,emoji)`/
  `padEnd(S.length+6,'xyz')` + `T=P.slice(...)` + `RESULT=T`.
  Closed by new `_js_f1571_stmt_decode` (disjoint from F1547
  (direct-RESULT) by grammar; emoji padString parsed raw).

F1572: sort a>b comparator with slice copy --
  `C.slice().sort(function(a,b){return a>b;})`. Closed by new
  `_js_f1572_stmt_decode` (V8 no-op: comparator never negative;
  disjoint from F1508 (no slice), F1548 (b<a) by grammar).

F1573: trim unicode-whitespace staging -- `(WS+S+WS).trim()` with
  WS in the JS trim set. Closed by new `_js_f1573_stmt_decode`
  (disjoint from F1549 (two-statement), F1272 (one-statement)).

F1575: slice/substring/substr identity twins -- `C.slice(0)` array
  form, `S.substring(0)`/`S.substr(0)` string forms. Closed by new
  `_js_f1575_stmt_decode` (two productions; disjoint from F1551).

F1576: valueOf wrapper twins -- `(c).valueOf()` per-element,
  `String(S).valueOf()` whole-string. Closed by new
  `_js_f1576_stmt_decode` (two productions; disjoint from F1553).

F1577: sparse-array toString hole-prefix -- `new Array(1).concat(C)`
  + `toString` + `split(',').slice(1).map(Number)`. Closed by new
  `_js_f1577_stmt_decode` (disjoint from F1554 (new Array(2n))).

F1578: String.raw live-template variants -- single-substitution
  with intermediate U, two-substitution `a${S}b${S}c` with
  `slice(1,S.length+1)`. Closed by new `_js_f1578_stmt_decode`
  (disjoint from F1555 (direct-RESULT)).

F1579: includes -0/false/0 fromIndex -- `S.includes('xoxb',-0)`,
  `false`, `0` + `K?S:''` ternary. Closed by new
  `_js_f1579_stmt_decode` (disjoint from F1556 (NaN)).

New dispatch loop; N_STMTDEC_LOOPS 92->93. All node-exact (v24.20.0,
short + 40-char secrets); fail-closed hook-level bounds; sibling
pins hold; F1580-F1607 (other lanes) still MISS.

Also: removed the duplicated F1540 `_stripped` block in _decode_layer
(documented wave-418 cleanup; behaviorally a no-op, _add dedups).

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=93; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = dsrc.count("for _stmtdec in (")
    if actual != 93:
        ok = False
        notes.append("N_STMTDEC_LOOPS actual=%d (want 93)" % actual)
    else:
        notes.append("N_STMTDEC_LOOPS=93")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    from gov.decision_codes import TAXONOMY
    if len(TAXONOMY) != 2143:
        ok = False
        notes.append("taxonomy=%d (want 2143)" % len(TAXONOMY))
    else:
        notes.append("taxonomy=2143")
    # F1540 duplicate block must be gone (single _stripped site)
    n1540 = dsrc.count("_stripped = _js_f1540_strip_dead_stmt(text)")
    if n1540 != 1:
        ok = False
        notes.append("F1540 strip sites=%d (want 1)" % n1540)
    else:
        notes.append("F1540 dup removed")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1570: 2-param function, "xy" thisArg
    ("f1570-0",
     'var C={I};var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},"xy");var S=E.join(\'\');var RESULT=S;'),
    # F1570: 1-param arrow, null thisArg
    ("f1570-1",
     "var C={I};var E=C.flatMap(c=>[String.fromCharCode(c)],null);var S=E.join('');var RESULT=S;"),
    # F1570: 1-param arrow, 0 thisArg
    ("f1570-2",
     "var C={I};var E=C.flatMap(c=>[String.fromCharCode(c)],0);var S=E.join('');var RESULT=S;"),
    # F1571: padStart 3-char
    ("f1571-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'abc');var T=P.slice(-S.length);var RESULT=T;"),
    # F1571: padStart emoji
    ("f1571-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+4,'\\uD83D\\uDE42');var T=P.slice(-S.length);var RESULT=T;"),
    # F1571: padEnd 3-char
    ("f1571-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padEnd(S.length+6,'xyz');var T=P.slice(0,S.length);var RESULT=T;"),
    # F1572: sort a>b with slice
    ("f1572-0",
     "var C={I};var D=C.slice().sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1573: NBSP trim
    ("f1573-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=('\\xa0'+S+'\\xa0').trim();var RESULT=T;"),
    # F1573: regular space trim
    ("f1573-4",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trim();var RESULT=T;"),
    # F1575: C.slice(0) array form
    ("f1575-0",
     "var C={I};var D=C.slice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1575: S.substring(0)
    ("f1575-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substring(0);var RESULT=T;"),
    # F1575: S.substr(0)
    ("f1575-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substr(0);var RESULT=T;"),
    # F1576: (c).valueOf()
    ("f1576-0",
     "var C={I};var E=C.map(function(c){return (c).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1576: String(S).valueOf()
    ("f1576-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String(S).valueOf();var RESULT=T;"),
    # F1577: sparse toString
    ("f1577-0",
     "var C={I};var D=new Array(1).concat(C);var S=D.toString();var T=S.split(',').slice(1).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    # F1578: String.raw single-subst
    ("f1578-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var U=T.slice(1,-1);var RESULT=U;"),
    # F1578: String.raw two-subst
    ("f1578-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b${S}c`;var U=T.slice(1,S.length+1);var RESULT=U;"),
    # F1579: includes -0
    ("f1579-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',-0);var RESULT=K?S:'';"),
    # F1579: includes false
    ("f1579-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',false);var RESULT=K?S:'';"),
    # F1579: includes 0
    ("f1579-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',0);var RESULT=K?S:'';"),
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
    # F1570: let/renamed, 2-param function
    'let C={I};let E=C.flatMap(function(x,y){return [String.fromCharCode(x)];},"ab");let S=E.join(\'\');let RESULT=S;',
    # F1570: parenthesized arrow, null
    "var C={I};var E=C.flatMap((c)=>[String.fromCharCode(c)],null);var S=E.join('');var RESULT=S;",
    # F1571: let, different padString
    "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let P=S.padStart(S.length+3,'qw');let T=P.slice(-S.length);let RESULT=T;",
    # F1571: bare INT target
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padEnd(99,'z');var T=P.slice(0,S.length);var RESULT=T;",
    # F1572: renamed params, whitespace
    "var C={I};var D=C.slice().sort(function(x,y){ return x > y; });var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1573: FEFF
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=('\\ufeff'+S+'\\ufeff').trim();var RESULT=T;",
    # F1573: U+3000
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=('\\u3000'+S+'\\u3000').trim();var RESULT=T;",
    # F1575: let C.slice(0)
    "let C={I};let D=C.slice(0);let S=String.fromCharCode.apply(null,D);let RESULT=S;",
    # F1575: const substring
    "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const T=S.substring(0);const RESULT=T;",
    # F1576: renamed param
    "var C={I};var E=C.map(function(x){return (x).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;",
    # F1577: let variant
    "let C={I};let D=new Array(1).concat(C);let S=D.toString();let T=S.split(',').slice(1).map(Number);let U=String.fromCharCode.apply(null,T);let RESULT=U;",
    # F1578: different affixes
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`m${S}n`;var U=T.slice(1,-1);var RESULT=U;",
    # F1579: whitespace
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes( 'xoxb' , 0 );var RESULT=K?S:'';",
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
    # F1570: 1-param function + "xy" -> F1546's territory? No: F1546 is
    # 1-param + string thisArg, so this SHOULD hit via F1546. Skip.
    # F1570: 3-param callback -> fail closed
    ("f1570-3param",
     'var C={I};var E=C.flatMap(function(a,b,c){return [String.fromCharCode(a)];},"xy");var S=E.join(\'\');var RESULT=S;'),
    # F1571: empty padString -> fail closed
    ("f1571-emptypad",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'');var T=P.slice(-S.length);var RESULT=T;"),
    # F1571: wrong slice (not -S.length) -> fail closed
    ("f1571-wrongslice",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'abc');var T=P.slice(0,5);var RESULT=T;"),
    # F1572: a<b (not a>b) -> fail closed
    ("f1572-notgt",
     "var C={I};var D=C.slice().sort(function(a,b){return a<b;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1572: no slice -> F1508's territory (should HIT via F1508, skip)
    # F1573: non-ws affix -> fail closed
    ("f1573-nonws",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=('xx'+S+'xx').trim();var RESULT=T;"),
    # F1575: slice(1) (not identity) -> fail closed
    ("f1575-slice1",
     "var C={I};var D=C.slice(1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1575: substring(1) -> fail closed
    ("f1575-sub1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.substring(1);var RESULT=T;"),
    # F1576: bare c.valueOf() (no parens) -> fail closed
    ("f1576-bare",
     "var C={I};var E=C.map(function(c){return c.valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1577: new Array(2) (not 1) -> fail closed
    ("f1577-arr2",
     "var C={I};var D=new Array(2).concat(C);var S=D.toString();var T=S.split(',').slice(1).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    # F1577: split(';') (not comma) -> fail closed
    ("f1577-splitsemi",
     "var C={I};var D=new Array(1).concat(C);var S=D.toString();var T=S.split(';').slice(1).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    # F1578: backtick in affix -> fail closed
    ("f1578-badtmpl",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}`;var U=T.slice(1,-1);var RESULT=U;"),
    # F1579: fromIndex 1 (not 0) -> fail closed (literal not at index 1... actually 'xoxb' at 0, fromIndex 1 -> false -> RESULT='' but decode would be dstr -> mis-decode, so must MISS)
    ("f1579-idx1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',1);var RESULT=K?S:'';"),
    # F1579: literal not a prefix -> fail closed
    ("f1579-notprefix",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('zzz',0);var RESULT=K?S:'';"),
]

# (name, payload, hook_fn): the NEW hook must return None on these shapes.
_FAILCLOSED_HOOK = [
    # F1570 hook must miss F1546's 1-param [] form
    ("f1570-f1546", "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;",
     "_js_f1570_stmt_decode"),
    # F1570 hook must miss F1569's 4-param arrow null form
    ("f1570-f1569", "var C={I};var E=C.flatMap((c,i,a,t)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
     "_js_f1570_stmt_decode"),
    # F1571 hook must miss F1547's direct-RESULT form
    ("f1571-f1547", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'abc');var RESULT=P.slice(-S.length);",
     "_js_f1571_stmt_decode"),
    # F1572 hook must miss F1508's no-slice form
    ("f1572-f1508", "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;",
     "_js_f1572_stmt_decode"),
    # F1572 hook must miss F1548's b<a form
    ("f1572-f1548", "var C={I};var D=C.slice().sort(function(a,b){return b<a;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
     "_js_f1572_stmt_decode"),
    # F1573 hook must miss F1549's two-statement form
    ("f1573-f1549", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\\u2003'+S+'\\u2003';var RESULT=T.trim();",
     "_js_f1573_stmt_decode"),
    # F1575 hook must miss F1551's S.slice(0) string form
    ("f1575-f1551", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);",
     "_js_f1575_stmt_decode"),
    # F1576 hook must miss F1553's new Number form
    ("f1576-f1553", "var C={I};var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;",
     "_js_f1576_stmt_decode"),
    # F1576 hook must miss F1553's S.valueOf() form
    ("f1576-f1553b", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.valueOf();",
     "_js_f1576_stmt_decode"),
    # F1577 hook must miss F1554's new Array(2n) form
    ("f1577-f1554", "var C={I};var D=new Array(2).concat(C);var S=D.toString();var RESULT=S;",
     "_js_f1577_stmt_decode"),
    # F1578 hook must miss F1555's direct-RESULT form
    ("f1578-f1555", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var RESULT=T.slice(1,-1);",
     "_js_f1578_stmt_decode"),
    # F1579 hook must miss F1556's NaN form
    ("f1579-f1556", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',NaN);var RESULT=K?S:'';",
     "_js_f1579_stmt_decode"),
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
    # F1546: 1-param [] thisArg still BLOCKs
    ("f1546",
     'var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join(\'\');var RESULT=S;'),
    # F1547: direct-RESULT padStart still BLOCKs
    ("f1547",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);"),
    # F1548: b<a sort still BLOCKs
    ("f1548",
     "var C={I};var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    # F1549: two-statement trim still BLOCKs
    ("f1549",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\\u2003'+S+'\\u2003';var RESULT=T.trim();"),
    # F1551: S.slice(0) still BLOCKs
    ("f1551",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);"),
    # F1553: new Number valueOf still BLOCKs
    ("f1553",
     "var C={I};var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    # F1555: String.raw direct-RESULT still BLOCKs
    ("f1555",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var RESULT=T.slice(1,-1);"),
    # F1556: includes NaN still BLOCKs
    ("f1556",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',NaN);var RESULT=K?S:'';"),
    # F1508: sort a>b no-slice still BLOCKs
    ("f1508",
     "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
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
    "var C=[65];var D=C.flatMap(function(c){return [c];});var RESULT=D;",
    "var s='hi';var t=s.includes('i',0);var RESULT=t;",
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

# F1580-F1607: other lanes' scope -- must stay MISS
_P7 = [
    # F1580: search patterns
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb'+'');var RESULT=S.slice(K);",
    # F1585: flat depths
    "var C={I};var D=C.flat(-1);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1590: optgroup (provenance, not decoder -- must stay quiet here)
    "var x='<optgroup label=\"x\">';var RESULT=x;",
    # F1591: replace arrow replacer
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,(m)=>m);var RESULT=T;",
    # F1603: trim EM SPACE direct-RESULT
    "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=('\\u2003'+S+'\\u2003').trim();",
]


@_t
def test_p7_other_opens_miss():
    """F1580-F1607 (other lanes) still MISS."""
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
    """Depth-1 green on w419_attack_probes: F1570-F1579 now closed.

    Honors GOV_SKIP_GREEN. F1570-F1573/F1575-F1579 pins flip to
    PIN-FAIL (expected, they now HIT). F1580-F1590 pins must stay
    pin-ok/prov-ok. Taxonomy, footer, nopaid must stay ok.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w419_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g420l1-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w419_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        pin_status = {}
        for line in out.split("\n"):
            m = re.match(r"(pin-ok|PIN-FAIL|carry-ok|prov-ok)\s+(F\d+)", line.strip())
            if m:
                pin_status[m.group(2)] = m.group(1)
        ok = True
        notes = []
        # F1570-F1573, F1575-F1579: expect PIN-FAIL (now HIT = closed)
        for fn in ["F1570", "F1571", "F1572", "F1573", "F1575",
                   "F1576", "F1577", "F1578", "F1579"]:
            st = pin_status.get(fn, "?")
            if st != "PIN-FAIL":
                ok = False
                notes.append(fn + "=" + st + "(want PIN-FAIL)")
        # F1580-F1589: expect pin-ok (still MISS = open)
        for fn in ["F1580", "F1581", "F1582", "F1583", "F1584",
                   "F1585", "F1586", "F1587", "F1588", "F1589"]:
            st = pin_status.get(fn, "?")
            if st != "pin-ok":
                ok = False
                notes.append(fn + "=" + st + "(want pin-ok)")
        # F1590: prov-ok
        if pin_status.get("F1590", "?") != "prov-ok":
            ok = False
            notes.append("F1590=" + pin_status.get("F1590", "?") + "(want prov-ok)")
        # taxonomy, footer, nopaid
        for tag in ["tax-ok", "footer-ok", "nopaid-ok"]:
            if tag not in out:
                ok = False
                notes.append(tag + " missing")
        if not notes:
            notes.append("F1570-F1579 flipped, F1580-F1590 held, tax/footer/nopaid ok")
        return (ok, "green(w419_attack): %s" % "; ".join(notes))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)


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
