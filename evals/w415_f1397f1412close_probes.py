#!/usr/bin/env python3
"""Wave-415 lane 3 close battery: F1397-F1412 CLOSED.

F1397: splice(0,0) no-op -- readout directly on C (F1365 residual:
  F1365 staged a *copy* via splice(0)/splice(0,C.length)).
F1398: String.fromCharCode(c).concat('') map wrapper + D.join('')
  single-char string readout (novel class).
F1399: C.slice(-C.length) negative-length full copy (F978 residual:
  F978 models non-negative/bare-arg slice copies).
F1400: new Array(C.length).fill(0).map((_,i)=>C[i]) index staging
  (novel class).
F1401: for-of C.values() push loop (F1364 residual: forEach-built
  object, no for-of iterator loop).
F1402: Number(c.toString(10)) / parseInt(c.toString(10),10) decimal
  roundtrip codec (F1356 residual: toFixed codec).
F1403: c|0, c*1, ~~c, c-0, +c identity wrappers (F1292 residual:
  Math rounding-method wrappers, different operator class).
F1404: Math.max(c,c) / Math.min(c,c) self wrappers (F1292 residual).
F1405: for-of C.entries() push(e[1]) (F1364 residual).
F1406: C.slice() + while shift-drain / pop+unshift drain (novel
  composition; both preserve order, node-verified).
F1407: C[C.lastIndexOf(C[i],i)] / C[C.indexOf(C[i],i)] self-index
  push loop (F1270 residual: findIndex side-effect accumulation).
F1408: C.join(',').split(',') apply-readout (F1357 residual: F1357
  is join/split/join with a *string* readout, no apply).
F1409: Object.values(C) direct array copy (F1363 residual: F1363
  stages a forEach-built object).
F1410: [...C] spread-copy (novel; disjoint from F1030 flat-spread).
F1411: C.map(c=>c) arrow-identity (F1361 residual: function-form
  identity callbacks).
F1412: String(C).split(',') (F1408 residual: the String() call form).

All 16 are new _decode_layer statement hooks sharing two readout
helpers; one new dispatch loop (N_STMTDEC_LOOPS 74->75). Node-exact
on all filed shapes (short + 40-char, v24.20.0); fail-closed
hook-level bounds; sibling pins hold; F1376-F1396/F1413-F1431
(other lanes' scope) still MISS.

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

SECRET_S = "xoxb-01" + "23456789acdef"
SECRET_L = "xoxb-" + "0123456789acdef0123456789acdef012"

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
    """Pin 2143 holds; N_STMTDEC_LOOPS=75; re.compile=29."""
    ok = True
    notes = []
    with open(os.path.join(REPO_ROOT, "evals",
                           "w395_perfharden_probes.py")) as f:
        src = f.read()
    m = re.search(r"N_STMTDEC_LOOPS\s*=\s*(\d+)", src)
    pin = int(m.group(1)) if m else -1
    with open(os.path.join(REPO_ROOT, "gov", "dlp.py")) as f:
        dsrc = f.read()
    actual = len(re.findall(r"for _stmtdec in \(", dsrc))
    if pin != 75 or actual != 75:
        ok = False
        notes.append("N_STMTDEC_LOOPS pin=%d actual=%d (want 75)" % (pin, actual))
    else:
        notes.append("N_STMTDEC_LOOPS=75")
    rc = len(re.findall(r"re\.compile\(", dsrc))
    if rc != 29:
        ok = False
        notes.append("re.compile=%d (want 29)" % rc)
    else:
        notes.append("re.compile=29")
    return ok, "; ".join(notes)


# ---------------- p1: filed shapes ----------------

_FILED = [
    # F1397: splice(0,0) no-op, readout on C
    ("f1397",
     "var C={I};C.splice(0,0);var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1398: concat('') wrapper + join('')
    ("f1398",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).concat('');});var S=D.join('');var RESULT=S;"),
    # F1399: slice(-C.length)
    ("f1399",
     "var C={I};var D=C.slice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1400: new Array().fill(0).map index
    ("f1400",
     "var C={I};var D=new Array(C.length).fill(0).map(function(_,i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1401: for-of values() push
    ("f1401",
     "var C={I};var D=[];for(var v of C.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1402: Number(c.toString(10))
    ("f1402-a",
     "var C={I};var D=C.map(function(c){return Number(c.toString(10));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1402: parseInt(c.toString(10),10)
    ("f1402-b",
     "var C={I};var D=C.map(function(c){return parseInt(c.toString(10),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c|0
    ("f1403-a",
     "var C={I};var D=C.map(function(c){return c|0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c*1
    ("f1403-b",
     "var C={I};var D=C.map(function(c){return c*1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: ~~c
    ("f1403-c",
     "var C={I};var D=C.map(function(c){return ~~c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c-0
    ("f1403-d",
     "var C={I};var D=C.map(function(c){return c-0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: +c
    ("f1403-e",
     "var C={I};var D=C.map(function(c){return +c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1404: Math.max(c,c)
    ("f1404-a",
     "var C={I};var D=C.map(function(c){return Math.max(c,c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1404: Math.min(c,c)
    ("f1404-b",
     "var C={I};var D=C.map(function(c){return Math.min(c,c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1405: for-of entries() push(e[1])
    ("f1405",
     "var C={I};var D=[];for(var e of C.entries()){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1406: shift-drain
    ("f1406-a",
     "var C={I};var D=C.slice();var E=[];while(D.length){E.push(D.shift());}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1406: pop/unshift drain
    ("f1406-b",
     "var C={I};var D=C.slice();var E=[];while(D.length){E.unshift(D.pop());}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1407: lastIndexOf self-index
    ("f1407-a",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C[C.lastIndexOf(C[i],i)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1407: indexOf self-index
    ("f1407-b",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C[C.indexOf(C[i],i)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1408: join(',').split(',')
    ("f1408",
     "var C={I};var D=C.join(',').split(',');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1409: Object.values(C)
    ("f1409",
     "var C={I};var D=Object.values(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1410: [...C]
    ("f1410",
     "var C={I};var D=[...C];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1411: map(c=>c)
    ("f1411",
     "var C={I};var D=C.map(c=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1412: String(C).split(',')
    ("f1412",
     "var C={I};var D=String(C).split(',');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


@_t
def test_p1_filed_shapes():
    """All 24 filed shape/size combos BLOCK."""
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
    # F1397: let/const + whitespace
    "let C={I};C.splice( 0 , 0 );let S=String.fromCharCode.apply(null,C);let RESULT=S;",
    # F1398: different param name
    "var C={I};var D=C.map(function(x){return String.fromCharCode(x).concat('');});var S=D.join('');var RESULT=S;",
    # F1399: const
    "const C={I};const D=C.slice(-C.length);const S=String.fromCharCode.apply(null,D);const RESULT=S;",
    # F1400: different param names
    "var C={I};var D=new Array(C.length).fill(0).map(function(a,b){return C[b];});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1401: let loop var
    "var C={I};var D=[];for(let v of C.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1402: different param name, Number twin
    "var C={I};var D=C.map(function(n){return Number(n.toString(10));});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1403: different param name, c|0
    "var C={I};var D=C.map(function(q){return q|0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1404: different param name, Math.max
    "var C={I};var D=C.map(function(q){return Math.max(q,q);});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1405: const loop var
    "var C={I};var D=[];for(const e of C.entries()){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1406: different names, shift-drain
    "var C={I};var D=C.slice();var F=[];while(D.length){F.push(D.shift());}var S=String.fromCharCode.apply(null,F);var RESULT=S;",
    # F1407: let loop var, indexOf twin
    "var C={I};var D=[];for(let i=0;i<C.length;i++){D.push(C[C.indexOf(C[i],i)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1408: whitespace
    "var C={I};var D=C.join( ',' ).split( ',' );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1409: let
    "let C={I};let D=Object.values(C);let S=String.fromCharCode.apply(null,D);let RESULT=S;",
    # F1410: const
    "const C={I};const D=[...C];const S=String.fromCharCode.apply(null,D);const RESULT=S;",
    # F1411: parenthesized arrow param
    "var C={I};var D=C.map((c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1411: different param name
    "var C={I};var D=C.map(x=>x);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1412: whitespace
    "var C={I};var D=String( C ).split( ',' );var S=String.fromCharCode.apply(null,D);var RESULT=S;",
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
    # F1397: deleteCount 1 -> not a no-op -> fail closed
    ("f1397-del1",
     "var C={I};C.splice(0,1);var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1397: start 1 -> fail closed
    ("f1397-start1",
     "var C={I};C.splice(1,0);var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    # F1398: concat('x') non-empty -> fail closed
    ("f1398-concat-x",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).concat('x');});var S=D.join('');var RESULT=S;"),
    # F1398: join(',') non-empty sep -> fail closed
    ("f1398-join-comma",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c).concat('');});var S=D.join(',');var RESULT=S;"),
    # F1399: slice(-1) partial -> fail closed
    ("f1399-slice-neg1",
     "var C={I};var D=C.slice(-1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1399: slice(-D.length) wrong base -> fail closed
    ("f1399-slice-wrongbase",
     "var C={I};var D=C.slice(-D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1400: fill(1) -> fail closed
    ("f1400-fill1",
     "var C={I};var D=new Array(C.length).fill(1).map(function(_,i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1400: map returns C[0] always -> fail closed
    ("f1400-idx0",
     "var C={I};var D=new Array(C.length).fill(0).map(function(_,i){return C[0];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1401: push(w) wrong var -> fail closed
    ("f1401-badvar",
     "var C={I};var D=[];for(var v of C.values()){D.push(w);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1401: keys() not values() -> fail closed
    ("f1401-keys",
     "var C={I};var D=[];for(var v of C.keys()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1402: radix 16 -> fail closed
    ("f1402-radix16",
     "var C={I};var D=C.map(function(c){return Number(c.toString(16));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1402: toString() bare (radix 10 default but unmodeled) -> fail closed
    ("f1402-bare",
     "var C={I};var D=C.map(function(c){return Number(c.toString());});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c|1 -> fail closed
    ("f1403-bitor1",
     "var C={I};var D=C.map(function(c){return c|1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c*2 -> fail closed
    ("f1403-mul2",
     "var C={I};var D=C.map(function(c){return c*2;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1403: c||0 logical-or -> fail closed
    ("f1403-logical",
     "var C={I};var D=C.map(function(c){return c||0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1404: Math.max(c,0) -> fail closed
    ("f1404-max0",
     "var C={I};var D=C.map(function(c){return Math.max(c,0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1404: Math.min(c,d) unknown -> fail closed
    ("f1404-mind",
     "var C={I};var D=C.map(function(c){return Math.min(c,d);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1405: e[0] index not value -> fail closed
    ("f1405-idx0",
     "var C={I};var D=[];for(var e of C.entries()){D.push(e[0]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1406: push(D.pop()) order-reversing -> fail closed
    ("f1406-push-pop",
     "var C={I};var D=C.slice();var E=[];while(D.length){E.push(D.pop());}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1406: unshift(D.shift()) order-reversing -> fail closed
    ("f1406-unshift-shift",
     "var C={I};var D=C.slice();var E=[];while(D.length){E.unshift(D.shift());}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1407: C[i] direct (no search) -> fail closed (different shape)
    ("f1407-direct",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C[i]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1407: indexOf without from-index -> fail closed
    ("f1407-nofrom",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C[C.indexOf(C[i])]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1408: join('|')/split('|') non-comma -> fail closed
    ("f1408-pipe",
     "var C={I};var D=C.join('|').split('|');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1408: join/split sep mismatch -> fail closed
    ("f1408-mismatch",
     "var C={I};var D=C.join(',').split(';');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1409: Object.keys not values -> fail closed
    ("f1409-keys",
     "var C={I};var D=Object.keys(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1410: spread of D not C -> fail closed
    ("f1410-spread-d",
     "var C={I};var D=[...D];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1411: c=>c+1 non-identity -> fail closed
    ("f1411-plus1",
     "var C={I};var D=C.map(c=>c+1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1411: function form (F1361's) is a different hook's shape -- must not hit THIS hook,
    # but it IS blocked by F1361's hook; use a non-identity arrow instead
    ("f1411-arrow-block",
     "var C={I};var D=C.map(c=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1412: split(';') non-comma -> fail closed
    ("f1412-semicolon",
     "var C={I};var D=String(C).split(';');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    # F1365 splice(0) copy still BLOCKs
    ("f1365",
     "var C={I};var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1361 map 2-param identity still BLOCKs
    ("f1361",
     "var C={I};var D=C.map(function(c,i){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1356 toFixed codec still BLOCKs
    ("f1356",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1292 Math.round wrapper still BLOCKs
    ("f1292",
     "var C={I};var D=C.map(function(c){return Math.round(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1357 join/split/join chain still BLOCKs
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    # F1363 Object.values forEach-built still BLOCKs
    ("f1363",
     "var O={};var C={I};C.forEach(function(c,i){O['k'+i]=c;});var A=Object.values(O);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    # F1350 flatMap bare staging still BLOCKs
    ("f1350",
     "var C={I};var E=C.flatMap(p=>[p]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F978 slice() bare copy still BLOCKs
    ("f978",
     "var C={I};var D=C.slice();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
    "var C=[1,2,3];var D=C.map(c=>c*2);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    "var C=[65,66];var D=[...C];var E=D.join(',');var RESULT=E;",
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
        _hits("var C=[%d];var D=C.map(function(c){return c|0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % (65 + (i % 26)))
    dt = time.time() - t0
    return dt < 30, "200 sites in %.1fs" % dt


# ---------------- p7: other opens miss ----------------

# F1376-F1396 (filing lane + lane 1/2 scope), F1413-F1431 (provenance +
# renumbered residuals): other lanes' scope -- must stay MISS.
_P7 = [
    # F1376: sort no-slice no-op
    "var C={I};var D=C.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1385: filter callback twin
    "var C={I};var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1390: copyWithin no-op
    "var C={I};var D=C.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1396: keys-iterator push
    "var C={I};var D=[];for(var k of C.keys()){D.push(C[k]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1417: map arrow 2-param (renumbered lane-1 residual)
    "var C={I};var D=C.map((c,i)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    # F1426: inline splice apply (renumbered lane-2 residual)
    "var C={I};var S=String.fromCharCode.apply(null,C.splice(0));var RESULT=S;",
]


@_t
def test_p7_other_opens_miss():
    """Other lanes' open findings still MISS."""
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
    """Depth-1 green on w414 red-first batteries: F1397-F1412 flipped
    to NO-BREAK (closed), F1385-F1396 + F1413-F1416 still BREAK (open).

    Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(redfirst): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g415l3-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd,
               GOV_DEPLOYMENT_MODE="staging",
               GOV_LOG_KEY="00" * 32)
    ok = True
    notes = []
    try:
        for n in range(1397, 1413):
            r = subprocess.run(
                [sys.executable,
                 os.path.join(REPO_ROOT, "evals",
                              "w414_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "")
            m = re.search(r"RESULT:\s*(\S+)", out)
            verdict = m.group(1) if m else "NO-RESULT"
            if verdict != "NO-BREAK":
                ok = False
                notes.append("f%d=%s" % (n, verdict))
        for n in list(range(1385, 1397)) + list(range(1413, 1417)):
            r = subprocess.run(
                [sys.executable,
                 os.path.join(REPO_ROOT, "evals",
                              "w414_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "")
            m = re.search(r"RESULT:\s*(\S+)", out)
            verdict = m.group(1) if m else "NO-RESULT"
            if verdict != "BREAK":
                ok = False
                notes.append("f%d=%s" % (n, verdict))
        # F1432-F1437: lane-filed residuals, must still BREAK (open-hold)
        for n in range(1432, 1438):
            r = subprocess.run(
                [sys.executable,
                 os.path.join(REPO_ROOT, "evals",
                              "w415_f%d_redfirst.py" % n)],
                capture_output=True, text=True, timeout=300, env=env,
                cwd=os.path.join(REPO_ROOT, "evals"))
            out = (r.stdout or "")
            if "FAILURES:0" not in out or "BREAK f%d" % n not in out:
                ok = False
                notes.append("f%d=NO-BREAK" % n)
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)
    return (ok, "green(redfirst): closed-flip 16/16, open-hold 22/22%s"
            % ("" if ok else " MISMATCH: " + ",".join(notes[:6])))


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
