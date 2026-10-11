#!/usr/bin/env python3
"""Wave-420 lane 2 close battery: F1580-F1589 CLOSED.

F1580: String.prototype.search pattern twins -- concatenated
  string ('xox'+'b'), String()-wrapped (String('xoxb')), and regex
  (/xoxb/) patterns with slice readout. Closed by
  `_js_f1580_stmt_decode`. Node-exact: the pattern has no regex
  metacharacters and is a prefix of dstr, so search returns 0.
  Disjoint from F1557 (plain string literal, direct RESULT).

F1581: String.prototype.replace identity twins -- `replaceAll`
  with identity function replacer and `replace` with
  regex-plus-identity-string. Closed by `_js_f1581_stmt_decode`.
  Node-exact: identity replacer returns subject unchanged;
  regex-source == replacement literal (no $ patterns) is the
  identity. Disjoint from F1558 (/./g identity), F1380, F1272.

F1582: Array.prototype.map with the Number constructor --
  string code array `A.map(Number)` then fromCharCode readout.
  Closed by `_js_f1582_stmt_decode`. Node-exact: Number() on
  canonical decimal strings, ToUint16 per code. Disjoint from
  F1559 (map(String)), F1528 (Array.from).

F1583: Object.assign array-copy with pre-sized target --
  `Object.assign(new Array(C.length),C)`. Closed by
  `_js_f1583_stmt_decode`. Node-exact: assign copies indices to
  the fresh array. Disjoint from F1560 (Object.assign([],C)).

F1584: Spread-call arguments staging -- `g(...C)` with
  `[...arguments]` spread readout. Closed by
  `_js_f1584_stmt_decode`. Node-exact: arguments holds the spread
  elements. Disjoint from F1561 (slice.call), F1529 (apply).

F1585: Array.prototype.flat depth twins -- flat(-1), flat(NaN)
  (no flattening, D[0] readout), flat(1) (one level, D readout).
  Closed by `_js_f1585_stmt_decode`. Node-exact:
  ToIntegerOrInfinity semantics. Disjoint from F1562 (flat(0)),
  F1432 (flat(2)), F1349, F1534.

F1586: Array.prototype.concat spread twins -- `[].concat(...C,
  ...[])` and `C.concat(...[])`. Closed by
  `_js_f1586_stmt_decode`. Node-exact: spread copies elements;
  empty spread contributes nothing. Disjoint from F1563
  ([].concat(...C)), F1387, F1538.

F1587: String.prototype.trim chained -- `(' '+S+' ').trim().
  trimStart().trimEnd()`. Closed by `_js_f1587_stmt_decode`.
  Node-exact: trim removes the padding; hook requires dstr with
  no edge whitespace. Disjoint from F1565, F1509-F1511.

F1588: String.prototype.replaceAll string-arg chained --
  `S.replaceAll('x','x')`. Closed by `_js_f1588_stmt_decode`.
  Node-exact: literal identity replacement (no $ patterns).
  Disjoint from F1566 (replace string-arg), F1380.

F1589: Array.prototype.slice two-arg computed --
  `C.slice(0,C.length)`. Closed by `_js_f1589_stmt_decode`.
  Node-exact: full-array copy. Disjoint from F1442, F1575.

New _decode_layer dispatch loop (F1580-F1589); N_STMTDEC_LOOPS
92->93 (real code-count change). Node-exact on all filed shapes
(short + 40-char, v24.20.0); fail-closed hook-level bounds;
sibling pins hold; F1570-F1579/F1590-F1607 still MISS.

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


def _strcodes(s):
    return "[" + ",".join('"%d"' % ord(c) for c in s) + "]"


def _hits(payload):
    """True if find_credential flags the payload (in-process)."""
    try:
        return bool(_dlp.find_credential(payload))
    except Exception:
        return False


def _misses(payload):
    return not _hits(payload)


_FILED = [
    ("f1580-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xox'+'b');var T=S.slice(K);var RESULT=T;"),
    ("f1580-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(String('xoxb'));var T=S.slice(K);var RESULT=T;"),
    ("f1580-2",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(/xoxb/);var T=S.slice(K);var RESULT=T;"),
    ("f1581-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll(/x/g,function(m){return m;});var RESULT=T;"),
    ("f1581-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/x/g,'x');var RESULT=T;"),
    ("f1582-0",
     "var A={J};var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1583-0",
     "var C={I};var D=Object.assign(new Array(C.length),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1584-0",
     "var C={I};function g(){return String.fromCharCode.apply(null,[...arguments]);}var S=g(...C);var RESULT=S;"),
    ("f1585-0",
     "var C={I};var D=[C].flat(-1);var S=String.fromCharCode.apply(null,D[0]);var RESULT=S;"),
    ("f1585-1",
     "var C={I};var D=[C].flat(NaN);var S=String.fromCharCode.apply(null,D[0]);var RESULT=S;"),
    ("f1585-2",
     "var C={I};var D=[C].flat(1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1586-0",
     "var C={I};var D=[].concat(...C,...[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1586-1",
     "var C={I};var D=C.concat(...[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1587-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trim().trimStart().trimEnd();var RESULT=T;"),
    ("f1588-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll('x','x');var RESULT=T;"),
    ("f1589-0",
     "var C={I};var D=C.slice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-419 lineage; N_STMTDEC_LOOPS=93; re.compile=29."""
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
    ok = (pin == 93 and len(loops) == 93)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w419 = "# Wave-419:" in ftxt
    ok = ok and has_w419
    notes.append("w419-footer=%s" % has_w419)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w419_attack_probes.py")) as f:
        asrc = f.read()
    ok = ok and ("2143" in asrc)
    notes.append("tax2143=%s" % ("2143" in asrc))
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
            payload = tmpl.replace("{I}", _codes(s)).replace("{J}",
                                                             _strcodes(s))
            if not _hits(payload):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const, renamed idents, ws-tolerance, arrow twin still HIT."""
    tmpls = [
        # F1580 let + renamed + ws
        "let C={I};let S=C.map(function(c){return String.fromCharCode(c);}).join('');let K2=S.search( 'xox' + 'b' );let T2=S.slice(K2);let RESULT=T2;",
        # F1580 arrow twin readout
        "var C={I};var S=C.map(c=>String.fromCharCode(c)).join('');var K=S.search(String('xoxb'));var T=S.slice(K);var RESULT=T;",
        # F1581 const + renamed
        "const C={I};const S=C.map(function(x){return String.fromCharCode(x);}).join('');const T2=S.replaceAll(/x/g,function(m){return m;});const RESULT=T2;",
        # F1582 let + renamed
        "let A={J};let E2=A.map(Number);let S2=String.fromCharCode.apply(null,E2);let RESULT=S2;",
        # F1583 const + renamed
        "const C={I};const D2=Object.assign(new Array(C.length),C);const S2=String.fromCharCode.apply(null,D2);const RESULT=S2;",
        # F1584 renamed function
        "var C={I};function h(){return String.fromCharCode.apply(null,[...arguments]);}var S=h(...C);var RESULT=S;",
        # F1585 ws-tolerance
        "var C={I};var D=[C].flat( -1 );var S=String.fromCharCode.apply(null,D[0]);var RESULT=S;",
        # F1586 renamed
        "var C={I};var D2=[].concat(...C,...[]);var S2=String.fromCharCode.apply(null,D2);var RESULT=S2;",
        # F1587 arrow twin
        "var C={I};var S=C.map(c=>String.fromCharCode(c)).join('');var T=(' '+S+' ').trim().trimStart().trimEnd();var RESULT=T;",
        # F1588 double quotes
        'var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join("");var T=S.replaceAll("x","x");var RESULT=T;',
        # F1589 let + ws
        "let C={I};let D=C.slice( 0 , C.length );let S=String.fromCharCode.apply(null,D);let RESULT=S;",
    ]
    bad = []
    for i, t in enumerate(tmpls):
        payload = t.replace("{I}", _codes(SECRET_S)).replace("{J}",
                                                              _strcodes(SECRET_S))
        if not _hits(payload):
            bad.append("g%d" % i)
    return (not bad, "%d/%d generalizations hit%s"
            % (len(tmpls) - len(bad), len(tmpls),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p3: fail-closed ----------------

@_t
def test_p3_fail_closed():
    """Wrong forms are NOT claimed (hook-level miss)."""
    cs = _codes(SECRET_S)
    cases = [
        # F1580: pattern not a prefix
        ("f1580-badlit",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('zzz');var T=S.slice(K);var RESULT=T;" % cs,
         _dlp._js_f1580_stmt_decode),
        # F1580: metacharacters
        ("f1580-metachar",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb.');var T=S.slice(K);var RESULT=T;" % cs,
         _dlp._js_f1580_stmt_decode),
        # F1580: regex with i flag
        ("f1580-regex-flag",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(/xoxb/i);var T=S.slice(K);var RESULT=T;" % cs,
         _dlp._js_f1580_stmt_decode),
        # F1580: regex with escape
        ("f1580-regex-esc",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(/xox\\b/);var T=S.slice(K);var RESULT=T;" % cs,
         _dlp._js_f1580_stmt_decode),
        # F1581: $ in replacement
        ("f1581-dollar",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/x/g,'$&');var RESULT=T;" % cs,
         _dlp._js_f1581_stmt_decode),
        # F1581: regex != repl
        ("f1581-mismatch",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/y/g,'x');var RESULT=T;" % cs,
         _dlp._js_f1581_stmt_decode),
        # F1581: non-identity function
        ("f1581-nonident",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll(/x/g,function(m){return 'z';});var RESULT=T;" % cs,
         _dlp._js_f1581_stmt_decode),
        # F1582: non-integer string
        ("f1582-nonstrint",
         'var A=["10a","105"];var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;',
         _dlp._js_f1582_stmt_decode),
        # F1582: empty array
        ("f1582-empty",
         'var A=[];var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;',
         _dlp._js_f1582_stmt_decode),
        # F1582: not Number
        ("f1582-nostring",
         "var A=%s;var E=A.map(String);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs,
         _dlp._js_f1582_stmt_decode),
        # F1583: wrong target
        ("f1583-bare",
         "var C=%s;var D=Object.assign([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1583_stmt_decode),
        # F1584: slice.call form (F1561)
        ("f1584-slicecall",
         "var C=%s;function g(){var A=Array.prototype.slice.call(arguments);return String.fromCharCode.apply(null,A);}var S=g(...C);var RESULT=S;" % cs,
         _dlp._js_f1584_stmt_decode),
        # F1585: flat(2)
        ("f1585-depth2",
         "var C=%s;var D=[C].flat(2);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1585_stmt_decode),
        # F1585: D[0] with depth 1
        ("f1585-d0-depth1",
         "var C=%s;var D=[C].flat(1);var S=String.fromCharCode.apply(null,D[0]);var RESULT=S;" % cs,
         _dlp._js_f1585_stmt_decode),
        # F1586: missing empty spread
        ("f1586-noempty",
         "var C=%s;var D=[].concat(...C);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1586_stmt_decode),
        # F1587: no trim head
        ("f1587-notrim",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trimStart().trimEnd();var RESULT=T;" % cs,
         _dlp._js_f1587_stmt_decode),
        # F1588: different strings
        ("f1588-mismatch",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll('x','y');var RESULT=T;" % cs,
         _dlp._js_f1588_stmt_decode),
        # F1588: $ pattern
        ("f1588-dollar",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll('x','$&');var RESULT=T;" % cs,
         _dlp._js_f1588_stmt_decode),
        # F1589: slice(0) only
        ("f1589-slice0",
         "var C=%s;var D=C.slice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs,
         _dlp._js_f1589_stmt_decode),
    ]
    bad = [n for n, p, fn in cases if fn(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """Neighboring hooks still HIT (disjoint by grammar)."""
    cs = _codes(SECRET_S)
    cases = [
        # F1557: search literal, direct RESULT (disjoint from F1580)
        ("f1557-search",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb');var RESULT=S.slice(K);" % cs),
        # F1558: replace /./g identity (disjoint from F1581)
        ("f1558-replace",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;" % cs),
        # F1559: map(String) (disjoint from F1582)
        ("f1559-mapstr",
         "var C=%s;var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1560: Object.assign([],C) (disjoint from F1583)
        ("f1560-assign",
         "var C=%s;var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1562: flat(0) (disjoint from F1585)
        ("f1562-flat0",
         "var C=%s;var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1563: [].concat(...C) (disjoint from F1586)
        ("f1563-concat",
         "var C=%s;var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        # F1565: trimStart/trimEnd without trim() (disjoint from F1587)
        ("f1565-trimse",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();" % cs),
        # F1566: replace string-arg (disjoint from F1588)
        ("f1566-replace",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','x');var RESULT=U;" % cs),
        # F1442: slice computed (disjoint from F1589)
        ("f1442-slice",
         "var C=%s;var D=C.slice(C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        # F1090: basic mapjoin
        ("f1090-mapjoin",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
    ]
    bad = [n for n, p in cases if not _hits(p)]
    return (not bad, "%d/%d siblings hit%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p5: honest quiet ----------------

@_t
def test_p5_honest_quiet():
    """Honest text stays quiet."""
    quiet = [
        "The quarterly financial summary shows revenue growth.",
        "var x=1;var y=x*2;console.log(y);",
        "function add(a,b){return a+b;}",
        "var s='  hello  ';console.log(s.trim());",
        "console.log('abc'.search('b'));",
        "console.log('abc'.replace(/x/g,'x'));",
        "var A=['1','2'];console.log(A.map(Number));",
        "var o=Object.assign({},a);console.log(o);",
        "function g(){return [...arguments];}",
        "console.log([1].flat(1));",
        "console.log([].concat([1]));",
        "console.log(' x '.trim());",
        "console.log('ax'.replaceAll('x','x'));",
        "console.log([1,2].slice(0,2));",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1570-F1579 and F1590-F1607 (other lanes, OPEN) still MISS.

    Uses the actual filed shapes from w419 red-first batteries.
    """
    cs = _codes(SECRET_S)
    cases = [
        ("f1570", "var C=%s;var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},\"xy\");var S=E.join('');var RESULT=S;" % cs),
        ("f1571", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'abc');var T=P.slice(-S.length);var RESULT=T;" % cs),
        ("f1572", "var C=%s;var D=C.slice().sort(function(a,b){return a>b;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
                ("f1573", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trim();var RESULT=T;" % cs),
        ("f1575", "var C=%s;var D=C.slice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1576", "var C=%s;var D=C.map(function(c){return (c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1577", "var C=%s;var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=C[i];}var S=A.toString().split(',').map(Number).map(function(n){return String.fromCharCode(n);}).join('');var RESULT=S;" % cs),
        ("f1578", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var U=T.slice(1,-1);var RESULT=U;" % cs),
        ("f1579", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',-0);var RESULT=OK?S:'';" % cs),
        ("f1590", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='<select><optgroup label=\"x\"><option>'+S+'</option></optgroup></select>';var RESULT=T;" % cs),
    ]
    bad = [n for n, p in cases if not _misses(p)]
    return (not bad, "%d/%d other-opens miss%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p7: perf ----------------

@_t
def test_p7_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xox'+'b');var T=S.slice(K);var RESULT=T;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=[C].flat(1);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 2:
            sites.append("The quarterly financial summary shows revenue growth %d." % i)
        elif i % 5 == 3:
            sites.append("var x=%d;var y=x*2;" % i)
        else:
            sites.append("function f%d(){return %d;}" % (i, i))
    t0 = time.time()
    for s in sites:
        _dlp.find_credential(s)
    dt = time.time() - t0
    return (dt < 120, "200 sites in %.1fs" % dt)


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w419_attack_probes.

    F1580-F1589 are now closed by this lane (their pins must break);
    F1570-F1579 and F1590-F1607 remain open (their pins must hold).
    Taxonomy (2143) and footer pins must hold. Honors GOV_SKIP_GREEN.

    Note: F1582's pin uses a hardcoded 2-char payload (["120","111"]
    -> "xo") that never forms a credential, so its pin stays MISS
    even though the hook works. We verify the hook directly instead.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w419_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g420l2-green-", dir="/var/tmp")
    try:
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w419_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        held = set()
        broken = set()
        for line in out.split("\n"):
            if line.startswith("pin-ok "):
                parts = line.split()
                if len(parts) >= 2:
                    held.add(parts[1])
            elif line.startswith("PIN-FAIL "):
                parts = line.split()
                if len(parts) >= 2:
                    broken.add(parts[1])
        # F1580-F1589 except F1582 (see note above)
        # w419_attack_probes.py has pins for F1570-F1590 only;
        # F1591-F1607 are lane-filed (not in attack probes).
        # F1590 is a provenance pin (prov-ok QUIET).
        # F1574 is CLOSED (incidental wave-419), not in open pins.
        expect_held = ({"F%d" % n for n in range(1570, 1580) if n != 1574} |
                       {"F1582"})
        expect_broken = ({"F%d" % n for n in range(1580, 1590)} -
                         {"F1582"})
        ok = (expect_held <= held and expect_broken <= broken)
        # Verify F1590 provenance still QUIET
        prov_ok = "prov-ok F1590 QUIET" in out
        ok = ok and prov_ok
        # Verify F1582 hook directly on the pin payload
        f1582_payload = 'var A=["120","111"];var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;'
        f1582_hook_ok = (_dlp._js_f1582_stmt_decode(f1582_payload) == "xo")
        ok = ok and f1582_hook_ok
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = ok and tax and footer
        return (ok, "green(w419_attack): held=%s broken=%s f1582-hook=%s prov1590=%s tax=%s footer=%s"
                % (sorted(held & expect_held) == sorted(expect_held),
                   sorted(broken & expect_broken) == sorted(expect_broken),
                   f1582_hook_ok, prov_ok, tax, footer))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)
    finally:
        import shutil
        shutil.rmtree(tmpd, ignore_errors=True)


@_t
def test_g0_green():
    return _green_check()


# ---------------- main ----------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", default=None)
    args = parser.parse_args()
    fails = 0
    total = 0
    for fn in TESTS:
        if args.only and args.only not in fn.__name__:
            continue
        total += 1
        try:
            ok, note = fn()
        except Exception as e:  # noqa: BLE001
            ok, note = False, "EXC %r" % e
        print(("%s %s: %s" % ("HELD" if ok else "BREAK",
                              fn.__name__, note)))
        if not ok:
            fails += 1
    print("RESULT: %d/%d HELD" % (total - fails, total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
