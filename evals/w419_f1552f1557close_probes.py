#!/usr/bin/env python3
"""Wave-419 lane 2 close battery: F1552-F1557 CLOSED.

F1552: Array.prototype.splice two-arg no-op twins --
  `var D=C.slice();D.splice(0,0);` and `D.splice(C.length,0);`
  (bare statements). Closed by `_js_f1552_stmt_decode`. Node-exact:
  both are pure no-ops, so D is the C.slice() copy. Disjoint from
  F1365 (splice(0)/splice(0,C.length) copy forms), F1443
  (splice(-C.length)), F1513 (splice(-1,1)), F1426 (inline splice).

F1553: Number/String valueOf wrapper twins -- per-element
  `new Number(c).valueOf()` map wrapper and whole-string
  `S.valueOf()` readout. Closed by `_js_f1553_stmt_decode`.
  Node-exact: boxing+unboxing is the identity; valueOf on a string
  primitive is the identity. Disjoint from F1514 (valueOf on the
  fcc result directly), F1523 ((new String(...)).valueOf() boxing
  twin; String(C) call form).

F1554: Array.prototype.toString on sparse arrays --
  `new Array(C.length*2)` with even-index fill, holes at odd
  indices, `A.toString().split(',').join('')`. Closed by
  `_js_f1554_stmt_decode`. Node-exact: holes render as empty
  strings. Fail-closed on comma codes (code 44 renders
  indistinguishably). Disjoint from F1515 (dense toString).

F1555: String.raw live template --
  ``var T=String.raw`a${S}b`;var RESULT=T.slice(1,-1);``.
  Closed by `_js_f1555_stmt_decode`. Node-exact: single-char
  affixes stripped by slice(1,-1). Disjoint from F1516 (dead
  tagged-template strip -- here the template is live).

F1556: String.prototype.includes with NaN fromIndex --
  `S.includes('xoxb',NaN)` (NaN coerces to 0) + `OK?S:''`.
  Closed by `_js_f1556_stmt_decode`. Node-exact: the hook requires
  the search literal to be a prefix of dstr, so includes() is
  provably true. Disjoint from F1517/F1524 (array filter forms).

F1557: String.prototype.search with a string pattern --
  `S.search('xoxb')` + `S.slice(K)`. Closed by
  `_js_f1557_stmt_decode`. Node-exact: the hook requires no regex
  metacharacters and a dstr prefix, so K is provably 0.
  Disjoint from F1525 (match readout).

New _decode_layer dispatch loop (F1552-F1557); N_STMTDEC_LOOPS
88->89 (real code-count change). Node-exact on all filed shapes
(short + 40-char, v24.20.0); fail-closed hook-level bounds;
sibling pins hold; F1546-F1551/F1558-F1569 still MISS.

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


_FILED = [
    ("f1552-0",
     "var C={I};var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1552-1",
     "var C={I};var D=C.slice();D.splice(C.length,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1553-0",
     "var C={I};var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("f1553-1",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.valueOf();"),
    ("f1554-0",
     "var C={I};var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');"),
    ("f1555-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b`;var RESULT=T.slice(1,-1);"),
    ("f1556-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',NaN);var RESULT=OK?S:'';"),
    ("f1557-0",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb');var RESULT=S.slice(K);"),
]


# ---------------- p0: pin/footer pins ----------------

@_t
def test_p0_pins():
    """Pin 2143 holds; footer has wave-418 lineage; N_STMTDEC_LOOPS=89; re.compile=29."""
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
    ok = (pin == 89 and len(loops) == 89)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w418 = "# Wave-418:" in ftxt
    ok = ok and has_w418
    notes.append("w418-footer=%s" % has_w418)
    with open(os.path.join(REPO_ROOT, "evals",
                           "w418_attack_probes.py")) as f:
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
            if not _hits(tmpl.replace("{I}", _codes(s))):
                bad.append("%s-%s" % (name, "s" if s == SECRET_S else "l"))
    return (not bad, "%d/%d filed hit%s"
            % (total - len(bad), total, "" if not bad else ": " + ",".join(bad[:5])))


# ---------------- p2: generalizations ----------------

@_t
def test_p2_generalizations():
    """let/const, renamed idents, ws-tolerance, arrow twin still HIT."""
    tmpls = [
        # F1552 let + renamed + ws
        "let C={I};let D=C.slice();D.splice( 0 , 0 );let S=D.map(function(c){return String.fromCharCode(c);}).join('');let RESULT=S;",
        # F1552 arrow twin readout
        "var C={I};var D=C.slice();D.splice(C.length,0);var S=D.map(c=>String.fromCharCode(c)).join('');var RESULT=S;",
        # F1553 const + renamed
        "const C={I};const D=C.map(function(x){return new Number(x).valueOf();});const S=D.map(function(x){return String.fromCharCode(x);}).join('');const RESULT=S;",
        # F1554 let + renamed loop var
        "let C={I};let A=new Array(C.length*2);for(let k=0;k<C.length;k++){A[k*2]=String.fromCharCode(C[k]);}let RESULT=A.toString().split(',').join('');",
        # F1555 different single-char affixes
        "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`x${S}y`;var RESULT=T.slice(1,-1);",
        # F1555 const
        "const C={I};const S=C.map(function(c){return String.fromCharCode(c);}).join('');const T=String.raw`a${S}b`;const RESULT=T.slice(1,-1);",
        # F1556 renamed + ws
        "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK2=S.includes( 'xoxb' , NaN );var RESULT=OK2?S:'';",
        # F1557 renamed
        "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K2=S.search('xoxb');var RESULT=S.slice(K2);",
    ]
    bad = []
    for i, t in enumerate(tmpls):
        if not _hits(t.replace("{I}", _codes(SECRET_S))):
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
        ("f1552-dc1",
         "var C=%s;var D=C.slice();D.splice(0,1);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1552_stmt_decode),
        ("f1552-start1",
         "var C=%s;var D=C.slice();D.splice(1,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1552_stmt_decode),
        ("f1552-dc2",
         "var C=%s;var D=C.slice();D.splice(0,2);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1552_stmt_decode),
        ("f1552-onearg",
         "var C=%s;var D=C.slice();D.splice(0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1552_stmt_decode),
        ("f1553-nonew",
         "var C=%s;var D=C.map(function(c){return Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1553_stmt_decode),
        ("f1553-stringbox",
         "var C=%s;var D=C.map(function(c){return new String(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs,
         _dlp._js_f1553_stmt_decode),
        ("f1554-comma",
         "var C=[44];var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');",
         _dlp._js_f1554_stmt_decode),
        ("f1554-len3",
         "var C=%s;var A=new Array(C.length*3);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');" % cs,
         _dlp._js_f1554_stmt_decode),
        ("f1554-idx1",
         "var C=%s;var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');" % cs,
         _dlp._js_f1554_stmt_decode),
        ("f1555-slice02",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b`;var RESULT=T.slice(0,-1);" % cs,
         _dlp._js_f1555_stmt_decode),
        ("f1555-2char",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`ab${S}b`;var RESULT=T.slice(1,-1);" % cs,
         _dlp._js_f1555_stmt_decode),
        ("f1555-noslice",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b`;var RESULT=T;" % cs,
         _dlp._js_f1555_stmt_decode),
        ("f1556-badlit",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('zzz',NaN);var RESULT=OK?S:'';" % cs,
         _dlp._js_f1556_stmt_decode),
        ("f1556-noNaN",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',0);var RESULT=OK?S:'';" % cs,
         _dlp._js_f1556_stmt_decode),
        ("f1556-nonempty-else",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',NaN);var RESULT=OK?S:'?';" % cs,
         _dlp._js_f1556_stmt_decode),
        ("f1557-metachar",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb.');var RESULT=S.slice(K);" % cs,
         _dlp._js_f1557_stmt_decode),
        ("f1557-badlit",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('zzz');var RESULT=S.slice(K);" % cs,
         _dlp._js_f1557_stmt_decode),
        ("f1557-caret",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('^xoxb');var RESULT=S.slice(K);" % cs,
         _dlp._js_f1557_stmt_decode),
        # Spec review H-1: regex literal in search (not a quoted string)
        ("f1557-regex",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(/xox\\d/);var RESULT=S.slice(K);" % cs,
         _dlp._js_f1557_stmt_decode),
        # Spec review H-2: regex literal in includes (throws in node)
        ("f1556-regex",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes(/xoxb/,NaN);var RESULT=OK?S:'';" % cs,
         _dlp._js_f1556_stmt_decode),
        # Spec review H-3: // is a line comment, not an empty string
        ("f1554-join-comment",
         "var C=%s;var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join(//);" % cs,
         _dlp._js_f1554_stmt_decode),
        ("f1556-ternary-comment",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',NaN);var RESULT=OK?S://;" % cs,
         _dlp._js_f1556_stmt_decode),
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
        ("f1365-splice0",
         "var C=%s;var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1443-spliceneg",
         "var C=%s;var D=C.splice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1513-splicedrain",
         "var C=%s;var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1514-valueof",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;" % cs),
        ("f1523-newstring",
         "var C=%s;var E=C.map(function(c){return (new String(String.fromCharCode(c))).valueOf();});var RESULT=E.join('');" % cs),
        ("f1515-tostring",
         "var C=%s;var S=C.toString();var RESULT=S.split(',').map(Number).map(function(n){return String.fromCharCode(n);}).join('');" % cs),
        ("f1517-includes",
         "var C=%s;var D=C.filter(function(c){return C.includes(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1524-includes0",
         "var C=%s;var E=C.filter(function(c,i){return C.includes(c,0);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1525-match",
         "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');" % cs),
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
        "var arr=[1,2,3];arr.splice(0,0);console.log(arr);",
        "var n=new Number(5);console.log(n.valueOf());",
        "var t=String.raw`hello`;console.log(t);",
        "console.log('abc'.includes('b',NaN));",
        "console.log('abc'.search('b'));",
        "var A=new Array(10);console.log(A.toString());",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: other opens still miss ----------------

@_t
def test_p6_other_opens_miss():
    """F1546-F1551 and F1558-F1569 (other lanes, OPEN) still MISS."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1546", "var C=%s;var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;" % cs),
        ("f1547", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);" % cs),
        ("f1548", "var C=%s;var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs),
        ("f1549", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\u2003'+S+'\u2003';var RESULT=T.trim();" % cs),
        ("f1550", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('<>');var T=S.split('<>').join('');var RESULT=T;" % cs),
        ("f1551", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);" % cs),
        ("f1558", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;" % cs),
        ("f1559", "var C=%s;var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1560", "var C=%s;var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1561", "var C=%s;function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);" % cs),
        ("f1562", "var C=%s;var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1563", "var C=%s;var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1564", "var C=%s;var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');" % cs),
        ("f1565", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();" % cs),
        ("f1566", "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','x');var RESULT=U;" % cs),
        ("f1568", "var C=%s;var E=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
        ("f1569", "var C=%s;var E=C.flatMap((c,i,a,t)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs),
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
                "var C=%s;var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb');var RESULT=S.slice(K);" % cs)
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
    """Depth-1 green on w418_attack_probes.

    F1552-F1557 are now closed by this lane (their pins must break);
    F1546-F1551 and F1558-F1569 remain open (their pins must hold).
    Taxonomy (2143) and footer pins must hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w418_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g419l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w418_attack_probes.py")],
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
        expect_held = ({"F%d" % n for n in range(1546, 1552)} |
                       {"F%d" % n for n in range(1558, 1570)})
        expect_broken = {"F%d" % n for n in range(1552, 1558)}
        ok = (expect_held <= held and expect_broken <= broken)
        tax = "tax-ok" in out
        footer = "footer-ok" in out
        ok = ok and tax and footer
        return (ok, "green(w418_attack): held=%s broken=%s tax=%s footer=%s"
                % (sorted(held & expect_held) == sorted(expect_held),
                   sorted(broken & expect_broken) == sorted(expect_broken),
                   tax, footer))
    except Exception as e:  # noqa: BLE001
        return (False, "green check error: %r" % e)


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
