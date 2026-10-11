#!/usr/bin/env python3
"""Wave-416 lane 2 close battery: F1443-F1455 CLOSED.

F1443: Array.prototype.splice negative-index copy staging (F1365
  residual) -- `var D=C.splice(-C.length);`. Closed by
  `_js_f1443_stmt_decode` (only the exact `-C.length` form admitted).
  Disjoint from F1365 (splice(0)/splice(0,C.length)) by grammar.

F1444: Array.prototype.copyWithin two-arg no-op staging (F1390
  residual) -- `var D=C.slice();D.copyWithin(0,0);`. Closed by
  `_js_f1444_stmt_decode` (only the exact two-arg (0,0) form).
  Disjoint from F1390 (three-arg copyWithin(0,0,D.length)) by grammar.

F1445: Array.prototype.fill identity-loop staging (F1400 residual) --
  `for(var i=0;i<D.length;i++){D.fill(C[i],i,i+1);}`. Closed by
  `_js_f1445_stmt_decode`. Disjoint from F1400 (fill+map) by grammar.

F1446: Map-constructor values-spread staging (F1353/F1354 residual) --
  `new Map(C.map(function(c,i){return [i,c];}))` drained by
  `for(var v of M.values()){D.push(v);}`. Closed by
  `_js_f1446_stmt_decode`. Disjoint from F989 (pair-list literal) and
  F1353/F1354 (fromEntries) by grammar.

F1447: Array.of spread staging (F1410 residual) --
  `Array.of.apply(null,C)`. Closed by `_js_f1447_stmt_decode`.
  Disjoint from F1410 ([...C] spread) by grammar.

F1448: Array.prototype.findIndex array-accumulation (F1394 residual) --
  `C.findIndex(function(c){D.push(c);return false;});`. Closed by
  `_js_f1448_stmt_decode` (callback must return exactly false).
  Disjoint from F1270 (S+=) and F1394 (find) by grammar.

F1449: flatMap three-param callback staging (F1377 residual) --
  `C.flatMap(function(c,i,a){return [c];})`. Closed by
  `_js_f1449_stmt_decode`. Disjoint from F1350 (1-param) and F1377
  (2-param) by grammar.

F1450: map three-param function staging (F1418 residual) --
  `C.map(function(c,i,a){return c;})`. Closed by
  `_js_f1450_stmt_decode`. Disjoint from F1361 (2-param function)
  and F1418 (3-param arrow) by grammar.

F1451: forEach thisArg staging (novel builtin class) --
  `C.forEach(function(c){D.push(c);},null);`. Closed by
  `_js_f1451_stmt_decode` (only the exact `,null` thisArg). Disjoint
  from no-thisArg forEach forms by grammar.

F1452: reduceRight unshift-accumulator staging (F1386 residual) --
  `C.reduceRight(function(a,c){a.unshift(c);return a;},[])`. Closed by
  `_js_f1452_stmt_decode`. Disjoint from F1358 (reduceRight string)
  and F1386 (reduce push) by grammar.

F1453: filter membership-predicate twins (F1385 residual) --
  `C.filter(function(c){return C.indexOf(c)!==-1;})` /
  `C.filter(function(c){return C.includes(c);})`. Closed by
  `_js_f1453_stmt_decode`. Disjoint from F1385 (truthy/identity) by
  grammar.

F1454: Object() array-boxing staging (novel builtin class) --
  `Object(C)` returns the array itself. Closed by
  `_js_f1454_stmt_decode`. Novel wrapper, no sibling.

F1455: Buffer.from staging (F1112 residual) --
  `Buffer.from(C)` + `Array.from(B)`; decode is byte-masked
  (ToUint8, node-verified: 300 -> 44). Closed by
  `_js_f1455_stmt_decode`. Disjoint from F1112 (TypedArray) by
  grammar.

New _decode_layer dispatch loop (F1443-F1455); N_STMTDEC_LOOPS 77->78
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1432-F1442 + F1456-F1503 (outside this lane) still MISS.

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
    """Pin 2143 holds; footer has wave-415 lineage; N_STMTDEC_LOOPS=78."""
    ok = True
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
    ok = (pin == 78 and len(loops) == 78)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w415 = "# Wave-415:" in ftxt
    ok = ok and has_w415
    notes.append("w415-footer=%s" % has_w415)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w415_attack_probes.py")) as f:
        asrc = f.read()
    m2 = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", asrc)
    tax_pin = int(m2.group(1)) if m2 else -1
    ok = ok and (tax_pin == 2143)
    notes.append("taxonomy-pin=%d" % tax_pin)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

_FILED = [
    ("f1443",
     "var C={I};var D=C.splice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1444",
     "var C={I};var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1445",
     "var C={I};var D=C.slice();for(var i=0;i<D.length;i++){D.fill(C[i],i,i+1);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1446",
     "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1447",
     "var C={I};var D=Array.of.apply(null,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1448",
     "var C={I};var D=[];C.findIndex(function(c){D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1449",
     "var C={I};var D=C.flatMap(function(c,i,a){return [c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1450",
     "var C={I};var D=C.map(function(c,i,a){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1451",
     "var C={I};var D=[];C.forEach(function(c){D.push(c);},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1452",
     "var C={I};var D=C.reduceRight(function(a,c){a.unshift(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1453a",
     "var C={I};var D=C.filter(function(c){return C.indexOf(c)!==-1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1453b",
     "var C={I};var D=C.filter(function(c){return C.includes(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1454",
     "var C={I};var O=Object(C);var S=String.fromCharCode.apply(null,O);var RESULT=S;"),
    ("f1455",
     "var C={I};var B=Buffer.from(C);var D=Array.from(B);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


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
    """let/const, renamed idents, renamed params still HIT."""
    tmpls = [
        # F1443 let + renamed
        "let C={I};let D=C.splice(-C.length);let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1444 const + renamed
        "const CC={I};const DD=CC.slice();DD.copyWithin(0,0);const SS=String.fromCharCode.apply(null,DD);const RESULT=SS;",
        # F1445 renamed loop var + arr
        "var C={I};var D=C.slice();for(let k=0;k<D.length;k++){D.fill(C[k],k,k+1);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1446 renamed
        "var C={I};var M2=new Map(C.map(function(x,y){return [y,x];}));var D=[];for(var w of M2.values()){D.push(w);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1447 renamed
        "var C={I};var E=Array.of.apply(null,C);var S=String.fromCharCode.apply(null,E);var RESULT=S;",
        # F1448 renamed params
        "var C={I};var D=[];C.findIndex(function(e){D.push(e);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1449 renamed params
        "const C={I};const D=C.flatMap(function(x,y,z){return [x];});const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1450 renamed params
        "let C={I};let D=C.map(function(x,y,z){return x;});let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1451 renamed
        "var C={I};var D=[];C.forEach(function(e){D.push(e);},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1452 renamed
        "var C={I};var D=C.reduceRight(function(x,y){x.unshift(y);return x;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1453 indexOf renamed
        "var C={I};var D=C.filter(function(e){return C.indexOf(e)!==-1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1453 includes renamed
        "const C={I};const D=C.filter(function(e){return C.includes(e);});const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1454 renamed
        "var C={I};var W=Object(C);var S=String.fromCharCode.apply(null,W);var RESULT=S;",
        # F1455 renamed
        "var C={I};var BB=Buffer.from(C);var DD=Array.from(BB);var S=String.fromCharCode.apply(null,DD);var RESULT=S;",
    ]
    # F1455 with a code >255: ToUint8 truncation is node-exact
    # (376 -> 120). First code bumped by 256; byte-masked decode
    # still yields the secret.
    cs_big = "[" + ",".join(
        str(ord(c) + (256 if i == 0 else 0))
        for i, c in enumerate(SECRET_S)) + "]"
    tmpls.append(
        "var C=%s;var B=Buffer.from(C);var D=Array.from(B);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
        % cs_big)
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
    """Wrong forms are NOT claimed by the new hooks (miss at hook level)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1443-splice0",
         "var C=%s;var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1443_stmt_decode),
        ("f1443-splice-neg1",
         "var C=%s;var D=C.splice(-1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1443_stmt_decode),
        ("f1443-splice-len2",
         "var C=%s;var D=C.splice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1443_stmt_decode),
        ("f1444-3arg",
         "var C=%s;var D=C.slice();D.copyWithin(0,0,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1444_stmt_decode),
        ("f1444-target1",
         "var C=%s;var D=C.slice();D.copyWithin(1,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1444_stmt_decode),
        ("f1445-fill-wrong",
         "var C=%s;var D=C.slice();for(var i=0;i<D.length;i++){D.fill(0,i,i+1);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1445_stmt_decode),
        ("f1445-fill-range2",
         "var C=%s;var D=C.slice();for(var i=0;i<D.length;i++){D.fill(C[i],i,i+2);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1445_stmt_decode),
        ("f1446-pair-swapped",
         "var C=%s;var M=new Map(C.map(function(c,i){return [c,i];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1446_stmt_decode),
        ("f1446-no-new",
         "var C=%s;var M=Map(C.map(function(c,i){return [i,c];}));var D=[];for(var v of M.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1446_stmt_decode),
        ("f1447-thisarg-undef",
         "var C=%s;var D=Array.of.apply(undefined,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1447_stmt_decode),
        ("f1447-spread-call",
         "var C=%s;var D=Array.of(...C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1447_stmt_decode),
        ("f1448-findindex-true",
         "var C=%s;var D=[];C.findIndex(function(c){D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1448_stmt_decode),
        ("f1448-find-true",
         "var C=%s;var D=[];C.find(function(c){D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1448_stmt_decode),
        ("f1449-2param",
         "var C=%s;var D=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1449_stmt_decode),
        ("f1449-ret-c",
         "var C=%s;var D=C.flatMap(function(c,i,a){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1449_stmt_decode),
        ("f1450-2param",
         "var C=%s;var D=C.map(function(c,i){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1450_stmt_decode),
        ("f1450-arrow",
         "var C=%s;var D=C.map((c,i,a)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1450_stmt_decode),
        ("f1451-no-thisarg",
         "var C=%s;var D=[];C.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1451_stmt_decode),
        ("f1451-thisarg-undef",
         "var C=%s;var D=[];C.forEach(function(c){D.push(c);},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1451_stmt_decode),
        ("f1452-push",
         "var C=%s;var D=C.reduceRight(function(a,c){a.push(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1452_stmt_decode),
        ("f1452-reduce",
         "var C=%s;var D=C.reduce(function(a,c){a.unshift(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1452_stmt_decode),
        ("f1453-eq",
         "var C=%s;var D=C.filter(function(c){return C.indexOf(c)==0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1453_stmt_decode),
        ("f1453-wrong-arr",
         "var C=%s;var E=[1];var D=C.filter(function(c){return E.includes(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1453_stmt_decode),
        ("f1454-new-object",
         "var C=%s;var O=new Object(C);var S=String.fromCharCode.apply(null,O);var RESULT=S;"
         % cs, _dlp._js_f1454_stmt_decode),
        ("f1454-object-2arg",
         "var C=%s;var O=Object(C,{});var S=String.fromCharCode.apply(null,O);var RESULT=S;"
         % cs, _dlp._js_f1454_stmt_decode),
        ("f1455-from-wrong",
         "var C=%s;var B=Buffer.from([1,2]);var D=Array.from(B);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1455_stmt_decode),
        ("f1455-no-arrayfrom",
         "var C=%s;var B=Buffer.from(C);var S=String.fromCharCode.apply(null,B);var RESULT=S;"
         % cs, _dlp._js_f1455_stmt_decode),
    ]
    bad = [n for n, p, hook in cases if hook(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1365/F1390/F1400/F1350/F1377/F1361/F1418/F1386/F1358/F1385/F1270/
    F1394/F1112 still HIT (disjoint by grammar)."""
    cs = _codes(SECRET_S)
    cases = [
        ("f1365-splice",
         "var C=%s;var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1390-copywithin3",
         "var C=%s;var D=C.slice();D.copyWithin(0,0,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1400-fill-map",
         "var C=%s;var D=new Array(C.length).fill(0).map(function(_,i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1350-flatmap1",
         "var C=%s;var D=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1377-flatmap2",
         "var C=%s;var D=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1361-map2fn",
         "var C=%s;var D=C.map(function(c,i){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1418-map3arrow",
         "var C=%s;var D=C.map((c,i,a)=>a[i]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1386-reduce-push",
         "var C=%s;var D=C.reduce(function(a,c){a.push(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1358-reduceRight-str",
         "var C=%s;var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;" % cs),
        ("f1385-filter-truthy",
         "var C=%s;var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1270-findindex-sacc",
         "var C=%s;var S='';C.findIndex(function(c){S+=String.fromCharCode(c);return false;});var RESULT=S;" % cs),
        ("f1394-find-acc",
         "var C=%s;var D=[];C.find(function(c){D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        "var arr=[1,2,3];var f=arr.filter(function(x){return x>1;});console.log(f);",
        "var m=[1,2,3].map(function(x){return x*2;});",
        "var d=[3,1,2].slice();d.reverse();console.log(d);",
        "var b=Buffer.from([1,2,3]);console.log(b);",
        "var o=Object({a:1});console.log(o);",
    ]
    bad = [p for p in quiet if not _misses(p)]
    return (not bad, "%d/%d honest quiet%s"
            % (len(quiet) - len(bad), len(quiet),
               "" if not bad else ": %d loud" % len(bad)))


# ---------------- p6: perf ----------------

@_t
def test_p6_perf():
    """200 mixed sites scan in reasonable time."""
    sites = []
    cs = _codes(SECRET_S)
    for i in range(200):
        if i % 5 == 0:
            sites.append(
                "var C=%s;var D=C.splice(-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var B=Buffer.from(C);var D=Array.from(B);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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


# ---------------- p7: other opens still miss ----------------

@_t
def test_p7_other_opens_miss():
    """F1432-F1442 + F1456-F1503 (outside this lane's closures) still
    MISS.

    Runs the w415 red-first batteries as subprocesses; each must exit
    0 (all shapes BREAK = still open). F1443-F1455 are excluded --
    they are CLOSED by this lane.

    F1469-F1475 have no w415 red-first batteries (renumbered lane-4
    residuals filed without batteries); skipped.

    F1476 is EXCLUDED: its filed shape `C.filter(c=>c)` is already
    closed on the base tree by `_js_f1360_stmt_decode` (verified via
    fresh clone at facd5867e) -- the wave-415 filing as OPEN was an
    overstatement. Reported to the merge coordinator; not stamped
    here (outside this lane's F1443-F1455 scope).

    F1486 is EXCLUDED: its filed shape is byte-identical to F1444's
    (`var D=C.slice();D.copyWithin(0,0);`) -- the wave-415 lane-2
    residual duplicates the attack's F1444 filing. It is incidentally
    CLOSED by `_js_f1444_stmt_decode`. Preserved explicitly per the
    round-68 lesson; the merge coordinator may stamp F1486 CLOSED.
    """
    bad = []
    skip = set(range(1443, 1456)) | {1476, 1486}
    # F1469-F1475: no batteries exist; skip silently.
    skip |= set(range(1469, 1476))
    for n in list(range(1432, 1443)) + list(range(1456, 1504)):
        if n in skip:
            continue
        p = os.path.join(REPO_ROOT, "evals",
                         "w415_f%d_redfirst.py" % n)
        if not os.path.exists(p):
            bad.append("f%d(missing)" % n)
            continue
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    return (not bad, "other opens miss%s"
            % ("" if not bad else ": " + ",".join(bad[:8])))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w415_attack_probes: F1456-F1462 still open.

    F1443-F1455 are now closed by this lane; the green check verifies
    F1456-F1462 remain open (their pins HELD) and the taxonomy/footer
    pins hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w415_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g416l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w415_attack_probes.py")],
            capture_output=True, text=True, timeout=900, env=env,
            cwd=os.path.join(REPO_ROOT, "evals"))
        out = (r.stdout or "") + (r.stderr or "")
        decoder_break_line = ""
        prov_held = False
        tax_held = False
        footer_held = False
        for line in out.split("\n"):
            if "test_new_decoder_pins" in line:
                decoder_break_line = line
            elif "test_new_prov_pins" in line:
                prov_held = line.startswith("HELD")
            elif "test_taxonomy_pin" in line:
                tax_held = line.startswith("HELD")
            elif "test_footer" in line:
                footer_held = line.startswith("HELD")
        # F1443-F1455 closed -> their pins break; F1456-F1462 open -> hold.
        no_open_broken = not any("f%d" % n in decoder_break_line
                                 for n in range(1456, 1463))
        closed_broken = all("f%d" % n in decoder_break_line
                            for n in (1443, 1444, 1445))
        ok = (decoder_break_line.startswith("BREAK") and no_open_broken
              and closed_broken and prov_held and tax_held
              and footer_held)
        return (ok, "green(w415_attack): no-open-broken=%s closed-broken=%s prov=%s tax=%s footer=%s"
                % (no_open_broken, closed_broken, prov_held, tax_held,
                   footer_held))
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
