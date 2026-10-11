#!/usr/bin/env python3
"""Wave-415 lane 2 close battery: F1385-F1396 CLOSED.

F1385: Array.prototype.filter callback twins (F1360/F1248 residual) --
  `C.filter(function(c){return c;})` and
  `C.filter(function(c,i){return i<C.length;})` + fromCharCode.apply
  assemble node-exactly (v24.20.0) while find_credential MISSED. Closed
  by `_js_f1385_stmt_decode` (fail-closed when any code is 0 on the
  truthy form). Disjoint from F1360 (Boolean callback) and F1248 by
  grammar.

F1386: Array.prototype.reduce push-accumulator staging (F1358/F906/
  F907 residual) -- `C.reduce(function(a,c){a.push(c);return a;},[])`.
  Closed by `_js_f1386_stmt_decode`. Disjoint by grammar.

F1387: Array.prototype.concat staging (F1113 residual) --
  `[].concat(C)` / `C.concat([])`. Closed by `_js_f1387_stmt_decode`.
  Disjoint from F1113 (String.prototype.concat) by grammar.

F1388: Array.prototype.every/some array-accumulation (F1270 residual)
  -- `C.every(function(c){D.push(c);return true;})` /
  `C.some(function(c){D.push(c);return false;})`. Closed by
  `_js_f1388_stmt_decode` (callback must return the total constant).
  Disjoint from F1270 (S+= forms) by grammar.

F1389: Number.prototype.toPrecision map codec (F1356/F1366 residual)
  -- `Number(c.toPrecision(3))` via map. Closed by
  `_js_f1389_stmt_decode` (fail-closed on codes >= 1000, precision
  must be exactly 3). Disjoint from F1356/F1366 by grammar.

F1390: Array.prototype.copyWithin no-op staging (F1365 residual) --
  `D=C.slice();D.copyWithin(0,0,D.length);`. Closed by
  `_js_f1390_stmt_decode`. Disjoint from F1365 (splice) by grammar.

F1391: Array.prototype.at index staging loop (round-66-80 triage
  residual) -- `for(var i=0;i<C.length;i++){D.push(C.at(i));}`.
  Closed by `_js_f1391_stmt_decode`. Disjoint from triaged single
  `.at(i)` reads by grammar (full-array staging loop).

F1392: JSON number-array roundtrip staging (F571 residual) --
  `JSON.parse(JSON.stringify(C))`. Closed by
  `_js_f1392_stmt_decode`. Disjoint from F571 (string literals) by
  grammar.

F1393: Array.from staging (F1112 residual) -- `Array.from(C)` /
  `Array.from(C,function(c){return c;})`. Closed by
  `_js_f1393_stmt_decode`. Disjoint from F1112 (TypedArray) by
  grammar.

F1394: Array.prototype.find array-accumulation (F1270 residual) --
  `C.find(function(c){D.push(c);return false;})`. Closed by
  `_js_f1394_stmt_decode`. Disjoint from F1270 by grammar.

F1395: Array.prototype.reverse double-reverse staging (novel builtin
  class) -- `D=C.slice();D.reverse();D.reverse();`. Closed by
  `_js_f1395_stmt_decode`.

F1396: Array keys-iterator staging (F1364 residual) --
  `for(var k of C.keys()){D.push(C[k]);}`. Closed by
  `_js_f1396_stmt_decode`. Disjoint from F1364 (Object.entries) by
  grammar.

New _decode_layer dispatch loop (F1385-F1396); N_STMTDEC_LOOPS 74->75
(real code-count change). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1376-F1384 + F1397-F1431 (outside this lane) still MISS.

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
    """Pin 2143 holds; footer has wave-414 lineage; N_STMTDEC_LOOPS=75."""
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
    ok = (pin == 75 and len(loops) == 75)
    notes.append("loops=%d pin=%d" % (len(loops), pin))
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        ftxt = f.read()
    has_w414 = "# Wave-414:" in ftxt
    ok = ok and has_w414
    notes.append("w414-footer=%s" % has_w414)
    # taxonomy pin 2143
    with open(os.path.join(REPO_ROOT, "evals",
                           "w414_attack_probes.py")) as f:
        asrc = f.read()
    m2 = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", asrc)
    tax_pin = int(m2.group(1)) if m2 else -1
    ok = ok and (tax_pin == 2143)
    notes.append("taxonomy-pin=%d" % tax_pin)
    return (ok, "; ".join(notes))


# ---------------- p1: filed shapes ----------------

_FILED = [
    ("f1385a",
     "var C={I};var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1385b",
     "var C={I};var D=C.filter(function(c,i){return i<C.length;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1386",
     "var C={I};var D=C.reduce(function(a,c){a.push(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1387a",
     "var C={I};var D=[].concat(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1387b",
     "var C={I};var D=C.concat([]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1388a",
     "var C={I};var D=[];C.every(function(c){D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1388b",
     "var C={I};var D=[];C.some(function(c){D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1389",
     "var C={I};var D=C.map(function(c){return Number(c.toPrecision(3));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1390",
     "var C={I};var D=C.slice();D.copyWithin(0,0,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1391",
     "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1392",
     "var C={I};var D=JSON.parse(JSON.stringify(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1393a",
     "var C={I};var D=Array.from(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1393b",
     "var C={I};var D=Array.from(C,function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1394",
     "var C={I};var D=[];C.find(function(c){D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1395",
     "var C={I};var D=C.slice();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1396",
     "var C={I};var D=[];for(var k of C.keys()){D.push(C[k]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
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
        # F1385 let + renamed
        "let C={I};let D=C.filter(function(x){return x;});let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1385 2-param renamed
        "var CC={I};var DD=CC.filter(function(a,b){return b<CC.length;});var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
        # F1386 renamed
        "const C={I};const D=C.reduce(function(x,y){x.push(y);return x;},[]);const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1387 const
        "const C={I};const D=[].concat(C);const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1388 let
        "let C={I};let D=[];C.every(function(e){D.push(e);return true;});let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1389 renamed param
        "var C={I};var D=C.map(function(v){return Number(v.toPrecision(3));});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1390 copyWithin(0) short form
        "var C={I};var D=C.slice();D.copyWithin(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1391 let loop var
        "var C={I};var D=[];for(let i=0;i<C.length;i++){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
        # F1392 const
        "const C={I};const D=JSON.parse(JSON.stringify(C));const S=String.fromCharCode.apply(null,D);const RESULT=S;",
        # F1393 renamed
        "var CC={I};var DD=Array.from(CC);var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
        # F1394 let
        "let C={I};let D=[];C.find(function(e){D.push(e);return false;});let S=String.fromCharCode.apply(null,D);let RESULT=S;",
        # F1395 renamed
        "var CC={I};var DD=CC.slice();DD.reverse();DD.reverse();var SS=String.fromCharCode.apply(null,DD);var RESULT=SS;",
        # F1396 const loop var
        "var C={I};var D=[];for(const k of C.keys()){D.push(C[k]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;",
    ]
    bad = [t for t in tmpls
           if not _hits(t.replace("{I}", _codes(SECRET_S)))]
    return (not bad, "%d/%d general hit%s"
            % (len(tmpls) - len(bad), len(tmpls),
               "" if not bad else ": %d miss" % len(bad)))


# ---------------- p3: fail-closed bounds ----------------

@_t
def test_p3_fail_closed():
    """Wrong forms are NOT claimed by the new hooks (miss at hook level)."""
    cs = _codes(SECRET_S)
    cs0 = _codes("xoxb-01" + "23456789abcde" + chr(0) + "f")
    cases = [
        ("f1385-zero",
         "var C=%s;var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs0, _dlp._js_f1385_stmt_decode),
        ("f1385-bool-cb",
         "var C=%s;var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1385_stmt_decode),
        ("f1385-idx-wrong-arr",
         "var C=%s;var E=[1];var D=C.filter(function(c,i){return i<E.length;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1385_stmt_decode),
        ("f1386-no-init",
         "var C=%s;var D=C.reduce(function(a,c){a.push(c);return a;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1386_stmt_decode),
        ("f1386-ret-c",
         "var C=%s;var D=C.reduce(function(a,c){a.push(c);return c;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1386_stmt_decode),
        ("f1387-arg2",
         "var C=%s;var D=C.concat([1,2]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1387_stmt_decode),
        ("f1388-every-false",
         "var C=%s;var D=[];C.every(function(c){D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1388_stmt_decode),
        ("f1388-some-true",
         "var C=%s;var D=[];C.some(function(c){D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1388_stmt_decode),
        ("f1389-bigcode",
         "var C=[1001,1002];var D=C.map(function(c){return Number(c.toPrecision(3));});var S=String.fromCharCode.apply(null,D);var RESULT=S;",
         _dlp._js_f1389_stmt_decode),
        ("f1389-prec2",
         "var C=%s;var D=C.map(function(c){return Number(c.toPrecision(2));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1389_stmt_decode),
        ("f1390-target1",
         "var C=%s;var D=C.slice();D.copyWithin(1,0,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1390_stmt_decode),
        ("f1391-neg-at",
         "var C=%s;var D=[];for(var i=0;i<C.length;i++){D.push(C.at(-1));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1391_stmt_decode),
        ("f1391-bare-i",
         "var C=%s;var D=[];for(i=0;i<C.length;i++){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1391_stmt_decode),
        ("f1392-stringify-wrong",
         "var C=%s;var D=JSON.parse(JSON.stringify([1]));var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1392_stmt_decode),
        ("f1393-map-nonident",
         "var C=%s;var D=Array.from(C,function(c){return c+1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1393_stmt_decode),
        ("f1394-find-true",
         "var C=%s;var D=[];C.find(function(c){D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1394_stmt_decode),
        ("f1395-single-rev",
         "var C=%s;var D=C.slice();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1395_stmt_decode),
        ("f1395-triple-rev",
         "var C=%s;var D=C.slice();D.reverse();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1395_stmt_decode),
        ("f1396-wrong-idx",
         "var C=%s;var D=[];for(var k of C.keys()){D.push(C[0]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1396_stmt_decode),
        ("f1396-values",
         "var C=%s;var D=[];for(var v of C.values()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"
         % cs, _dlp._js_f1396_stmt_decode),
    ]
    bad = [n for n, p, hook in cases if hook(p) is not None]
    return (not bad, "%d/%d fail-closed%s"
            % (len(cases) - len(bad), len(cases),
               "" if not bad else ": " + ",".join(bad)))


# ---------------- p4: sibling pins ----------------

@_t
def test_p4_sibling_pins():
    """F1360-F1375 (wave-414 closed) still HIT.

    Note: F1424 (wave-414 lane-1 residual, `filter(function(c){return
    c;})`) is incidentally CLOSED by the new `_js_f1385_stmt_decode`
    hook -- the filed shape is byte-identical to F1385's f1385-0
    production. Preserved explicitly per the round-68 lesson; the
    merge coordinator may stamp F1424 CLOSED.
    """
    cs = _codes(SECRET_S)
    cases = [
        ("f1360-filter-bool",
         "var C=%s;var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1365-splice",
         "var C=%s;var D=C.splice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1366-toexp",
         "var C=%s;var D=C.map(function(c){return Number(c.toExponential(2));});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1367-abs",
         "var C=%s;var D=C.map(function(c){return Math.abs(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1370-join-sep",
         "var C=%s;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('ab').split('ab').join('');var RESULT=S;" % cs),
        ("f1424-truthy-filter",
         "var C=%s;var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
        ("f1375-parseint",
         "var C=%s;var D=C.map(function(c){return parseInt(c.toFixed(0),10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs),
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
        "var o={};var s=JSON.stringify(o);console.log(s);",
        "var m=[1,2,3].map(function(x){return x*2;});",
        "var d=[3,1,2].slice();d.reverse();console.log(d);",
        "var e=[1,2,3].concat([4]);console.log(e);",
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
                "var C=%s;var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
        elif i % 5 == 1:
            sites.append(
                "var C=%s;var D=JSON.parse(JSON.stringify(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;" % cs)
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
    """F1376-F1384 + F1397-F1431 + F1432-F1453 (outside this lane's
    closures) still MISS.

    Runs the w414/w415 red-first batteries as subprocesses; each must
    exit 0 (all shapes BREAK = still open).

    F1424 is EXCLUDED: it is incidentally closed by `_js_f1385_stmt_decode`
    (its filed shape is byte-identical to F1385's f1385-0 production;
    see test_p4_sibling_pins). Preserved explicitly per round-68.
    """
    bad = []
    skip = {1424}
    for n in list(range(1376, 1385)) + list(range(1397, 1432)):
        if n in skip:
            continue
        p = os.path.join(REPO_ROOT, "evals",
                         "w414_f%d_redfirst.py" % n)
        try:
            r = subprocess.run(
                [sys.executable, p],
                capture_output=True, text=True, timeout=300,
                cwd=os.path.join(REPO_ROOT, "evals"))
            if r.returncode != 0:
                bad.append("f%d(rc=%d)" % (n, r.returncode))
        except Exception:  # noqa: BLE001
            bad.append("f%d(exc)" % n)
    for n in range(1432, 1454):
        p = os.path.join(REPO_ROOT, "evals",
                         "w415_f%d_redfirst.py" % n)
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
            % ("" if not bad else ": " + ",".join(bad)))


# ---------------- g0: green check ----------------

def _green_check():
    """Depth-1 green on w414_attack_probes: F1397-F1416 still open.

    F1385-F1396 are now closed by this lane; the green check verifies
    F1397-F1416 remain open (their pins HELD) and the taxonomy/footer
    pins hold. Honors GOV_SKIP_GREEN.
    """
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return (True, "green(w414_attack): skipped via GOV_SKIP_GREEN=1")
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="g415l2-green-", dir="/var/tmp")
    env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmpd)
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(REPO_ROOT, "evals",
                                          "w414_attack_probes.py")],
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
        # F1385-F1396 closed -> their pins break; F1397-F1412 open -> hold.
        no_open_broken = not any("f%d" % n in decoder_break_line
                                 for n in range(1397, 1413))
        closed_broken = all("f%d" % n in decoder_break_line
                            for n in (1385, 1386, 1387))
        ok = (decoder_break_line.startswith("BREAK") and no_open_broken
              and closed_broken and prov_held and tax_held
              and footer_held)
        return (ok, "green(w414_attack): no-open-broken=%s closed-broken=%s prov=%s tax=%s footer=%s"
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
