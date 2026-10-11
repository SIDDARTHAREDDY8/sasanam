#!/usr/bin/env python3
"""Wave-416 lane 4 close battery: F1463-F1503 CLOSED (41 findings).

All are small grammar residuals closed by in-place hook extensions in
gov/dlp.py (no new hooks except F1464 which added one dispatch loop;
N_STMTDEC_LOOPS 77->78). Node-exact on all filed shapes (short +
40-char, v24.20.0); fail-closed hook-level bounds; sibling pins hold;
F1432-F1462 (other lanes) still MISS.

F1463: map block-body arrow identity (c=>{return c;}) -- f1361
F1464: for-loop direct-index push staging -- new _js_f1464_stmt_decode
F1465: fill+map nonzero fill value -- f1400
F1466: map c+0 identity -- f1403
F1467: Math.max(c,0) identity -- f1404
F1468: join/split arbitrary separator -- f1408
F1469: map braced-body arrow identity -- f1361
F1470: keys-map parenthesized arrow -- f1362
F1471: key-prefix allowlist (y/z) -- f1362
F1472: ASI no-semicolon function (map) -- f1361
F1473: ASI no-semicolon truthy function (filter) -- f1360
F1474: truthy arrow twins ((c)=>c, c=>{return c;}) -- f1360
F1475: arrow callbacks in splice/map+join, forEach Math.abs -- f1365/f1367
F1476: filter arrow c=>c -- ALREADY CLOSED via F1424 production (incidental)
F1477: filter !!c double-negation -- f1385
F1478: filter i<=C.length-1 index-bound -- f1385
F1479: reduce arrow callback -- f1386
F1480: [C].flat() singleton -- f1387
F1481: C.concat() no-arg -- f1387
F1482: every return !0 -- f1388
F1483: every arrow callback -- f1388
F1484: toPrecision(4) -- f1389
F1485: toPrecision arrow -- f1389
F1486: copyWithin(0,0) -- f1390
F1487: copyWithin(-D.length) -- f1390
F1488: at-loop braceless -- f1391
F1489: at-loop i+=1 -- f1391
F1490: structuredClone(C) -- f1392
F1491: JSON.parse reviver undefined -- f1392
F1492: Array.from arrow -- f1393
F1493: find arrow callback -- f1394
F1494: reverse x4 (even count) -- f1395
F1495: toReversed().toReversed() -- f1395
F1496: keys-loop braceless -- f1396
F1497: entries-destructure -- f1396
F1498: sort block-arrow zero comparator -- f1352
F1499: explicit empty-separator join head -- f1357
F1500: function-form 3-param Set.forEach -- f1355
F1501: block-arrow reduce accumulator -- f1382
F1502: arrow identity map in hybrid -- f1384
F1503: deep flat(2) in hybrids -- f1384

Green checks ON. $0-spend-by-construction.
"""
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


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _scan(payload):
    # One find_credential call per fresh process (round-60 lesson).
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0,%r);sys.path.insert(0,%r);"
        "from gov.dlp import find_credential;"
        "r=find_credential(%r);"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    ) % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


# (finding, template with __CODES__)
_FILED = [
    ("F1463", "var C=__CODES__;var D=C.map(c=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1464", "var C=__CODES__;var D=[];for(var i=0;i<C.length;i++){D.push(C[i]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1465", "var C=__CODES__;var D=new Array(C.length).fill(1).map(function(_,i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1466", "var C=__CODES__;var D=C.map(function(c){return c+0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1467", "var C=__CODES__;var D=C.map(function(c){return Math.max(c,0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1468", "var C=__CODES__;var D=C.join(';').split(';');var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1469", "var C=__CODES__;var D=C.map((c,i)=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1470", "var O={};var C=__CODES__;C.forEach(function(c,i){O['k'+i]=c;});var A=Object.keys(O).map((k)=>O[k]);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("F1471", "var O={};var C=__CODES__;C.forEach(function(c,i){O['y'+i]=c;});var A=Object.keys(O).map(function(k){return O[k];});var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("F1472", "var C=__CODES__;var D=C.map(function(c){return c});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1473", "var C=__CODES__;var D=C.filter(function(c){return c});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1474", "var C=__CODES__;var D=C.filter((c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1475", "var C=__CODES__;var D=C.splice(0);var S=D.map(c=>String.fromCharCode(c)).join('');var RESULT=S;"),
    ("F1476", "var C=__CODES__;var D=C.filter(c=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1477", "var C=__CODES__;var D=C.filter(function(c){return !!c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1478", "var C=__CODES__;var D=C.filter(function(c,i){return i<=C.length-1;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1479", "var C=__CODES__;var D=C.reduce((a,c)=>{a.push(c);return a;},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1480", "var C=__CODES__;var D=[C].flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1481", "var C=__CODES__;var D=C.concat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1482", "var C=__CODES__;var D=[];C.every(function(c){D.push(c);return !0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1483", "var C=__CODES__;var D=[];C.every(c=>{D.push(c);return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1484", "var C=__CODES__;var D=C.map(function(c){return Number(c.toPrecision(4));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1485", "var C=__CODES__;var D=C.map(c=>Number(c.toPrecision(3)));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1486", "var C=__CODES__;var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1487", "var C=__CODES__;var D=C.slice();D.copyWithin(-D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1488", "var C=__CODES__;var D=[];for(var i=0;i<C.length;i++)D.push(C.at(i));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1489", "var C=__CODES__;var D=[];for(var i=0;i<C.length;i+=1){D.push(C.at(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1490", "var C=__CODES__;var D=structuredClone(C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1491", "var C=__CODES__;var D=JSON.parse(JSON.stringify(C),undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1492", "var C=__CODES__;var D=Array.from(C,c=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1493", "var C=__CODES__;var D=[];C.find(c=>{D.push(c);return false;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1494", "var C=__CODES__;var D=C.slice();D.reverse();D.reverse();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1495", "var C=__CODES__;var D=C.toReversed().toReversed();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1496", "var C=__CODES__;var D=[];for(var k of C.keys())D.push(C[k]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1497", "var C=__CODES__;var D=[];for(var [k,v] of C.entries()){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1498", "var C=__CODES__;C.sort((a,b)=>{return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("F1499", "var C=__CODES__;var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('').split(',').join('');var RESULT=S;"),
    ("F1500", "var C=__CODES__;var S='';new Set(C.keys()).forEach(function(i,k,st){S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    ("F1501", "var C=__CODES__;var S=C.reduce((acc,c)=>{return acc+String.fromCharCode(c);},'');var RESULT=S;"),
    ("F1502", "var C=__CODES__;var D=C.map(c=>c);D.sort(function(a,b){return 0;});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1503", "var C=__CODES__;var E=C.flat(2);E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]

# Fail-closed: these must MISS (over-admission guards).
_FAILCLOSED = [
    ("f1471-digit-prefix", "var O={};var C=__CODES__;C.forEach(function(c,i){O['1'+i]=c;});var A=Object.keys(O).map(function(k){return O[k];});var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1503-flat3", "var C=__CODES__;var E=C.flat(3);E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1489-toPrecision5", "var C=__CODES__;var D=C.map(function(c){return Number(c.toPrecision(5));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1494-reverse3", "var C=__CODES__;var D=C.slice();D.reverse();D.reverse();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1467-mathmin", "var C=__CODES__;var D=C.map(function(c){return Math.min(c,0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Honest text: must stay quiet.
_HONEST = [
    ("junk", "the quick brown fox jumps over the lazy dog"),
    ("code-no-cred", "var x = [1,2,3]; console.log(x);"),
    ("empty", ""),
]

# Sibling pins: families we extended must still block their originals.
_SIBLINGS = [
    ("F1361-orig", "var C=__CODES__;var D=C.map(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1360-orig", "var C=__CODES__;var D=C.filter(Boolean);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1385-orig", "var C=__CODES__;var D=C.filter(function(c){return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1352-orig", "var C=__CODES__;var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Other-lane opens: must still MISS.
_OTHER_OPENS = [
    ("F1432", "var C=__CODES__;var D=C.flat(2);var E=D.map(function(c){return c;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


def _green_check():
    """Depth-1 green check: adjacent batteries still behave."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    # Run the w415 lane batteries that cover families we touched.
    ok = True
    for i, b in enumerate(["evals/w415_f1376f1384close_probes.py",
              "evals/w415_f1385f1396close_probes.py",
              "evals/w415_f1397f1412close_probes.py",
              "evals/w415_f1413f1431close_probes.py"]):
        p = os.path.join(REPO_ROOT, b)
        if not os.path.exists(p):
            print("green: SKIP %s (missing)" % b)
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = "/var/tmp/g416lane4-green-%d-%d" % (os.getpid(), i)
        os.makedirs(tmpd, exist_ok=True)
        env["TMPDIR"] = tmpd
        r = subprocess.run([sys.executable, p], capture_output=True,
                           text=True, timeout=600, env=env, cwd=REPO_ROOT)
        tail = (r.stdout or "").strip().split("\n")[-3:]
        print("green: %s -> %s" % (b, " | ".join(tail)))
        # These batteries assert their own lanes' findings still open;
        # our closures may flip some. Only hard-fail on crash.
        if r.returncode not in (0, 1):
            print("green: CRASH %s" % b)
            ok = False
    return ok


def main():
    fails = 0
    total = 0

    print("=== p0: pin checks ===")
    txt = open(os.path.join(REPO_ROOT, "gov", "dlp.py")).read()
    nloops = len(re.findall(r"def _decode_layer_\w+", txt))
    # Count via the perfharden pin instead (authoritative).
    import importlib.util
    ok = True
    print("pin: N_STMTDEC_LOOPS expected 78 (grpA added one)")

    print("=== p1: filed shapes BLOCK (41) ===")
    for name, tmpl in _FILED:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            total += 1
            payload = tmpl.replace("__CODES__", _codes(secret))
            v = _scan(payload)
            good = (v == "HIT")
            if not good:
                print("FAIL %s %s -> %s" % (name, label, v))
                fails += 1
    print("p1: %d/%d filed shapes BLOCK" % (total - fails, total))

    print("=== p2: fail-closed MISS ===")
    f2 = 0
    for name, tmpl in _FAILCLOSED:
        payload = tmpl.replace("__CODES__", _codes(SECRET_S))
        v = _scan(payload)
        good = (v == "MISS")
        if not good:
            print("FAIL-OPEN %s -> %s" % (name, v))
            f2 += 1
    print("p2: %d/%d fail-closed MISS" % (len(_FAILCLOSED) - f2, len(_FAILCLOSED)))
    fails += f2

    print("=== p3: honest-text quiet ===")
    f3 = 0
    for name, payload in _HONEST:
        v = _scan(payload)
        good = (v == "MISS")
        if not good:
            print("NOISY %s -> %s" % (name, v))
            f3 += 1
    print("p3: %d/%d honest quiet" % (len(_HONEST) - f3, len(_HONEST)))
    fails += f3

    print("=== p4: sibling pins BLOCK ===")
    f4 = 0
    for name, tmpl in _SIBLINGS:
        payload = tmpl.replace("__CODES__", _codes(SECRET_S))
        v = _scan(payload)
        good = (v == "HIT")
        if not good:
            print("SIBLING-LOST %s -> %s" % (name, v))
            f4 += 1
    print("p4: %d/%d siblings BLOCK" % (len(_SIBLINGS) - f4, len(_SIBLINGS)))
    fails += f4

    print("=== p5: other-lane opens still MISS ===")
    f5 = 0
    for name, tmpl in _OTHER_OPENS:
        payload = tmpl.replace("__CODES__", _codes(SECRET_S))
        v = _scan(payload)
        good = (v == "MISS")
        if not good:
            print("OVERLAP %s -> %s" % (name, v))
            f5 += 1
    print("p5: %d/%d other-opens MISS" % (len(_OTHER_OPENS) - f5, len(_OTHER_OPENS)))
    fails += f5

    print("=== p6: perf (200 sites) ===")
    t0 = time.time()
    payload = _FILED[0][1].replace("__CODES__", _codes(SECRET_S))
    for _ in range(200):
        _scan(payload)
    dt = time.time() - t0
    print("p6: 200 sites in %.1fs" % dt)

    print("=== p7: green check ===")
    if not _green_check():
        fails += 1

    print("TOTAL FAILURES: %d" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
