#!/usr/bin/env python3
"""Wave-417 attack round 85 coverage battery.

Wave-418 merge: F1518-F1545 now CLOSED (must HIT). Carry-forward for F1504-F1516 (must HIT). Taxonomy + footer pins.
$0-spend-by-construction: local node validation only, no paid machinery.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


SECRET = "xoxb-01" + "23456789abcdef"

# New round-85 pins: (finding, [payload templates with {I}]) -- first shape per finding
_NEW_PINS = []

# Carry-forward: round-84 opens F1504-F1516 (now CLOSED in wave-417 merge, must HIT). F1517 CLOSED in merge.
_CARRY = [
    ("F1504", "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1505", "var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    ("F1506", "var C={I};var D=C.map(function(c){return String(c).padEnd(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    ("F1507", "var C={I};var D=C.map(function(c){return String(c).padStart(5,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"),
    ("F1508", "var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("F1509", "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"),
    ("F1510", "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimStart();});var S=D.join('');var RESULT=S;"),
    ("F1511", "var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimEnd();});var S=D.join('');var RESULT=S;"),
    ("F1512", "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;"),
    ("F1513", "var C={I};var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1514", "var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;"),
    ("F1515", "var C={I};var J=C.toString();var D=J.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1516", "var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("F1518", "var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},null);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1519", "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(10,'0').slice(-1);});var RESULT=E.join('');"),
    ("F1520", "var C={I};var D=C.slice().sort((a,b)=>a>b);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1521", "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join('|');var E=J.split('|');var RESULT=E.join('');"),
    ("F1522", "var C={I};var D=C.slice(-(C.length-0));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1523", "var C={I};var S=String(C);var E=S.split(',').map(Number);var R=String.fromCharCode.apply(null,E);var RESULT=R;"),
    ("F1524", "var C={I};var E=C.filter(function(c,i){return C.includes(c,0);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1525", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');"),
    ("F1526", "var C={I};var E=[];for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_v);}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1527", "var C={I};var J=JSON.stringify(C,function(k,v){return v;});var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1528", "var C={I};var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1530", "var C={I};function* g(){yield* C;}var E=[...g()];var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1532", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=atob(btoa(S));"),
    ("F1533", "var C={I};var E=C.map(function(c){return Number(BigInt.asUintN(16,BigInt(c)));});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1534", "var C={I};var N=C.map(function(c){return [c];});var E=N.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1535", "var C={I};var E=Array.of(...C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1536", "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var E=[...M.values()];var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1539", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*1+0));}var RESULT=E.join('');"),
    ("F1540", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=1;var RESULT=S;"),
    ("F1541", "var C={I};var E=C.values().take(C.length).toArray();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1543", "var C={I};var E=C.map(function(c){return String.fromCharCode(c).repeat(1);});var RESULT=E.join('');"),
    ("F1544", "var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("F1545", "var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("F1529", "var C={I};function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,C);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1531", "var C={I};var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1537", "var C={I};var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){if(K[k]!=='length'){E.push(C[K[k]]);}}var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1538", "var C={I};var E=[].concat(...[C]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1542", "var C={I};var D=C.with(C.length-1,C[C.length-1]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def _check_footer():
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1376-F1545 CLOSED (170)" in txt) and ("next free F1570" in txt)
    return ok


def main():
    fails = 0
    total = 0
    for fname, tmpls in _NEW_PINS:
        for t in tmpls:
            total += 1
            v = _scan(t.replace("{I}", _codes(SECRET)))
            ok = (v == "MISS")
            print(("pin-ok " if ok else "PIN-FAIL ") + fname + " " + v)
            if not ok:
                fails += 1
    for gname, t in _CARRY:
        total += 1
        v = _scan(t.replace("{I}", _codes(SECRET)))
        ok = (v == "HIT")
        print(("carry-ok " if ok else "CARRY-FAIL ") + gname + " " + v)
        if not ok:
            fails += 1
    # taxonomy pin: decision-code count must equal 2143
    total += 1
    from gov.decision_codes import TAXONOMY
    ok = len(TAXONOMY) == 2143
    print(("tax-ok " if ok else "TAX-FAIL ") + "taxonomy pin 2143 (%d)" % len(TAXONOMY))
    if not ok:
        fails += 1
    # footer pin
    total += 1
    ok = _check_footer()
    print(("footer-ok " if ok else "FOOTER-FAIL ") + "F1376-F1545/F1570 footer")
    if not ok:
        fails += 1
    # no paid machinery: scan non-check code for paid imports/usages
    total += 1
    lines = open(__file__).read().split("\n")
    # find this check's own block to exclude it
    self_start = next(i for i, l in enumerate(lines) if "no paid machinery" in l and "scan" in l)
    # the check block runs to the end of the function; exclude from self_start onward
    # (this check is the last code before the summary print)
    scan_lines = lines[:self_start]
    bad_hits = []
    for i, line in enumerate(scan_lines, 1):
        s = line.strip()
        if s.startswith("#"):
            continue
        low = s.lower()
        if ("import realmodel" in low or "from realmodel" in low
                or "modeldriver(" in low
                or ("openai" in low and "import" in low)):
            bad_hits.append((i, s[:80]))
    ok = not bad_hits
    print(("nopaid-ok " if ok else "NOPAID-FAIL ") + "no paid machinery")
    if not ok:
        fails += 1
    print("HELD:%d/%d FAILURES:%d" % (total - fails, total, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
