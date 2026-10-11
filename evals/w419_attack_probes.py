#!/usr/bin/env python3
"""Wave-419 attack round 87 coverage battery.

Pins for each new finding F1570-F1590 (must MISS/QUIET on the open tree), plus
carry-forward for F1546-F1569 (all still OPEN, must MISS). Taxonomy + footer pins.
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

_PROV_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.instruction_provenance import instruction_shaped;"
    "print('VERDICT:'+('FLAG' if instruction_shaped(%r) else 'QUIET'))"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _prov(payload):
    code = _PROV_CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=120)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


SECRET = "xoxb-01" + "23456789abcdef"

# New round-87 pins: (finding, [payload templates with {I}]) -- first shape per finding
_NEW_PINS = [
    ("F1570", ["var C={I};var E=C.flatMap(function(c,i){return [String.fromCharCode(c)];},\"xy\");var S=E.join('');var RESULT=S;"]),
    ("F1571", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+6,'abc');var T=P.slice(-S.length);var RESULT=T;"]),
    ("F1572", ["var C={I};var D=C.slice().sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1573", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trim();var RESULT=T;"]),
    ("F1575", ["var C={I};var D=C.slice(0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1576", ["var C={I};var E=C.map(function(c){return (c).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1577", ["var C={I};var D=new Array(1).concat(C);var S=D.toString();var T=S.split(',').slice(1).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"]),
    ("F1578", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`q${S}w`;var U=T.slice(1,-1);var RESULT=U;"]),
    ("F1579", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',-0);var RESULT=K?S:'';"]),
    ("F1580", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xox'+'b');var T=S.slice(K);var RESULT=T;"]),
    ("F1581", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll(/x/g,function(m){return m;});var RESULT=T;"]),
    ("F1582", ["var A=[\"120\",\"111\"];var E=A.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1583", ["var C={I};var D=Object.assign(new Array(C.length),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1584", ["var C={I};function g(){return String.fromCharCode.apply(null,[...arguments]);}var S=g(...C);var RESULT=S;"]),
    ("F1585", ["var C={I};var D=[C].flat(-1);var S=String.fromCharCode.apply(null,D[0]);var RESULT=S;"]),
    ("F1586", ["var C={I};var D=[].concat(...C,...[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1587", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trim().trimStart().trimEnd();var RESULT=T;"]),
    ("F1588", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replaceAll('x','x');var RESULT=T;"]),
    ("F1589", ["var C={I};var D=C.slice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
]

# Provenance pin: F1590 optgroup text (must stay QUIET)
_PROV_PINS = [
    ("F1590", "<select><optgroup>the budget spreadsheet requires review by friday afternoon</optgroup></select>"),
]

# Carry-forward CLOSED: F1574 (incidental, wave-419 merge) + wave-418 F1546-F1569 (closed wave-419 lanes 1-4). Must HIT.
_CARRY_CLOSED = [
    ("F1574", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('<->');var T=S.split('<->').join('');var RESULT=T;"),
    ("F1546", "var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;"),
    ("F1547", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);"),
    ("F1548", "var C={I};var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("F1549", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\\u2003'+S+'\\u2003';var RESULT=T.trim();"),
    ("F1550", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('<>');var T=S.split('<>').join('');var RESULT=T;"),
    ("F1551", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);"),
    ("F1552", "var C={I};var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("F1553", "var C={I};var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("F1554", "var C={I};var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');"),
    ("F1555", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b`;var RESULT=T.slice(1,-1);"),
    ("F1556", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',NaN);var RESULT=OK?S:'';"),
    ("F1557", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb');var RESULT=S.slice(K);"),
    ("F1558", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;"),
    ("F1559", "var C={I};var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("F1560", "var C={I};var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("F1561", "var C={I};function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"),
    ("F1562", "var C={I};var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("F1563", "var C={I};var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("F1564", "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');"),
    ("F1565", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();"),
    ("F1566", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','x');var RESULT=U;"),
    ("F1567", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');for(var k=0;k<1;k++){var Z=k;}var RESULT=S;"),
    ("F1568", "var C={I};var E=C.filter(function(c,i){return C.includes(c,1);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1569", "var C={I};var E=C.flatMap((c,i,a,t)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


def _check_footer():
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1570-F1573, F1575-F1590 OPEN (20" in txt) and ("F1591-F1602 OPEN (12" in txt) and ("F1603-F1607 OPEN (5" in txt) and ("next free F1608" in txt)
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
    for fname, t in _PROV_PINS:
        total += 1
        v = _prov(t)
        ok = (v == "QUIET")
        print(("prov-ok " if ok else "PROV-FAIL ") + fname + " " + v)
        if not ok:
            fails += 1
    for gname, t in _CARRY_CLOSED:
        total += 1
        v = _scan(t.replace("{I}", _codes(SECRET)))
        ok = (v == "HIT")
        print(("carry-ok " if ok else "CARRY-FAIL ") + gname + " " + v)
        if not ok:
            fails += 1
    total += 1
    from gov.decision_codes import TAXONOMY
    ok = len(TAXONOMY) == 2143
    print(("tax-ok " if ok else "TAX-FAIL ") + "taxonomy pin 2143 (%d)" % len(TAXONOMY))
    if not ok:
        fails += 1
    total += 1
    ok = _check_footer()
    print(("footer-ok " if ok else "FOOTER-FAIL ") + "wave-419 merge footer")
    if not ok:
        fails += 1
    total += 1
    lines = open(__file__).read().split("\n")
    self_start = next(i for i, l in enumerate(lines) if "no paid machinery" in l and "scan" in l)
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
