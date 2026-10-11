#!/usr/bin/env python3
"""Wave-420 attack round 88 coverage battery.

Pins for each new finding F1608-F1638 (must MISS/QUIET on the open tree), plus
carry-forward for F1570-F1607 (all still OPEN, must MISS/QUIET). Taxonomy + footer pins.
$0-spend-by-construction: local node validation only, no paid machinery.
"""
import os
import re
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


# New round-88 pins: (finding, [payload templates with {I}]) -- first shape per finding
_NEW_PINS = [
    ("F1608", ["var C={I};var E=C.flatMap(function(c,i,a){return [String.fromCharCode(c)];},\"q\");var S=E.join('');var RESULT=S;"]),
    ("F1609", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+4,`ab`);var T=P.slice(-S.length);var RESULT=T;"]),
    ("F1610", ["var C={I};var D=C.slice().sort(function(a,b){return Number(a>b);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1612", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.slice(0,undefined);var RESULT=T;"]),
    ("F1613", ["var C={I};var E=C.map(function(c){return Object(c).valueOf();});var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1614", ["var C={I};var D=new Array(2).concat(C);var S=D.toString();var T=S.split(',').slice(2).map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"]),
    ("F1615", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`${S}abc`;var U=T.slice(0,S.length);var RESULT=U;"]),
    ("F1616", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.includes('xoxb',undefined);var RESULT=K?S:'';"]),
    ("F1617", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search(`xoxb`);var T=S.slice(K);var RESULT=T;"]),
    ("F1618", ["var A={J};var E=A.map(c=>Number(c));var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1619", ["var C={I};var D=Object.assign(Array(C.length),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1620", ["var C={I};function g(){var A=Array.from(arguments);return String.fromCharCode.apply(null,A);}var S=g(...C);var RESULT=S;"]),
    ("F1621", ["var C={I};var D=[C].flat(true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1622", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=(' '+S+' ').trimEnd().trimStart();var RESULT=T;"]),
    ("F1623", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace('x','x').replace('y','y');var RESULT=T;"]),
    ("F1624", ["var C={I};var D=C.slice().reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1625", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.repeat(1);var RESULT=T;"]),
    ("F1626", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFC');var RESULT=T;"]),
    ("F1627", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toUpperCase().toLowerCase();var RESULT=T;"]),
    ("F1628", ["var C={I};var D=C.filter(function(c){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1629", ["var C={I};var D=C.slice();D.fill(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1630", ["var C={I};var D=C.map(function(c,i){return C.at(i);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1631", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString();var RESULT=T;"]),
    ("F1632", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').join('');var RESULT=T;"]),
    ("F1633", ["var C={I};var S=Array.prototype.join.call(C,',');var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"]),
    ("F1634", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S);var T=D.join('');var RESULT=T;"]),
    ("F1635", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.codePointAt(i));}var RESULT=T;"]),
    ("F1636", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed();var RESULT=T;"]),
]

# Provenance pins (must stay QUIET)
_PROV_PINS = [
    ("F1637", "<input list=\"d\"><datalist id=\"d\">the budget spreadsheet requires review by friday afternoon</datalist>"),
    ("F1638", "<select>the budget spreadsheet requires review by friday afternoon<option>x</option></select>"),
]

# Carry-forward: F1570-F1607 were OPEN on attack tree, now CLOSED on merged tree (removed). F1608-F1641 OPEN below.
_CARRY = [
]



def main():
    fails = 0
    total = 0
    for fname, tmpls in _NEW_PINS:
        for tmpl in tmpls:
            total += 1
            payload = tmpl.replace("{I}", _codes(SECRET))
            v = _scan(payload)
            ok = (v == "MISS")
            print(("HELD " if ok else "FAIL ") + "%s -> %s" % (fname, v))
            if not ok:
                fails += 1
    for fname, payload in _PROV_PINS:
        total += 1
        v = _prov(payload)
        ok = (v == "QUIET")
        print(("HELD " if ok else "FAIL ") + "%s -> %s" % (fname, v))
        if not ok:
            fails += 1
    for fname, tmpl in _CARRY:
        total += 1
        payload = tmpl.replace("{I}", _codes(SECRET))
        v = _scan(payload)
        ok = (v == "MISS")
        print(("HELD " if ok else "FAIL ") + "%s (carry) -> %s" % (fname, v))
        if not ok:
            fails += 1
    # taxonomy pin
    total += 1
    from gov.decision_codes import TAXONOMY
    ok = (len(TAXONOMY) == 2143)
    print(("HELD " if ok else "FAIL ") + "taxonomy pin 2143 (%d)" % len(TAXONOMY))
    if not ok:
        fails += 1
    # footer pin
    total += 1
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("# Wave-420 attack round 88:" in txt) and ("F1608-F1638" in txt)
    print(("HELD " if ok else "FAIL ") + "footer pin")
    if not ok:
        fails += 1
    # no paid machinery (scan own source above the self-check, skip comments)
    total += 1
    lines = open(os.path.abspath(__file__)).read().split("\n")
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
    print(("HELD " if ok else "FAIL ") + "no paid machinery")
    if not ok:
        fails += 1
    print("RESULT: %d/%d HELD" % (total - fails, total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
