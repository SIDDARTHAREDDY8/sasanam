#!/usr/bin/env python3
"""Wave-416 attack round 84 coverage battery.

Pins for each new finding (must MISS on the open tree), plus carry-forward
groups for F1432-F1503 (must still MISS). Taxonomy + footer pins.
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

# New round-84 pins: (finding, [payload templates with {I}])
_NEW_PINS = [
    ("F1504", ["var C={I};var E=C.flatMap(function(c,i,a,t){return [c];},{});var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1505", ["var C={I};var D=C.map(function(c){return String(c).padStart(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"]),
    ("F1506", ["var C={I};var D=C.map(function(c){return String(c).padEnd(String(c).length,'0');});var S=String.fromCharCode.apply(null,D.map(Number));var RESULT=S;"]),
    ("F1507", ["var C={I};var D=C.map(function(c){return String(c).padStart(5,'0');});var S=String.fromCharCode.apply(null,D.map(function(x){return Number(x);}));var RESULT=S;"]),
    ("F1508", ["var C={I};C.sort(function(a,b){return a>b;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"]),
    ("F1509", ["var C={I};var D=C.map(function(c){return String.fromCharCode(c).trim();});var S=D.join('');var RESULT=S;"]),
    ("F1510", ["var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimStart();});var S=D.join('');var RESULT=S;"]),
    ("F1511", ["var C={I};var D=C.map(function(c){return String.fromCharCode(c).trimEnd();});var S=D.join('');var RESULT=S;"]),
    ("F1512", ["var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(',');var S=J.split(',').join('');var RESULT=S;"]),
    ("F1513", ["var C={I};var D=C.splice(-1,1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1514", ["var C={I};var D=C.map(function(c){return String.fromCharCode(c).valueOf();});var S=D.join('');var RESULT=S;"]),
    ("F1515", ["var C={I};var J=C.toString();var D=J.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1516", ["var C={I};var T=String.raw`x`;var S=String.fromCharCode.apply(null,C);var RESULT=S;"]),
    ("F1517", ["var C={I};var D=C.filter(function(c){return C.includes(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
]

# Carry-forward: one representative shape per open group (must still MISS)
_CARRY = [
    ("F1432-F1462", "var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1463-F1468", "var C={I};var D=C.map((c)=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1469-F1475", "var C={I};var D=C.map((c,i)=>{return c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1476-F1497", "var C={I};var D=C.filter((c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1498-F1503", "var C={I};C.sort((a,b)=>{return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]


def _check_footer():
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1376-F1516 CLOSED (141)" in txt) and ("F1518-F1543 OPEN (26" in txt) and ("F1544 OPEN (1" in txt) and ("F1545 OPEN (1" in txt) and ("next free F1546" in txt)
    return ok


def main():
    fails = 0
    total = 0
    # Wave-417: F1504-F1516 CLOSED by lanes 1-3; F1517 CLOSED (incidental wave-416).
    # All _NEW_PINS must now HIT.
    for fname, tmpls in _NEW_PINS:
        for t in tmpls:
            total += 1
            v = _scan(t.replace("{I}", _codes(SECRET)))
            ok = (v == "HIT")
            print(("pin-ok " if ok else "PIN-FAIL ") + fname + " " + v)
            if not ok:
                fails += 1
    # Wave-417: F1432-F1503 CLOSED by wave-416 lanes; carry pins must now HIT.
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
    print(("footer-ok " if ok else "FOOTER-FAIL ") + "F1376-F1516/F1518-F1543 footer")
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
