#!/usr/bin/env python3
"""Wave-418 attack round 86 coverage battery.

Pins for each new finding F1546-F1566 (must MISS on the open tree), plus
carry-forward for F1518-F1545 (all still OPEN, must MISS). Taxonomy + footer pins.
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

# New round-86 pins: (finding, [payload templates with {I}]) -- first shape per finding
_NEW_PINS = [
    ("F1546", ["var C={I};var E=C.flatMap(function(c){return [String.fromCharCode(c)];},[]);var S=E.join('');var RESULT=S;"]),
    ("F1547", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=S.padStart(S.length+10,'ab');var RESULT=P.slice(-S.length);"]),
    ("F1548", ["var C={I};var D=C.slice().sort(function(a,b){return b<a;});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"]),
    ("F1549", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='\u2003'+S+'\u2003';var RESULT=T.trim();"]),
    ("F1550", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('<>');var T=S.split('<>').join('');var RESULT=T;"]),
    ("F1551", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S.slice(0);"]),
    ("F1552", ["var C={I};var D=C.slice();D.splice(0,0);var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"]),
    ("F1553", ["var C={I};var D=C.map(function(c){return new Number(c).valueOf();});var S=D.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"]),
    ("F1554", ["var C={I};var A=new Array(C.length*2);for(var i=0;i<C.length;i++){A[i*2]=String.fromCharCode(C[i]);}var RESULT=A.toString().split(',').join('');"]),
    ("F1555", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String.raw`a${S}b`;var RESULT=T.slice(1,-1);"]),
    ("F1556", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var OK=S.includes('xoxb',NaN);var RESULT=OK?S:'';"]),
    ("F1557", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var K=S.search('xoxb');var RESULT=S.slice(K);"]),
    ("F1558", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.replace(/./g,function(m){return m;});var RESULT=T;"]),
    ("F1559", ["var C={I};var D=C.map(String);var T=D.join(',').split(',').map(Number);var RESULT=T.map(function(c){return String.fromCharCode(c);}).join('');"]),
    ("F1560", ["var C={I};var D=Object.assign([],C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"]),
    ("F1561", ["var C={I};function g(){var A=Array.prototype.slice.call(arguments);return A.map(function(c){return String.fromCharCode(c);}).join('');}var RESULT=g(...C);"]),
    ("F1562", ["var C={I};var D=C.flat(0);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"]),
    ("F1563", ["var C={I};var D=[].concat(...C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');"]),
    ("F1564", ["var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var V=[...M.values()];var RESULT=V.map(function(c){return String.fromCharCode(c);}).join('');"]),
    ("F1565", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=(' '+S+' ').trimStart().trimEnd();"]),
    ("F1566", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var U=S.replace('x','x');var RESULT=U;"]),
]

# Carry-forward: round-85 opens F1518-F1543 + F1544 + F1545 (all still OPEN, must MISS)
_CARRY = [
    ("F1518", 'var C={I};var E=C.flatMap((c,i,a,t,u)=>[c]);var S=String.fromCharCode.apply(null,E);'),
    ("F1519", "var C={I};var E=C.map(function(c){return String.fromCharCode(c).padStart(10,'0').slice(-1);});"),
    ("F1520", 'var C={I};var D=C.slice().sort((a,b)=>a>b);var S=String.fromCharCode.apply(null,D);'),
    ("F1521", "var C={I};var J=C.map(function(c){return String.fromCharCode(c);}).join(' ');var E=J.split(' ').map(function(s){return s.trim();});"),
    ("F1522", 'var C={I};var D=C.slice(-(C.length-0));var S=String.fromCharCode.apply(null,D);'),
    ("F1523", 'var C={I};var E=C.map(function(c){return (new String(String.fromCharCode(c))).valueOf();});'),
    ("F1524", 'var C={I};var E=C.filter(function(c,i){return C.includes(c,0);});var S=String.fromCharCode.apply(null,E);'),
    ("F1525", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.match(/./g);var RESULT=E.join('');"),
    ("F1526", 'var C={I};var E=[];for(var _p of C.entries()){var _i=_p[0],_v=_p[1];E.push(_v);}var S=String.fromCharCode.apply(null,E);'),
    ("F1527", 'var C={I};var J=JSON.stringify(C,function(k,v){return v;});var E=JSON.parse(J);var S=String.fromCharCode.apply(null,E);'),
    ("F1528", 'var C={I};var E=Array.from(C,function(c){return c;},{});var S=String.fromCharCode.apply(null,E);'),
    ("F1529", 'var C={I};function g(){var a=[];for(var k=0;k<arguments.length;k++){a.push(arguments[k]);}return a;}var E=g.apply(null,C);var S=String.fromCharCode.apply(null,E);'),
    ("F1530", 'var C={I};function* g(){yield* C;}var E=[...g()];var S=String.fromCharCode.apply(null,E);'),
    ("F1531", 'var C={I};var E=[];var k=0;do{E.push(C[k]);k++;}while(k<C.length);var S=String.fromCharCode.apply(null,E);'),
    ("F1532", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var B=new TextEncoder().encode(S);var T=new TextDecoder().decode(B);"),
    ("F1533", 'var C={I};var E=C.map(function(c){return Number(BigInt.asUintN(16,BigInt(c)));});var S=String.fromCharCode.apply(null,E);'),
    ("F1534", 'var C={I};var N=C.map(function(c){return [c];});var E=N.flat(1+1);var S=String.fromCharCode.apply(null,E);'),
    ("F1535", 'var C={I};var E=Array.of(...C);var S=String.fromCharCode.apply(null,E);'),
    ("F1536", 'var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var E=[...M.values()];var S=String.fromCharCode.apply(null,E);'),
    ("F1537", "var C={I};var K=Reflect.ownKeys(C);var E=[];for(var k=0;k<K.length;k++){if(K[k]!=='length'){E.push(C[K[k]]);}}var S=String.fromCharCode.apply(null,E);"),
    ("F1538", 'var C={I};var E=[].concat(...[C]);var S=String.fromCharCode.apply(null,E);'),
    ("F1539", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=[];for(var k=0;k<S.length;k++){E.push(S.charAt(k*1+0));}var RESULT=E.join('');"),
    ("F1540", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var E=S.search(/x/);var RESULT=S;"),
    ("F1541", 'var C={I};var E=C.values().take(C.length).toArray();var S=String.fromCharCode.apply(null,E);'),
    ("F1542", 'var C={I};var D=C.toReversed().toReversed().toReversed().toReversed();'),
    ("F1543", 'var C={I};var E=C.map(function(c){return String.fromCharCode(c).repeat(1);});'),
    ("F1544", 'var C={I};var D=C.splice(-1);var E=C.concat(D);var S=String.fromCharCode.apply(null,E);'),
    ("F1545", 'var C={I};var E=C.map(function(c){return [[c]];}).flat(2);var S=String.fromCharCode.apply(null,E);'),
]


def _check_footer():
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    ok = ("F1546-F1566" in txt) and ("next free F1567" in txt)
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
        ok = (v == "MISS")
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
    print(("footer-ok " if ok else "FOOTER-FAIL ") + "F1546-F1566 footer")
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
