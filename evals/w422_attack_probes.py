#!/usr/bin/env python3
"""Wave-422 attack round 90 coverage battery.

Pins for each new finding F1672-F1689 (must MISS on the open tree; F1674 is
length-dependent: short HITs, long MISSES), plus carry-forward for
F1642-F1671 open (must MISS). Taxonomy + footer pins.
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


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


# New round-90 pins: (finding, [payload templates with {I}]) -- first shape per finding
_NEW_PINS = [
    ("F1672", ["var C={I};var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1673", ["var C={I};var T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;"]),
    ("F1675", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...new Intl.Segmenter().segment(S)].map(function(s){return s.segment;}).join('');var RESULT=D;"]),
    ("F1676", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var P=new URLSearchParams([['k',S]]);var T=P.get('k');var RESULT=T;"]),
    ("F1677", ["var C={I};var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);"]),
    ("F1678", ["var C={I};var D=JSON.parse(JSON.stringify(C));var RESULT=String.fromCharCode.apply(null,D);"]),
    ("F1679", ["var C={I};var RESULT=String.fromCodePoint.apply(null,C);"]),
    ("F1680", ["var C={I};var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);"]),
    ("F1681", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;"]),
    ("F1682", ["var C={I};var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1683", ["var C={I};var D=C.map(function(c){return BigInt(c);});var E=D.map(function(b){return Number(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1684", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"]),
    ("F1685", ["var C={I};var D=C.map(function(c){return c.toString(16);});var E=D.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1686", ["var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"]),
    ("F1687", ["var C={I};var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"]),
    ("F1688", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;"]),
    ("F1689", ["var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"]),
]

# F1674 is length-dependent: short HITs, long MISSES
_LONLY_PINS = [
    ("F1674", "var C={I};var RESULT=Iterator.from(C).map(function(c){return String.fromCharCode(c);}).reduce(function(a,ch){return a+ch;},'');"),
]

_CARRY = [
    ("F1642", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;"),
    ("F1643", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleUpperCase();var U=T.toLocaleLowerCase();var RESULT=U;"),
    ("F1644", "var C={I};var D=C.filter((c)=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1645", "var C={I};var D=C.map(function(c,i){return C.at(i-C.length);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1646", "var C={I};var S=C.toLocaleString();var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("F1647", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var M=[...S.matchAll(/(?<ch>.)/g)];var T=M.map(function(m){return m[1];}).join('');var RESULT=T;"),
    ("F1648", "var C={I};var f=String.fromCharCode.bind(null);var S=f.apply(null,C);var RESULT=S;"),  # f1648-1 surviving shape; f1648-0 incidentally closed by F1633
    ("F1649", "var C={I};var D=Array.from(C,(c)=>c);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1650", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.codePointAt(0);});var T=String.fromCharCode.apply(null,D);var RESULT=T;"),
    ("F1651", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toWellFormed().toWellFormed();var RESULT=T;"),
    ("F1652", "var C={I};var T='';var D=C.slice();var x;while((x=D.pop())!==undefined){T=String.fromCharCode(x)+T;}var RESULT=T;"),
    ("F1653", "var C={I};var G=Object.groupBy(C,function(c){return 'k';});var D=G.k;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1654", "var C={I};var D=[...C.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1655", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=Array.from(S,undefined);var T=D.join('');var RESULT=T;"),
    ("F1656", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S,];var T=D.join('');var RESULT=T;"),
    ("F1657", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=String.fromCharCode(S.charCodeAt(i));}var RESULT=T;"),
    ("F1658", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T='';for(var i=0;i<S.length;i++){T+=S[i];}var RESULT=T;"),
    ("F1659", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=String(S).toWellFormed();var RESULT=T;"),
    ("F1660", "var C={I};var D=C.flat(0.000);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1661", "var C={I};var D=C.flat(000);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1662", "var C={I};var D=C.flat(0e0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1663", "var C={I};var D=C.flat(-0e0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1664", "var C={I};var D=Object.assign(new Array(00),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1665", "var C={I};var D=Object.assign(new Array(0.0),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1666", "var C={I};var D=Object.assign(new Array(-0),C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1667", "var C={I};var D=C.slice();D.fill(1,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1668", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.toLocaleString('de-DE');var RESULT=T;"),
    ("F1669", "var C={I};var S=Array.prototype.join.call(C);var T=S.split(',').map(Number);var U=String.fromCharCode.apply(null,T);var RESULT=U;"),
    ("F1670", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFD');var RESULT=T;"),
    ("F1671", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.normalize('NFKC');var RESULT=T;"),
]


def main():
    fails = 0
    total = 0
    for fname, tmpls in _NEW_PINS:
        for tmpl in tmpls:
            for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
                total += 1
                payload = tmpl.replace("{I}", _codes(secret))
                v = _scan(payload)
                ok = (v == "MISS")
                print(("HELD " if ok else "FAIL ") + "%s %s -> %s" % (fname, label, v))
                if not ok:
                    fails += 1
    for fname, tmpl in _LONLY_PINS:
        total += 1
        v_s = _scan(tmpl.replace("{I}", _codes(SECRET_S)))
        ok_s = (v_s == "HIT")
        print(("HELD " if ok_s else "FAIL ") + "%s short -> %s (expect HIT)" % (fname, v_s))
        if not ok_s:
            fails += 1
        total += 1
        v_l = _scan(tmpl.replace("{I}", _codes(SECRET_L)))
        ok_l = (v_l == "MISS")
        print(("HELD " if ok_l else "FAIL ") + "%s long -> %s (expect MISS)" % (fname, v_l))
        if not ok_l:
            fails += 1
    for fname, tmpl in _CARRY:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = (v == "MISS")
            print(("HELD " if ok else "FAIL ") + "%s %s -> %s" % (fname, label, v))
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
    ok = ("# Wave-422 attack round 90:" in txt) and ("F1672-F1689" in txt)
    print(("HELD " if ok else "FAIL ") + "footer pin")
    if not ok:
        fails += 1
    # no paid machinery (scan own source above the self-check, skip comments)
    total += 1
    src_lines = open(os.path.abspath(__file__)).read().split("\n")
    self_start = next(i for i, l in enumerate(src_lines) if "no paid machinery" in l and "scan" in l)
    scan_lines = src_lines[:self_start]
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
