#!/usr/bin/env python3
"""Wave-426 attack round 94 coverage battery: new F1735-F1748 pins (MISS) +
F1715-F1734 carry-forward pins (MISS) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
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

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

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


def _codes_bare(s):
    return ",".join(str(ord(c)) for c in s)


# New round-94 pins: (name, template) — must MISS on open tree
_NEW = [
    ("f1735", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padStart(S.length+(C.length-C.length),' ');var RESULT=T;"),
    ("f1736", "var C={I};var S=String.fromCharCode.apply(null,C);var T=S.padEnd(S.length+(C.length-C.length),' ');var RESULT=T;"),
    ("f1737", "var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var A=Array.from(V);A.reverse();A.reverse();var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1738", "var C={I};var U=new Uint8Array(C.length);U.set(C,C.length-C.length);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;"),
    ("f1739", "var C={I};var U=new Uint8Array(C);var V=U.subarray(0).subarray(0);var S=String.fromCharCode.apply(null,Array.from(V));var RESULT=S;"),
    ("f1740", "var C={I};var B=new ArrayBuffer(C.length);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint8(i,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint8(j));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1741", "var C={I};var B=new Uint8Array(C).buffer;var B2=B.slice(0);var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;"),
    ("f1742", "var C={I};var D=C.toReversed();D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1743", "var C={I};var n=C.length-C.length+1;var D=[C];var F=D.flat(n);var S=String.fromCharCode.apply(null,F);var RESULT=S;"),
    ("f1744", "var C={I};var S=String.fromCharCode.apply(null,C);var n=C.length-C.length+1;var T=S.repeat(n);var RESULT=T;"),
    ("f1745", "var C={I};var D=C.slice();for(var i=0;i<D.length;i++){D.fill(D[i],i,i+1);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1746", "var C={I};var B=new ArrayBuffer(C.length*2);var V=new DataView(B);for(var i=0;i<C.length;i++){V.setUint16(i*2,C[i]);}var D=[];for(var j=0;j<C.length;j++){D.push(V.getUint16(j*2));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1747", "var C={I};var D=C.slice();D.copyWithin(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1748", "var C={I};var D=C.slice();D.fill(0,C.length-C.length,C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward OPEN pins from wave-425 (attack 93 F1715-F1724, lane-C F1725,
# S1 residuals F1726-F1734) — must still MISS on the open tree
_CARRY_MISS = [
    ("F1715", "var C={I};var D=C.reduceRight(function(a,c){return [c].concat(a);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1716", "var C={I};var E=C.entries();var D=[];for(var [i,c] of E){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1717", "var C={I};var O=Object.assign({},C);var D=[];for(var [k,v] of Object.entries(O)){D.push(Number(v));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1718", "var C={I};var D=[];D.push.apply(D,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1719", "var C={I};var D=Array.from(C,function(c){return c;},undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1720", "var C={I};var T=C.join(undefined);var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1721", "var C={I};var D=[C];var E=D.flat(Infinity);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1722", "var C={I};var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1723", "var C={I};var T=[];C.findLast(function(c){T.unshift(c);return false;});var S=String.fromCharCode.apply(null,T);var RESULT=S;"),
    ("F1724", "var C={I};var D=C.filter(function(c,i,a){return a[i]===c;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1725", "var C={I};var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1726", "var C={I};var D=Object.assign([],C,C,C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1727", "var C={I};var D=Object.assign([],C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1728", "var C={I};var S=String.fromCharCode.apply(null,C);var T=`x${S}`;var RESULT=T;"),
    ("F1729", "var C={I};var D=C.flatMap(function(c,i){return [c];},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1730", "var C={I};var D=C.flatMap(function(c){return [c];},{});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1731", "var C={I};var D=C.map(function(c,i,a){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1732", "var C={I};var D=Array.from(C,function(c,i){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1733", "var C={I};var D=C.slice();C.splice(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1734", "var C=[{CODES},0xD800];var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
]


def main():
    held = 0
    total = 0
    # p1: new pins must MISS (both sizes)
    h1 = t1 = 0
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            t1 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "MISS":
                h1 += 1
            else:
                print("FAIL new %s: got %s" % (name, v))
    print("p1 new pins: %d/%d HELD" % (h1, t1))
    held += h1
    total += t1
    # p2: carry-forward MISS pins (both sizes)
    h2 = t2 = 0
    for name, tmpl in _CARRY_MISS:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            if "{CODES}" in tmpl:
                payload = tmpl.replace("{CODES}", _codes_bare(secret))
            else:
                payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            if v == "MISS":
                h2 += 1
            else:
                print("FAIL carry %s: got %s" % (name, v))
    print("p2 carry pins: %d/%d HELD" % (h2, t2))
    held += h2
    total += t2
    # p3: taxonomy pin 2143 in gov/guac_graph.py
    t3 = 1
    h3 = 0
    gtxt = open(os.path.join(REPO_ROOT, "gov", "guac_graph.py")).read()
    m = re.search(r"TAXONOMY_PIN\s*=\s*(\d+)", gtxt)
    if m and m.group(1) == "2143":
        h3 = 1
    else:
        print("FAIL taxonomy pin")
    print("p3 taxonomy: %d/%d HELD" % (h3, t3))
    held += h3
    total += t3
    # p4: footer
    t4 = 1
    h4 = 0
    ftxt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "# Wave-426 attack round 94:" in ftxt and "next free F1749" in ftxt:
        h4 = 1
    else:
        print("FAIL footer")
    print("p4 footer: %d/%d HELD" % (h4, t4))
    held += h4
    total += t4
    # p5: no paid machinery in new batteries
    bad = ["realmodel_harness", "ModelDriver", "openai"]
    t5 = 0
    h5 = 0
    for num in range(1735, 1749):
        t5 += 1
        btxt = open(os.path.join(REPO_ROOT, "evals", "w426_f%d_redfirst.py" % num)).read()
        if not any(b in btxt for b in bad):
            h5 += 1
        else:
            print("FAIL paid-machinery f%d" % num)
    print("p5 no-paid: %d/%d HELD" % (h5, t5))
    held += h5
    total += t5
    # p6: footer-vs-stamp — F1735-F1748 all OPEN
    t6 = 0
    h6 = 0
    for num in range(1735, 1749):
        t6 += 1
        idx = ftxt.find("(F%d filed" % num)
        if idx >= 0 and "LOW, OPEN" in ftxt[idx:idx+2000]:
            h6 += 1
        else:
            print("FAIL stamp f%d" % num)
    print("p6 stamps: %d/%d HELD" % (h6, t6))
    held += h6
    total += t6
    print("TOTAL: %d/%d HELD" % (held, total))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
