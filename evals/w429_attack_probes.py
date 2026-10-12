#!/usr/bin/env python3
"""Wave-429 attack round 97 coverage battery (wave-429 merge): new F1768-F1781 pins (MISS) +
F1757-F1767 carry-forward CLOSED pins (HIT) + taxonomy/footer/no-paid-machinery.

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

SECRET_S = "xoxb-" + "0123456789abcde"
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


# New round-97 pins: (name, template) — must MISS on open tree
_NEW = [
    ("f1768", "var C={I};var D=new Array(...C);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1769", "var C={I};var [...D]=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1770", "var C={I};var D=C.slice(0).reverse().reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1771", "var C={I};var D=C.toSorted(function(){return 0;}).toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1772", "var C={I};var D=C.with(C.length-C.length,C[C.length-C.length]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1773", "var C={I};var D=C.slice();D.splice(D.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1774", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var RESULT=D.join('');"),
    ("f1775", "var C={I};var it=C.values();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1776", "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1777", "var C={I};Promise.resolve(C).then(function(c){var S=String.fromCharCode.apply(null,c);var RESULT=S;});"),
    ("f1778", "var C={I};var D;var S=(D=C,String.fromCharCode.apply(null,D));var RESULT=S;"),
    ("f1779", "var C={I};var D;D??=C;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1780", "var C={I};var D=C||[];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1781", "var C={I};var D=[];while(C.length){D.push(C.shift());}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward OPEN pins (F1757-F1766 attack 96 + F1767 lane-C residual) — must still MISS
_CARRY = [
    ("F1757", "var C={I};var G=Object.groupBy(C,function(c,i){return Math.floor(i/4);});var D=[];for(var k=0;String(k) in G;k++){D=D.concat(G[String(k)]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1758", "var C={I};var M=new Map(C.map(function(c,i){return [i,c];}));var D=Array.from(M.values());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1759", "var C={I};(async function(){var D=await Array.fromAsync(C);var S=String.fromCharCode.apply(null,D);})();"),
    ("F1760", "var C={I};var B=new Uint8Array(C).buffer;var B2=structuredClone(B,{transfer:[B]});var S=String.fromCharCode.apply(null,Array.from(new Uint8Array(B2)));var RESULT=S;"),
    ("F1761", "var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1762", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}O.length=C.length;var D=Array.from(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1763", "var C={I};var P=new Proxy(C,{});var D=Array.from(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1764", "var C={I};var U=new Uint8Array(C);var V=U.toSorted(function(){return 0;});var D=Array.from(V);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1765", "var C={I};var B=new SharedArrayBuffer(C.length);var U=new Uint8Array(B);U.set(C);var S=String.fromCharCode.apply(null,Array.from(U));var RESULT=S;"),
    ("F1766", "var C={I};var F=new Function('C','return String.fromCharCode.apply(null,C);');var S=F(C);var RESULT=S;"),
    ("F1767", "var C={I};var S=String.fromCharCode.apply(null,C);var R=/(.)/gdi;var D=new Array(C.length);var M;while((M=R.exec(S))!==null){D[M.indices[0][0]]=M[1].charCodeAt(0);}var T=String.fromCharCode.apply(null,D);var RESULT=T;"),
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
    # p2: carry-forward CLOSED pins must now HIT (both sizes) - wave-429 closed F1757-F1767
    h2 = t2 = 0
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "HIT":
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
    if "# Wave-429 attack round 97:" in ftxt and "next free F1782" in ftxt:
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
    for num in range(1768, 1782):
        t5 += 1
        btxt = open(os.path.join(REPO_ROOT, "evals", "w429_f%d_redfirst.py" % num)).read()
        if not any(b in btxt for b in bad):
            h5 += 1
        else:
            print("FAIL paid-machinery f%d" % num)
    print("p5 no-paid: %d/%d HELD" % (h5, t5))
    held += h5
    total += t5
    # p6: footer-vs-stamp — F1768-F1781 all OPEN
    t6 = 0
    h6 = 0
    for num in range(1768, 1782):
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
