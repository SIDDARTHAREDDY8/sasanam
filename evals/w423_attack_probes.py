#!/usr/bin/env python3
"""Wave-423 attack round 91 coverage battery: new F1690-F1702 pins (MISS) +
carry-forward F1672-F1689 pins (MISS) + taxonomy/footer/no-paid-machinery.

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


# New round-91 pins: (name, template) — must MISS on open tree
_NEW = [
    ("f1690", "var C={I};var f=String.fromCharCode.bind(null);var S=f(...C);var RESULT=S;"),
    ("f1691", "var C={I};var f=String.fromCodePoint.bind(null);var S=f.apply(null,C);var RESULT=S;"),
    ("f1692a", "var C={I};var D=C.slice().sort((a,b)=>0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1692b", "var C={I};var D=C.slice().sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1693", "var C={I};var D=[,].concat(C);var S=String.fromCharCode.apply(null,D.slice(1));var RESULT=S;"),
    ("f1694", "var C={I};var O=Object.assign({},C);var E=Object.entries(O);var D=E.map(function(e){return Number(e[1]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1695", "var C={I};var O=Object.assign({},C);var K=Object.keys(O);var D=K.map(function(k){return Number(O[k]);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1696", "var C={I};var A=Reflect.construct(Array,C);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
    ("f1697", "var C={I};var P=new Proxy(C,{get:function(t,k){return t[k];}});var S=String.fromCharCode.apply(null,P);var RESULT=S;"),
    ("f1698a", "var C={I};var U=new Uint8Array(C);var V=U.subarray(0);var S=String.fromCharCode.apply(null,V);var RESULT=S;"),
    ("f1698b", "var C={I};var U=new Uint8Array(C);var V=U.slice();var S=String.fromCharCode.apply(null,V);var RESULT=S;"),
    ("f1699", "var C={I};var T=C.join('\t');var D=T.split('\t').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1700", "var C={I};var T=C.map(String);var D=T.map(function(x){return parseInt(x,10);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1701", "var C={I};var E=C.entries();var D=[];for(var e of E){D.push(e[1]);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1702", "var C={I};var D=[...C.values()].map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward round-90 pins (F1672-F1689) — exact templates from w422_attack_probes.py
# NOTE: F1675 and F1676 are now incidentally HIT on the wave-422 base (see report);
# they are carried as HIT-expect pins below, not MISS.
# wave-423 merge: F1672-F1688 CLOSED -> expect HIT; F1689 S2-fresh is F1704 (OPEN) -> expect MISS
_CARRY_HIT_MERGED = [
    ("F1672", "var C={I};var D=Iterator.from(C).map(function(c){return c;}).toArray();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1673", "var C={I};var T='';Iterator.from(C).forEach(function(c){T+=String.fromCharCode(c);});var RESULT=T;"),
    ("F1677", "var C={I};var D=structuredClone(C);var RESULT=String.fromCharCode.apply(null,D);"),
    ("F1678", "var C={I};var D=JSON.parse(JSON.stringify(C));var RESULT=String.fromCharCode.apply(null,D);"),
    ("F1679", "var C={I};var RESULT=String.fromCodePoint.apply(null,C);"),
    ("F1680", "var C={I};var D=new Uint8Array(C);var RESULT=String.fromCharCode.apply(null,D);"),
    ("F1681", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.bold().replace(/<\\/?b>/g,'');var RESULT=T;"),
    ("F1682", "var C={I};var O=Object.assign({},C);var D=Object.values(O).map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1683", "var C={I};var D=C.map(function(c){return BigInt(c);});var E=D.map(function(b){return Number(b);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1684", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<S.length;i++){D.push(S.at(i-S.length).charCodeAt(0));}var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
    ("F1685", "var C={I};var D=C.map(function(c){return c.toString(16);});var E=D.map(function(h){return parseInt(h,16);});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1686", "var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("F1687", "var C={I};var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1688", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;"),
]
_CARRY_MISS = [
    # F1689 S2-fresh variant is F1704 (OPEN) -- expect MISS
    ("F1704", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
]

# F1675/F1676 incidentally closed on wave-422 base — expect HIT (documented, not restamped)
_CARRY_HIT = [
    ("F1675", "var C={I};var S=String.fromCharCode.apply(null,C);var G=new Intl.Segmenter().segment(S);var T='';for(var s of G){T+=s.segment;}var RESULT=T;"),
    ("F1676", "var C={I};var S=String.fromCharCode.apply(null,C);var P=new URLSearchParams([['k',S]]);var RESULT=P.get('k');"),
]

# F1674 length-dependent: short HITs, long MISSES
_F1674 = "var C={I};var RESULT=Iterator.from(C).map(function(c){return String.fromCharCode(c);}).reduce(function(a,ch){return a+ch;},'');"


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
    for name, tmpl in _CARRY_HIT_MERGED:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "HIT":
                h2 += 1
            else:
                print("FAIL carry-closed %s: got %s" % (name, v))
    for name, tmpl in _CARRY_MISS:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "MISS":
                h2 += 1
            else:
                print("FAIL carry %s: got %s" % (name, v))
    # p2b: carry-forward HIT pins (F1675/F1676 incidentally closed) — expect HIT
    for name, tmpl in _CARRY_HIT:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            v = _scan(tmpl.replace("{I}", _codes(secret)))
            if v == "HIT":
                h2 += 1
            else:
                print("FAIL incidental %s: got %s" % (name, v))
    # F1674: short HIT, long MISS
    t2 += 2
    vs = _scan(_F1674.replace("{I}", _codes(SECRET_S)))
    vl = _scan(_F1674.replace("{I}", _codes(SECRET_L)))
    if vs == "HIT" and vl == "MISS":
        h2 += 2
    else:
        print("FAIL f1674 length: short=%s long=%s" % (vs, vl))
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
    if "# Wave-423 attack round 91:" in ftxt and "next free F1705" in ftxt:
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
    for num in range(1690, 1703):
        t5 += 1
        btxt = open(os.path.join(REPO_ROOT, "evals", "w423_f%d_redfirst.py" % num)).read()
        if not any(b in btxt for b in bad):
            h5 += 1
        else:
            print("FAIL paid-machinery f%d" % num)
    print("p5 no-paid: %d/%d HELD" % (h5, t5))
    held += h5
    total += t5
    print("TOTAL: %d/%d HELD" % (held, total))
    return 0 if held == total else 1


if __name__ == "__main__":
    sys.exit(main())
