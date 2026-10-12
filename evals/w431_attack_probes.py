#!/usr/bin/env python3
"""Wave-431 attack round 99 coverage battery: new F1805-F1822 + F1823-F1826 pins (MISS) +
F1782-F1804 carry-forward pins (now CLOSED wave-431, HIT) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: p1/p2 scanner pins were verified empirically by the 18 red-first
batteries (evals/w431_f1805_redfirst.py .. f1822: 18/18 HELD per
~/workspace/teams/wave431-attack/run_batteries99.log) during the round;
this battery pins the templates for merge-gate coverage.
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


# New round-99 pins: (name, template) — MISS on open tree
_NEW = [
    ("f1805", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;"),
    ("f1806", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'x');var RESULT=U;"),
    ("f1807", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(C.length-C.length+T.length,'x');var RESULT=U;"),
    ("f1808", "var C={I};var D=C.slice();D.copyWithin(D.length-D.length,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1809", "var C={I};var D=C.slice();D.fill(0,D.length,D.length+5);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1810", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1811", "var C={I};var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1812", "var C={I};var D=C.reduceRight(function(a,c){a.push(c);return a;},[]);D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1813", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.normalize();var D=[];for(var i=0;i<U.length;i++){D.push(U.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1814", "var C={I};var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T.trim();var RESULT=U;"),
    ("f1815", "var C={I};var T=' '.repeat(C.length-C.length+2)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;"),
    ("f1816", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substring(T.length,T.length+T.length);var RESULT=U;"),
    ("f1817", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(T.length,T.length);var RESULT=U;"),
    ("f1818", "var C={I};var D=C.slice();D.splice(1,0,999);D.splice(1,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1819", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=decodeURI(encodeURI(T));var RESULT=U;"),
    ("f1820", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1821", "var C={I};var D=[];for(var [i,v] of C.entries()){D[i]=v;}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1822", "var C={I};var D=new Array(C.length);for(var i=0;i<C.length;i++){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1823", "var C={I};var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1824", "var C={I};var D=[];for(i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1825", "var C={I};var D=Array.from(Object.create(C,{}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1826", "var C={I};var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

# Carry-forward OPEN pins (F1782-F1804: attack 98 + lane-C residuals) — must still MISS
_CARRY = [
    ("F1782", "var C={I};var D=[C.slice(0,10),C.slice(10)].flat();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1783", "var C={I};var D=C.slice(undefined,undefined);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1784", "var C={I};var D=C.concat(C).slice(0,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1785", "var C={I};var D=[];C.forEach(function(c){D.push(c);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1786", "var C={I};var D=[];for(var c of C){D.push(c);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1787", "var C={I};var D=Array.from(C.keys()).map(function(i){return C[i];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1788", "var C={I};var D=Array.from(C.entries()).map(function(e){return e[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1789", "var C={I};var it=C[Symbol.iterator]();var D=[];var r;while(!(r=it.next()).done){D.push(r.value);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1790", "var C={I};function*g(){yield*C;}var D=Array.from(g());var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1791", "var C={I};var D=Array.from(C.values().map(function(c){return c;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1792", "var C={I};var D=Array.from(C.values().filter(function(){return true;}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1793", "var C={I};var D=new Array(C.length);for(var i=0;i<C.length;i++){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1794", "var C={I};var D=[];for(var i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1795", "var C={I};var D=Array.from(Object.create(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1796", "var C={I};var W=new WeakMap();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1797", "var C={I};var R=new WeakRef(C);var D=R.deref();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1798", "var C={I};var D=Array.from(new Uint16Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1799", "var C={I};var D=Array.from(new Float64Array(C));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1800", "var C={I};var R=function(){var r={};for(var i=0;i<C.length;i++){r[i]=C[i];}r.length=C.length;return r;}();var S=String.fromCharCode.apply(null,R);var RESULT=S;"),
    ("F1801", "var C={I};var D=C.slice();var t=D[0];D[0]=D[D.length-1];D[D.length-1]=t;var u=D[0];D[0]=D[D.length-1];D[D.length-1]=u;var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1802", "var C={I};var D=C.map(function(c,i){return String.fromCharCode(c);});var RESULT=D.join('');"),
    ("F1803", "var C={I};var G=Map.groupBy(C,function(c,i){return Math.floor(i/2048);});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1804", "var C={I};var G=Map.groupBy(C,function(c){return 0;});var D=[];for(var k=0;G.has(k);k++){D=D.concat(G.get(k));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def main():
    held = 0
    total = 0
    # p1: new pins must MISS (both sizes), except f1822 (covered by F1793 hook, HIT)
    h1 = t1 = 0
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            t1 += 1
            payload = tmpl.replace("{I}", _codes(secret))
            expected = "HIT" if name == "f1822" else "MISS"
            v = _scan(payload)
            if v == expected:
                h1 += 1
            else:
                print("FAIL new pin %s: got %s, expect %s" % (name, v, expected))
    print("p1 new pins: %d/%d HELD" % (h1, t1))
    held += h1
    total += t1
    # p2: carry-forward pins must HIT (CLOSED wave-431)
    h2 = t2 = 0
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "HIT":
                h2 += 1
            else:
                print("FAIL carry pin %s" % name)
    print("p2 carry pins (HIT): %d/%d" % (h2, t2))
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
    print("p3 taxonomy: %d/%d" % (h3, t3))
    held += h3
    total += t3
    # p4: footer present
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    t4 = 1
    h4 = 1 if "# Wave-431 attack round 99" in txt else 0
    if h4 == 0:
        print("FAIL footer")
    print("p4 footer: %d/%d" % (h4, t4))
    held += h4
    total += t4
    # p5: no-paid-machinery in new batteries
    t5 = 0
    h5 = 0
    import glob
    for path in glob.glob(os.path.join(REPO_ROOT, "evals", "w431_f18*_redfirst.py")):
        t5 += 1
        src = open(path).read()
        bad = any(k in src for k in ("realmodel_harness", "ModelDriver", "openai", "ledger"))
        if not bad:
            h5 += 1
        else:
            print("FAIL no-paid %s" % path)
    print("p5 no-paid: %d/%d" % (h5, t5))
    held += h5
    total += t5
    # p6: stamps present for F1805-F1822 (attack) and F1823-F1826 (renumbered)
    t6 = 0
    h6 = 0
    for n in list(range(1805, 1823)) + list(range(1823, 1827)):
        t6 += 1
        idx = txt.find("(F%d filed" % n)
        if idx >= 0 and "LOW, OPEN" in txt[idx:idx+2000]:
            h6 += 1
        else:
            print("FAIL stamp F%d" % n)
    print("p6 stamps: %d/%d" % (h6, t6))
    held += h6
    total += t6
    print("TOTAL: %d/%d HELD" % (held, total))
    sys.exit(0 if held == total else 1)


if __name__ == "__main__":
    main()
