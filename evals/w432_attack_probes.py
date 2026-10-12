#!/usr/bin/env python3
"""Wave-432 attack round 100 coverage battery: new F1827-F1847 pins (MISS) +
F1805-F1821, F1823-F1826 carry-forward pins (still OPEN, MISS) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: p1/p2 scanner pins were verified empirically by the 21 red-first
batteries (evals/w432_f1827_redfirst.py .. f1847: 21/21 HELD per
~/workspace/teams/wave432-attack/run_batteries100.log) during the round;
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


# New round-100 pins: (name, template) — MISS on open tree
_NEW = [
    ("f1827", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(C.length-C.length+2)).trimEnd();var RESULT=U;"),
    ("f1828", "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1829", "var C={I};var D=C.slice();if(D.at(D.length-D.length)===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1830", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.at(i-i+i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1831", "var C={I};var D=C.slice();var E=D.with(0,D[0]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1832", "var C={I};var D=C.slice();var E=D.with(D.length-1,D[D.length-1]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1833", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll(String.fromCharCode(0),String.fromCharCode(1));var RESULT=U;"),
    ("f1834", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replaceAll('~'.repeat(0)+'~','~');var RESULT=U;"),
    ("f1835", "var C={I};var D=C.toSpliced(C.length-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1836", "var C={I};var D=C.slice();var L=D.findLast(function(c){return true;});if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1837", "var C={I};var D=C.slice();var I=D.findLastIndex(function(c){return c===C[C.length-1];});if(I===D.length-1){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1838", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./g)){U+=m[0];}var RESULT=U;"),
    ("f1839", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var R=new RegExp('.'.repeat(1),'g');var U='';for(var m of T.matchAll(R)){U+=m[0];}var RESULT=U;"),
    ("f1840", "var C={I};var D=C.slice();var L=D.at(-1);if(L===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1841", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.slice(T.length-T.length,T.length);var RESULT=U;"),
    ("f1842", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.concat(''.repeat(C.length-C.length));var RESULT=U;"),
    ("f1843", "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var U=D.join(''.repeat(1).slice(0,0));var RESULT=U;"),
    ("f1844", "var C={I};var D=Object.keys(C).map(function(k){return C[k];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1845", "var C={I};var M=new Map();for(var i=0;i<C.length;i++){M.set(i,C[i]);}var D=[...M.values()];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1846", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw`${T}`;var RESULT=U;"),
    ("f1847", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('~');var U=T.split('~'.repeat(1)).join('');var RESULT=U;"),
]

# Carry-forward OPEN pins (F1805-F1821 attack 99 + F1823-F1826 lane-C residuals) — must still MISS
_CARRY = [
    ("F1805", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(C.length-C.length+1);var RESULT=U;"),
    ("F1806", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(C.length,'x');var RESULT=U;"),
    ("F1807", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padStart(C.length-C.length+T.length,'x');var RESULT=U;"),
    ("F1808", "var C={I};var D=C.slice();D.copyWithin(D.length-D.length,D.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1809", "var C={I};var D=C.slice();D.fill(0,D.length,D.length+5);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1810", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charCodeAt(i-i+i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1811", "var C={I};var D=C.slice();if(D.lastIndexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("F1812", "var C={I};var D=C.reduceRight(function(a,c){a.push(c);return a;},[]);D.reverse();var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1813", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.normalize();var D=[];for(var i=0;i<U.length;i++){D.push(U.charCodeAt(i));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1814", "var C={I};var T='  '+C.map(function(c){return String.fromCharCode(c);}).join('')+'  ';var U=T.trim();var RESULT=U;"),
    ("F1815", "var C={I};var T=' '.repeat(C.length-C.length+2)+C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart();var RESULT=U;"),
    ("F1816", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substring(T.length,T.length+T.length);var RESULT=U;"),
    ("F1817", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(T.length,T.length);var RESULT=U;"),
    ("F1818", "var C={I};var D=C.slice();D.splice(1,0,999);D.splice(1,1);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1819", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=decodeURI(encodeURI(T));var RESULT=U;"),
    ("F1820", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.values(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1821", "var C={I};var D=[];for(var [i,v] of C.entries()){D[i]=v;}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1823", "var C={I};var D=[];for(const i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1824", "var C={I};var D=[];for(i in C){D[i]=C[i];}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1825", "var C={I};var D=Array.from(Object.create(C,{}));var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("F1826", "var C={I};var W=new Map();var O={};W.set(O,C);var D=W.get(O);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def main():
    held = 0
    total = 0
    # p1: new pins must MISS (both sizes)
    h1 = t1 = 0
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            t1 += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "MISS":
                h1 += 1
            else:
                print("FAIL new pin %s" % name)
    print("p1 new pins (MISS): %d/%d" % (h1, t1))
    held += h1
    total += t1
    # p2: carry-forward pins must still MISS
    h2 = t2 = 0
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            t2 += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "MISS":
                h2 += 1
            else:
                print("FAIL carry pin %s" % name)
    print("p2 carry pins (MISS): %d/%d" % (h2, t2))
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
    h4 = 1 if "# Wave-432 attack round 100" in txt else 0
    if h4 == 0:
        print("FAIL footer")
    print("p4 footer: %d/%d" % (h4, t4))
    held += h4
    total += t4
    # p5: no-paid-machinery in new batteries
    t5 = 0
    h5 = 0
    import glob
    for path in glob.glob(os.path.join(REPO_ROOT, "evals", "w432_f18*_redfirst.py")):
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
    # p6: stamps present for F1827-F1847
    t6 = 0
    h6 = 0
    for n in range(1827, 1848):
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
