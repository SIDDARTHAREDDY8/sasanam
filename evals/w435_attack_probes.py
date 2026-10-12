#!/usr/bin/env python3
"""Wave-435 attack round 103 coverage battery: new F1891-F1906 pins (MISS) +
F1865-F1881/F1883-F1890 carry-forward pins (still OPEN, MISS) + F1882 covered pin (HIT) +
taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 16 red-first
batteries (evals/w435_f1891_redfirst.py .. f1906: 16/16 BREAK) during the round;
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


_NEW = [
    ("f1891", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimLeft();var RESULT=U;"),
    ("f1892", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;"),
    ("f1893", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T);var RESULT=U;"),
    ("f1894", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`;var RESULT=U;"),
    ("f1895", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T);var RESULT=U;"),
    ("f1896", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'';var RESULT=U;"),
    ("f1897", "var C={I};var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;"),
    ("f1898", "var C={I};var D=C.filter(function(){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1899", "var C={I};var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1900", "var C={I};var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1901", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1902", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=0){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1903", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1904", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-6))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1905", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1906", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join('');var RESULT=U;"),
]

_CARRY = [
    ("f1865", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimRight();var RESULT=U;"),
    ("f1866", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.at(i-(T.length-T.length)).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1867", "var C={I};var D=C.slice();var E=D.with(-1,D[D.length-1]);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1868", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.replace(/~/,'~');var RESULT=U;"),
    ("f1869", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.isWellFormed()){var S=T;}else{var S='';}var RESULT=S;"),
    ("f1870", "var C={I};var D=C.slice();if(D.findLast(function(c,i){return i===D.length-1;})===C[C.length-1]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1871", "var C={I};var D=C.slice();if(D.findLastIndex(function(x){return x===C[0];})>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1872", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='';for(var m of T.matchAll(/./gd)){U+=m[0];}var RESULT=U;"),
    ("f1873", "var C={I};var D=C.toSpliced(-C.length,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1874", "var C={I};var G=Object.groupBy(C,function(c){return 0;});var D=G[0];var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1875", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+T).substr(-T.length,T.length);var RESULT=U;"),
    ("f1876", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.padEnd(T.length,'~'.slice(0,0));var RESULT=U;"),
    ("f1877", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=[];for(var [k,v] of Object.entries(O)){D.push(v);}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1878", "var C={I};var D=C.reduce(function(a,x){return a.concat([x]);},[]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1879", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toLocaleUpperCase().toLocaleLowerCase();var RESULT=U;"),
    ("f1880", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.charAt(0)===T[0]){var S=T;}else{var S='';}var RESULT=S;"),
    ("f1881", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/(?:.)/g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;"),
    ("f1883", "var C={I};var D=C.slice();if(D.includes(C[0],0)){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1884", "var C={I};var D=C.slice();if(D.indexOf(C[C.length-1],C.length-1)>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1885", "var C={I};var D=C.slice();var E=D.toSorted(function(a,b){return a-a;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1886", "var C={I};var D=[C];var E=D.flat(1+1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1887", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){var k=kv[0];var v=kv[1];return v;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1888", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().valueOf();var RESULT=U;"),
    ("f1889", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries([...Object.entries(O)]);var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1890", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.at(-1)===T[T.length-1]){var S=T;}else{var S='';}var RESULT=S;"),
]

_COVERED = [
    ("f1882", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.search(/xoxb/)>=0){var S=T;}else{var S='';}var RESULT=S;"),
]


def main():
    held = 0
    total = 0

    # New pins must MISS (both sizes)
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "MISS":
                held += 1
            else:
                print("FAIL new %s[%d]" % (name, len(secret)))

    # Carry-forward (still OPEN) must MISS
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "MISS":
                held += 1
            else:
                print("FAIL carry %s[%d]" % (name, len(secret)))

    # Covered pins must HIT
    for name, tmpl in _COVERED:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "HIT":
                held += 1
            else:
                print("FAIL covered %s[%d]" % (name, len(secret)))

    # Taxonomy pin 2143
    total += 1
    with open(os.path.join(REPO_ROOT, "gov", "guac_graph.py")) as f:
        if "TAXONOMY_PIN = 2143" in f.read():
            held += 1
        else:
            print("FAIL taxonomy pin")

    # Footer check
    total += 1
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        txt = f.read()
    if "# Wave-435 attack round 103: F1891-F1906 filed OPEN" in txt:
        held += 1
    else:
        print("FAIL footer")

    # No paid machinery in new batteries
    total += 1
    bad = []
    import glob
    for p in glob.glob(os.path.join(REPO_ROOT, "evals", "w435_f*_redfirst.py")):
        with open(p) as f:
            c = f.read()
        for marker in ("realmodel_harness", "ModelDriver", "openai", "anthropic",
                       "ledger", "spend"):
            if marker in c.lower():
                bad.append((p, marker))
    if not bad:
        held += 1
    else:
        print("FAIL paid machinery: %s" % bad)

    # Footer-vs-stamp: F1891-F1906 all OPEN
    total += 1
    ok = True
    for n in range(1891, 1907):
        idx = txt.find("(F%d filed" % n)
        if idx < 0 or "LOW, OPEN" not in txt[idx:idx+2000]:
            print("FAIL stamp F%d" % n)
            ok = False
    if ok:
        held += 1

    print("HELD %d/%d" % (held, total))
    if held == total:
        print("ALL HELD")


if __name__ == "__main__":
    main()
