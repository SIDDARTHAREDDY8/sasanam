#!/usr/bin/env python3
"""Wave-433 attack round 101 coverage battery: new F1848-F1864 pins (MISS) +
F1827-F1847 carry-forward pins (still OPEN, MISS) + taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 17 red-first
batteries (evals/w433_f1848_redfirst.py .. f1864: 17/17 BREAK) during the round;
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


# New round-101 pins: (name, template) — MISS on open tree
_NEW = [
    ("f1848", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[];for(var i=0;i<T.length;i++){D.push(T.charAt(i).charCodeAt(0));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1849", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.match(/./g);var S=String.fromCharCode.apply(null,A.map(function(c){return c.charCodeAt(0);}));var RESULT=S;"),
    ("f1850", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.search('xoxb')>=0){var S=T;}else{var S='';}var RESULT=S;"),
    ("f1851", "var C={I};var D=C.slice();if(D.includes(D[0])){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1852", "var C={I};var D=C.slice();if(D.indexOf(C[0])>=0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1853", "var C={I};var D=C.slice();var E=D.toSorted(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1854", "var C={I};var D=C.slice();var E=D.toReversed().toReversed();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1855", "var C={I};var D=[C];var E=D.flat(2-1);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1856", "var C={I};var D=C.slice(C.length-C.length,C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1857", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var D=Object.entries(O).map(function(kv){return kv[1];});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1858", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf();var RESULT=U;"),
    ("f1859", "var C={I};var O={};for(var i=0;i<C.length;i++){O[i]=C[i];}var P=Object.fromEntries(Object.entries(O));var D=Object.values(P);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1860", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '.repeat(3)+T).trimStart().trimEnd();var RESULT=U;"),
    ("f1861", "var C={I};var D=[];for(var i=0;i<C.length;i++){D.push(C.at(i-(C.length-C.length)));}var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1862", "var C={I};var D=C.with(C.length-C.length,C[0]);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1863", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.repeat(2-1);var RESULT=U;"),
    ("f1864", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var A=T.split('',T.length);var U=A.join('');var RESULT=U;"),
]

# Carry-forward OPEN pins (F1827-F1847 attack 100) — must still MISS
_CARRY = [
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

    # Carry-forward must still MISS (both sizes)
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            payload = tmpl.replace("{I}", _codes(secret))
            if _scan(payload) == "MISS":
                held += 1
            else:
                print("FAIL carry %s[%d]" % (name, len(secret)))

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
    if "# Wave-433 attack round 101: F1848-F1864 filed OPEN" in txt:
        held += 1
    else:
        print("FAIL footer")

    # No paid machinery in new batteries
    total += 1
    bad = []
    import glob
    for p in glob.glob(os.path.join(REPO_ROOT, "evals", "w433_f*_redfirst.py")):
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

    # Footer-vs-stamp: F1848-F1864 all OPEN with first-filing
    total += 1
    ok = True
    for n in range(1848, 1865):
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
