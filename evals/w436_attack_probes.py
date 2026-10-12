#!/usr/bin/env python3
"""Wave-436 attack round 104 coverage battery: new F1907-F1943 pins (MISS) +
F1891-F1904/F1906 carry-forward pins (still OPEN, MISS) +
taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 37 red-first
batteries (evals/w436_f1907_redfirst.py .. f1943: 37/37 BREAK) during the round;
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
    ("f1907", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(' '+T).trimStart();var RESULT=U;"),
    ("f1908", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimLeft();var RESULT=U;"),
    ("f1909", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.trimStart(' ');var RESULT=U;"),
    ("f1910", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=('  '+T).trimLeft();var RESULT=U;"),
    ("f1911", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString(10);var RESULT=U;"),
    ("f1912", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.prototype.toString.call(T);var RESULT=U;"),
    ("f1913", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.valueOf().toString();var RESULT=U;"),
    ("f1914", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String.raw({raw:[T]});var RESULT=U;"),
    ("f1915", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T).toString();var RESULT=U;"),
    ("f1916", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${''}${T}`;var RESULT=U;"),
    ("f1917", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T.toString()}`;var RESULT=U;"),
    ("f1918", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`.toString();var RESULT=U;"),
    ("f1919", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat('',T);var RESULT=U;"),
    ("f1920", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U='x'.concat(T).slice(1);var RESULT=U;"),
    ("f1921", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''+T;var RESULT=U;"),
    ("f1922", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+String();var RESULT=U;"),
    ("f1923", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+''+'';var RESULT=U;"),
    ("f1924", 'var C={I};var D=C.slice();var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;'),
    ("f1925", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(T.toString,T,[]);var RESULT=U;"),
    ("f1926", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;"),
    ("f1927", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Reflect.apply(String,null,[T]);var RESULT=U;"),
    ("f1928", 'var C={I};var D=C.filter(()=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ("f1929", "var C={I};var D=C.slice();var L=D.find(()=>true);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1930", "var C={I};var D=C.slice();var L=D.find(Boolean);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1931", "var C={I};var D=C.slice();var L=D.findIndex(()=>true);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1932", "var C={I};var D=C.slice();var L=D.findIndex(Boolean);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1933", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb',0)){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1934", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb',0)>=0){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1935", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')!==-1){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1936", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith(T.slice(0,4))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1937", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.toLowerCase().startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1938", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1939", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-1))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1940", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=Array.from(T).join('');var RESULT=U;"),
    ("f1941", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(``);var RESULT=U;"),
    ("f1942", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join(String());var RESULT=U;"),
]

_PROV_NEW = [
    ("f1943a", '<script type="text/unknown">PROBE</script>'),
    ("f1943b", '<script type="text/foo">PROBE</script>'),
    ("f1943c", '<script type="application/json">PROBE</script>'),
]

_CARRY = [
    ("f1891", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=(T+' '.repeat(2)).trimLeft();var RESULT=U;"),
    ("f1892", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T.toString();var RESULT=U;"),
    ("f1893", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=String(T);var RESULT=U;"),
    ("f1894", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=`${T}`;var RESULT=U;"),
    ("f1895", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=''.concat(T);var RESULT=U;"),
    ("f1896", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=T+'';var RESULT=U;"),
    ("f1897", 'var C={I};var D=C.slice();var S=Reflect.apply(String.fromCharCode,null,D);var RESULT=S;'),
    ("f1898", 'var C={I};var D=C.filter(function(){return true;});var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
    ("f1899", "var C={I};var D=C.slice();var L=D.find(function(c){return true;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1900", "var C={I};var D=C.slice();var L=D.findIndex(function(c){return true;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1901", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.includes('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1902", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.indexOf('xoxb')>=0){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1903", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1904", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');if(T.endsWith(T.slice(-6))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1906", "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');var U=[...T].join('');var RESULT=U;"),
]

_PROV_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.instruction_provenance import instruction_shaped;"
    "r=instruction_shaped(%r);"
    "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
)

_PAYLOAD = "The quarterly summary is ready for review in the shared folder."


def _pcheck(html):
    code = _PROV_CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), html)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def main():
    held = 0
    total = 0
    # new decoder pins: must MISS x2 sizes
    for name, tmpl in _NEW:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            if _scan(tmpl.replace("{I}", _codes(secret))) == "MISS":
                held += 1
            else:
                print("UNEXPECTED HIT:", name)
    # new provenance pins: must be QUIET
    for name, shape in _PROV_NEW:
        total += 1
        if _pcheck(shape.replace("PROBE", _PAYLOAD)) == "QUIET":
            held += 1
        else:
            print("UNEXPECTED FLAG:", name)
    # carry-forward pins: must still MISS x2 sizes
    for name, tmpl in _CARRY:
        for secret in (SECRET_S, SECRET_L):
            total += 1
            if _scan(tmpl.replace("{I}", _codes(secret))) == "MISS":
                held += 1
            else:
                print("CARRY HIT (now closed?):", name)
    # taxonomy pin
    total += 1
    sys.path.insert(0, os.path.join(REPO_ROOT, "gov"))
    import guac_graph
    if guac_graph.TAXONOMY_PIN == 2143:
        held += 1
    else:
        print("TAXONOMY PIN MISMATCH")
    # footer pin
    total += 1
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    if "next free F1944" in txt:
        held += 1
    else:
        print("FOOTER PIN MISMATCH")
    # no-paid-machinery self-check: scan the new red-first batteries
    total += 1
    import glob
    bad = []
    for p in glob.glob(os.path.join(REPO_ROOT, "evals", "w436_f*_redfirst.py")):
        with open(p) as f:
            c = f.read()
        for marker in ("realmodel_harness", "ModelDriver", "openai", "anthropic",
                       "ledger", "spend"):
            if marker in c.lower():
                bad.append((p, marker))
    if not bad:
        held += 1
    else:
        print("PAID MACHINERY PRESENT: %s" % bad)
    print("HELD %d/%d" % (held, total))


if __name__ == "__main__":
    main()
