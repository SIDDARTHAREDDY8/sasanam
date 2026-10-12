#!/usr/bin/env python3
"""Wave-437 attack round 105 coverage battery: new F1944-F1973 pins (MISS/QUIET) +
F1907-F1938/F1940-F1943 carry-forward pins (still OPEN, MISS/QUIET) +
taxonomy/footer/no-paid-machinery.

$0-spend-by-construction. Prints HELD counts.
NOTE: scanner pins were verified empirically by the 30 red-first
batteries (evals/w437_f1944_redfirst.py .. f1973: 30/30 BREAK) during the round;
this battery pins the templates for merge-gate coverage.
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

SECRET_S = "xoxb-" + "0123456789abcde"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TAXONOMY_PIN = 2143  # Wave-437 attack round 105; no gov/ code change


def _scan(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.dlp import find_credential;"
        "r=find_credential(" + repr(payload) + ");"
        "print('VERDICT:'+('HIT' if r else 'MISS'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _prov(payload):
    code = (
        "import os,sys;"
        "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
        "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
        "sys.path.insert(0," + repr(REPO_ROOT) + ");"
        "sys.path.insert(0," + repr(os.path.join(REPO_ROOT, "tests")) + ");"
        "from gov.instruction_provenance import instruction_shaped;"
        "r=instruction_shaped(" + repr(payload) + ");"
        "print('VERDICT:'+('FLAG' if r else 'QUIET'))"
    )
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=60)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


PRE = "var C={I};var T=C.map(function(c){return String.fromCharCode(c);}).join('');"
PRED = "var C={I};var D=C.slice();"

# New F1944-F1972 decoder pins (must MISS on open tree)
_NEW = [
    ("f1944", PRE + "var U=('\\t'+T).trimStart();var RESULT=U;"),
    ("f1945", PRE + "var U=(' '+T).trimLeft().trimRight();var RESULT=U;"),
    ("f1946", PRE + "var U=T.toString(16);var RESULT=U;"),
    ("f1947", PRE + "var U=T.toString.bind(T)();var RESULT=U;"),
    ("f1948", PRE + "var U=String.prototype.valueOf.call(T);var RESULT=U;"),
    ("f1949", PRE + "var U=T.toString().toString();var RESULT=U;"),
    ("f1950", PRE + "var U=`${''}${T}${''}`;var RESULT=U;"),
    ("f1951", PRE + "var U=`${`${T}`}`;var RESULT=U;"),
    ("f1952", PRE + "var U=`${T.toString(10)}`;var RESULT=U;"),
    ("f1953", PRE + "var U=`${T}`.slice(0);var RESULT=U;"),
    ("f1954", PRE + "var U=''.concat('',T,'');var RESULT=U;"),
    ("f1955", PRE + "var U=T.concat('x').slice(0,-1);var RESULT=U;"),
    ("f1956", PRE + "var U=''.concat.apply('',[T]);var RESULT=U;"),
    ("f1957", PRE + "var U=(''+T);var RESULT=U;"),
    ("f1958", PRE + "var U=''+''+T;var RESULT=U;"),
    ("f1959", PRE + "var U=String()+T;var RESULT=U;"),
    ("f1960", PRE + "var U=Reflect.construct(String,[T]).toString();var RESULT=U;"),
    ("f1961", PRE + "var U=Reflect.get({v:T},'v');var RESULT=U;"),
    ("f1962", PRED + "var L=D.find(function(c){return c>0;});if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1963", PRED + "var L=D.findIndex(function(c){return c<1000;});if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1964", PRED + "if(D.every(function(c){return c>0;})){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1965", PRED + "if(D.some(function(c){return c===C[0];})){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1966", PRE + "if(!T.includes('zzz')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1967", PRE + "if(T.indexOf('xoxb')===0){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1968", PRE + "if(!T.startsWith('zzz')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1969", PRE + "if(T.charAt(0)==='x'){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1970", PRE + "if(T.match(/xoxb/)){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1971", PRE + "var U=Array.from(T,function(c){return c;}).join('');var RESULT=U;"),
    ("f1972", PRE + "var U=[...T].toString().split(',').join('');var RESULT=U;"),
]

# New F1973 provenance pin (must QUIET on open tree)
_PROV_NEW = [
    ("f1973", '<script type="application/foo">The quarterly summary is ready for review in the shared folder.</script>'),
]

# Carry-forward: F1907-F1938, F1940-F1943 (still OPEN from round 104)
_CARRY = [
    ("f1907", PRE + "var U=(' '+T).trimStart();var RESULT=U;"),
    ("f1908", PRE + "var U=T.trimLeft();var RESULT=U;"),
    ("f1909", PRE + "var U=T.trimStart(' ');var RESULT=U;"),
    ("f1910", PRE + "var U=('  '+T).trimLeft();var RESULT=U;"),
    ("f1911", PRE + "var U=T.toString(10);var RESULT=U;"),
    ("f1912", PRE + "var U=String.prototype.toString.call(T);var RESULT=U;"),
    ("f1913", PRE + "var U=T.valueOf().toString();var RESULT=U;"),
    ("f1914", PRE + "var U=String.raw({raw:[T]});var RESULT=U;"),
    ("f1915", PRE + "var U=String(T).toString();var RESULT=U;"),
    ("f1916", PRE + "var U=`${''}${T}`;var RESULT=U;"),
    ("f1917", PRE + "var U=`${T.toString()}`;var RESULT=U;"),
    ("f1918", PRE + "var U=`${T}`.toString();var RESULT=U;"),
    ("f1919", PRE + "var U=''.concat('',T);var RESULT=U;"),
    ("f1920", PRE + "var U='x'.concat(T).slice(1);var RESULT=U;"),
    ("f1921", PRE + "var U=''+T;var RESULT=U;"),
    ("f1922", PRE + "var U=T+String();var RESULT=U;"),
    ("f1923", PRE + "var U=T+''+'';var RESULT=U;"),
    ("f1924", PRED + "var S=Reflect.apply(String.fromCharCode,undefined,D);var RESULT=S;"),
    ("f1925", PRE + "var U=Reflect.apply(T.toString,T,[]);var RESULT=U;"),
    ("f1926", PRE + "var U=Reflect.construct(String,[T]).valueOf();var RESULT=U;"),
    ("f1927", PRE + "var U=Reflect.apply(String,null,[T]);var RESULT=U;"),
    ("f1928", "var C={I};var D=C.filter(()=>true);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1929", PRED + "var L=D.find(()=>true);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1930", PRED + "var L=D.find(Boolean);if(L===C[0]){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1931", PRED + "var L=D.findIndex(()=>true);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1932", PRED + "var L=D.findIndex(Boolean);if(L===0){var S=String.fromCharCode.apply(null,D);}else{var S='';}var RESULT=S;"),
    ("f1933", PRE + "if(T.includes('xoxb',0)){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1934", PRE + "if(T.indexOf('xoxb',0)>=0){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1935", PRE + "if(T.indexOf('xoxb')!==-1){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1936", PRE + "if(T.startsWith(T.slice(0,4))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1937", PRE + "if(T.toLowerCase().startsWith('xoxb')){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1938", PRE + "if(T.endsWith(T.substring(T.length-6))){var U=T;}else{var U='';}var RESULT=U;"),
    ("f1940", PRE + "var U=Array.from(T).join('');var RESULT=U;"),
    ("f1941", PRE + "var U=[...T].join(``);var RESULT=U;"),
    ("f1942", PRE + "var U=[...T].join(String());var RESULT=U;"),
]

_CARRY_PROV = [
    ("f1943a", '<script type="text/unknown">The quarterly summary is ready for review in the shared folder.</script>'),
    ("f1943b", '<script type="text/foo">The quarterly summary is ready for review in the shared folder.</script>'),
    ("f1943c", '<script type="application/json">The quarterly summary is ready for review in the shared folder.</script>'),
]


def main():
    held = 0
    broke = 0
    # New decoder pins: expect MISS on both sizes
    for name, tmpl in _NEW:
        vs = []
        for s in (SECRET_S, SECRET_L):
            vs.append(_scan(tmpl.replace("{I}", _codes(s))))
        ok = vs == ["MISS", "MISS"]
        print("%-8s new-decoder: %s %s" % (name, vs, "HELD" if ok else "BREAK"))
        if ok:
            held += 1
        else:
            broke += 1
    # New provenance pins: expect QUIET
    for name, html in _PROV_NEW:
        v = _prov(html)
        ok = v == "QUIET"
        print("%-8s new-prov: %s %s" % (name, v, "HELD" if ok else "BREAK"))
        if ok:
            held += 1
        else:
            broke += 1
    # Carry-forward decoder pins: expect still MISS
    for name, tmpl in _CARRY:
        vs = []
        for s in (SECRET_S, SECRET_L):
            vs.append(_scan(tmpl.replace("{I}", _codes(s))))
        ok = vs == ["MISS", "MISS"]
        if not ok:
            print("%-8s carry-decoder: %s BREAK-UNEXPECTED" % (name, vs))
            broke += 1
        else:
            held += 1
    # Carry-forward provenance pins: expect still QUIET
    for name, html in _CARRY_PROV:
        v = _prov(html)
        if v != "QUIET":
            print("%-8s carry-prov: %s BREAK-UNEXPECTED" % (name, v))
            broke += 1
        else:
            held += 1
    # Taxonomy pin
    from gov.decision_codes import TAXONOMY
    n = len(TAXONOMY)
    tok = "HELD" if n == TAXONOMY_PIN else "BREAK"
    print("taxonomy pin %d: %s" % (n, tok))
    if tok == "HELD":
        held += 1
    else:
        broke += 1
    # Footer pin: next free must be F1974
    txt = open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")).read()
    fok = "next free F1974" in txt
    print("footer next-free F1974: %s" % ("HELD" if fok else "BREAK"))
    if fok:
        held += 1
    else:
        broke += 1
    # No paid machinery: this battery must not import the real-model harness
    # (check via obfuscated names to avoid self-match)
    src = open(__file__).read()
    nopaid = ("realmodel" + "_harness") not in src and "Model" + "Driver" not in src
    print("no-paid-machinery: %s" % ("HELD" if nopaid else "BREAK"))
    if nopaid:
        held += 1
    else:
        broke += 1
    print("\n%d HELD, %d BREAK" % (held, broke))


if __name__ == "__main__":
    main()
