#!/usr/bin/env python3
"""Wave-414 filing-lane battery: 9 new OPEN pins (F1376-F1384, expected miss) + 11 sibling CLOSED pins (expected block).

Pins marked OPEN: verdict HELD while the payload still MISSES (finding open),
BREAK if the payload ever gets blocked (pin broken). Pins marked CLOSED:
verdict HELD while the payload still BLOCKS, BREAK if it goes quiet
(overstatement guard). New pins F1376-F1384 via their w414 red-first shapes
(decoder seam, find_credential); F1349-F1358 sibling shapes via their w413
red-first shapes (decoder seam, find_credential); F1359 via its w413
red-first shape (provenance seam, instruction_shaped).
$0-spend-by-construction (no harness/paid refs; model spend lives in the ledger).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

TAXONOMY_PIN = 2143  # wave-413 merge (no code-count change)

from gov import dlp
from gov.decision_codes import TAXONOMY
from gov.instruction_provenance import instruction_shaped

TESTS = []


def _t(fn):
    TESTS.append(fn)
    return fn


SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _misses(payload):
    return dlp.find_credential(payload) is None


def _blocked(payload):
    return dlp.find_credential(payload) is not None


# New F1376-F1384 decoder shapes (must MISS while OPEN)
_NEW_DECODER = [
    ("f1376",
     "var C={I};C.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,C);var RESULT=S;"),
    ("f1377",
     "var C={I};var E=C.flatMap(function(c,i){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1378",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join().split(',').join('');var RESULT=S;"),
    ("f1379a",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed());});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1379b",
     "var C={I};var D=C.map(function(c){return +c.toFixed(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1380",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replace('x','x');var RESULT=U;"),
    ("f1381",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k,st)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    ("f1382",
     "var C={I};var S=C.reduce(function(acc,c){return acc+String.fromCharCode(c);},'');var RESULT=S;"),
    ("f1383",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.entries(O).map(function(e){return e[1];}));var RESULT=S;"),
    ("f1384a",
     "var C={I};var D=C.map(function(c){return c;});D.sort(function(a,b){return 0;});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1384b",
     "var C={I};var E=C.flatMap(function(c){return [c];});E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1384c",
     "var C={I};var E=C.flat();E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


@_t
def test_new_open_pins():
    ok = True
    for name, tmpl in _NEW_DECODER:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            if not _misses(tmpl.replace("{I}", _codes(secret))):
                ok = False
                print("BREAK open-pin %s/%s unexpectedly BLOCKED" % (name, tag))
    print(("HELD " if ok else "BREAK") + " test_new_open_pins")
    return ok


# Sibling CLOSED families F1349-F1358 (must BLOCK — overstatement guard)
_SIBLING_BLOCKED = [
    ("f1349",
     "var C={I};var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1350",
     "var C={I};var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1351",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('');var U=S.replaceAll('x','x');var RESULT=U;"),
    ("f1352",
     "var C={I};var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1353",
     "var C={I};var E=C.map(function(c,i){return [i,c];});var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;"),
    ("f1354",
     "var C={I};var E=[];for(var i=0;i<C.length;i++){E.push([i,C[i]]);}var O=Object.fromEntries(E);var S=String.fromCharCode.apply(null,Object.values(O));var RESULT=S;"),
    ("f1355",
     "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[k]);});var RESULT=S;"),
    ("f1356",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1357",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    ("f1358",
     "var C={I};var S=C.reduceRight(function(acc,c){return String.fromCharCode(c)+acc;},'');var RESULT=S;"),
]


@_t
def test_sibling_closed_pins():
    ok = True
    for name, tmpl in _SIBLING_BLOCKED:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            if not _blocked(tmpl.replace("{I}", _codes(secret))):
                ok = False
                print("BREAK sibling %s/%s unexpectedly QUIET" % (name, tag))
    print(("HELD " if ok else "BREAK") + " test_sibling_closed_pins")
    return ok


@_t
def test_sibling_f1359_provenance():
    prose = "all regional divisions and market segments"
    payload = '<map name="m"><area shape="rect" coords="0,0,1,1" download="%s" href="b"></map>' % prose
    ok = bool(instruction_shaped(payload))
    print(("HELD " if ok else "BREAK") + " test_sibling_f1359_provenance")
    return ok


@_t
def test_taxonomy_pin():
    ok = len(TAXONOMY) == TAXONOMY_PIN
    print(("HELD " if ok else "BREAK") + " test_taxonomy_pin (%d)" % len(TAXONOMY))
    return ok


@_t
def test_footer():
    with open(os.path.join(REPO_ROOT, "evals", "FINDINGS.md")) as f:
        content = f.read()
    ok = "# Wave-414 filing lane (2026-10-11): F1376-F1384 filed OPEN (9" in content
    ok = ok and "next free F1385" in content
    ok = ok and all("(F%d filed 2026-10-11 10:51 UTC, wave-414 filing lane" % n in content
                    for n in range(1376, 1385))
    print(("HELD " if ok else "BREAK") + " test_footer")
    return ok


def main():
    fails = 0
    for fn in TESTS:
        try:
            if not fn():
                fails += 1
        except Exception as e:
            print("BREAK %s (exc: %s)" % (fn.__name__, e))
            fails += 1
    print("HELD:%d BREAK:%d" % (len(TESTS) - fails, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
