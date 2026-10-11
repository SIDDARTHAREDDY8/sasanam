#!/usr/bin/env python3
"""F1384 red-first (wave-415 lane 1 closure): decoder-seam hybrid compositions -- map/flatMap/flat staged sorts
Filed 2026-10-11 10:51 UTC, wave-414 filing lane; closed 2026-10-11 wave-415 lane 1. Prints BREAK on the open (pre-fix) tree.
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


_TMPLS = [
    ("f1384-0",
     "var C={I};var D=C.map(function(c){return c;});D.sort(function(a,b){return 0;});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1384-1",
     "var C={I};var E=C.flatMap(function(c){return [c];});E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1384-2",
     "var C={I};var E=C.flat();E.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]

_CONTROLS = [
    ("f1352-slice-ctrl",
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var D=C.slice();D.sort(function(a,b){return 0;});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("f1350-1param-ctrl",
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var E=C.flatMap(function(c){return [c];});var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("f1349-flat-ctrl",
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var D=C.map(function(c){return [c];});var E=D.flat();var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = (v == "MISS")
            print(("BREAK " if ok else "FAIL ") + name + "/" + tag + " -> " + v)
            if not ok:
                fails += 1
    for name, payload in _CONTROLS:
        v = _scan(payload)
        ok = (v == "HIT")
        print(("CTRL-OK " if ok else "CTRL-FAIL ") + name + " -> " + v)
        if not ok:
            fails += 1
    print("FAILURES:" + str(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
