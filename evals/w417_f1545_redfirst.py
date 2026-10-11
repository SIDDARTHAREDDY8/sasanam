#!/usr/bin/env python3
"""F1545 red-first: flat depth-2 chained-map variant staging.

Filed 2026-10-11, wave-417 merge red-first audit residual (local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open tree.

`var C=[codes];var E=C.map(function(c){return [[c]];}).flat(2);var S=String.fromCharCode.apply(null,E);`
assembles node-exactly (v24.20.0, identical to the F1432 two-statement form)
while find_credential MISSES. F1432's hook models only the two-statement
D=map/E=D.flat(2) grammar; the chained E=C.map(...).flat(2) form is unmodeled.
Genuine residual found during wave-417 merge audit, not a regression (MISSES
on base a84a482a5 too).
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
    ("f1545-0",
     "var C={I};var E=C.map(function(c){return [[c]];}).flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
]

_CONTROLS = [
    ("direct-ctrl",
     'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
    ("f1432-two-stmt-ctrl",
     'var C={I};var D=C.map(function(c){return [[c]];});var E=D.flat(2);var S=String.fromCharCode.apply(null,E);var RESULT=S;'),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            nc = subprocess.run(
                ["node", "-e",
                 payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
                capture_output=True, text=True, timeout=30)
            node_ok = False
            for line in (nc.stdout or "").strip().split("\n"):
                if line.startswith("OUT:"):
                    node_ok = (line[4:] == secret)
            verdict = _scan(payload)
            ok = node_ok and verdict == "MISS"
            print(("BREAK " if ok else "FAIL ") + "%s %s node=%s scanner=%s" % (name, label, node_ok, verdict))
            if not ok:
                fails += 1
    for name, payload in _CONTROLS:
        payload = payload.replace("{I}", _codes(SECRET_S))
        verdict = _scan(payload)
        ok = verdict == "HIT"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name + " scanner=" + verdict)
        if not ok:
            fails += 1
    print("FAILURES:%d" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
