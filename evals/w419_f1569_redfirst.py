#!/usr/bin/env python3
"""F1569 red-first: Array.prototype.flatMap 4-param arrow callback with null thisArg.

Filed 2026-10-11 17:05 UTC, wave-418 lane-1 residual (local node validation, $0.00 model spend (0 paid calls); node v24.20.0, one find_credential per fresh process).
`C.flatMap((c,i,a,t)=>[c],null)` assembles node-exactly (v24.20.0) while
find_credential MISSES. Distinct from F1518 (CLOSED: 4-param function-form
null thisArg + 5-param arrow via F1504 hook), F1504 (OPEN: 4-param
function/arrow with {} thisArg, 5-param function), F1546 (attack-86 OPEN:
1-param callback with [] thisArg, arrow with "x" thisArg -- different shapes).
Prints BREAK on the closed lane-1 tree (residual, unfiled at wave-418 merge).
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


def _node_assembles(payload, secret):
    js = "(function(){ %s return S; })()" % payload
    r = subprocess.run(["node", "-e", "var S=%s; console.log(S===%r?'OK':'NO');" % (js, secret)],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() == "OK"


_TMPLS = [
    ('f1569-0',
     'var C={I};var E=C.flatMap((c,i,a,t)=>[c],null);var S=String.fromCharCode.apply(null,E);var RESULT=S;'),
]

_CONTROLS = [
    ('direct-ctrl',
     'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
]


def main():
    n_closed = 0
    n_total = 0
    for name, tmpl in _TMPLS:
        for sec in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(sec))
            n_total += 1
            if not _node_assembles(payload, sec):
                print("%s/%d: node MISASSEMBLES (shape not node-exact here)" % (name, len(sec)))
                continue
            v = _scan(payload)
            if v == "HIT":
                n_closed += 1
                print("%s/%d: CLOSED (scanner HIT, node-exact)" % (name, len(sec)))
            else:
                print("%s/%d: HELD (scanner %s)" % (name, len(sec), v))
    for name, tmpl in _CONTROLS:
        for sec in (SECRET_S, SECRET_L):
            v = _scan(tmpl.replace("{I}", _codes(sec)))
            print("control %s/%d: scanner %s (want HIT)" % (name, len(sec), v))
    print("CLOSED %d/%d" % (n_closed, n_total))
    return 0 if n_closed == n_total and n_total > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
