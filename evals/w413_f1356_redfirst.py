#!/usr/bin/env python3
"""F1356 red-first: Number.prototype.toFixed map codec (F1203 residual).

Filed 2026-10-11 09:13 UTC, wave-412 attack round 80. Prints BREAK on the
open tree. NOTE: the w412_f1356_redfirst.py battery used a `{{I}}` template
with `.replace("{I}", ...)` producing `var C={[...]};` -- a JS SyntaxError,
so its BREAK was vacuous. This battery uses the genuine filed shape.
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

_NODE = (
    "var C=%s;"
    "var D=C.map(function(c){return Number(c.toFixed(0));});"
    "var S=String.fromCharCode.apply(null,D);"
    "if(S!==%r){process.exit(1);}"
    "console.log('NODE-OK');"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR"


def _node_ok(secret):
    codes = "[" + ",".join(str(ord(c)) for c in secret) + "]"
    code = _NODE % (codes, secret)
    r = subprocess.run(["node", "-e", code],
                       capture_output=True, text=True, timeout=60)
    return "NODE-OK" in (r.stdout or "")


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    ("f1356-0",
     "var C={I};var D=C.map(function(c){return Number(c.toFixed(0));});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]

_CONTROLS = [
    ('f1203-forloop-ctrl',
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(parseInt(C[i].toFixed(0),10));}var RESULT=S;"),
]


def main():
    fails = 0
    for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
        ok = _node_ok(secret)
        print(("NODE-OK " if ok else "NODE-FAIL ") + "f1356/" + tag)
        if not ok:
            fails += 1
    for name, tmpl in _TMPLS:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            assert "{" not in payload.split("var C=")[1][:2], \
                "template produced a SyntaxError payload"
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
