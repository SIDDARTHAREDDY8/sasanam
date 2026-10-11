#!/usr/bin/env python3
"""F1372 red-first: Set.forEach two-param arrow using first param (F1355 residual).

Filed 2026-10-11 10:01 UTC, wave-413 lane 2 Spec-review residual
(local node validation, $0.00 model spend (0 paid calls). Prints
BREAK on the open tree. Uses the genuine filed shape (single-brace
{I} template -- not the vacuous {{I}} form).
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

_NODE = "var C=%s;var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[i]);});if(S!==%r){process.exit(1);}console.log('NODE-OK');"


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
    ("f1360-0", "var C={I};var S='';new Set(C.keys()).forEach((i,k)=>{S+=String.fromCharCode(C[i]);});var RESULT=S;"),
]


def main():
    fails = 0
    for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
        ok = _node_ok(secret)
        print(("NODE-OK " if ok else "NODE-FAIL ") + "f1360/" + tag)
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
    print("FAILURES:" + str(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
