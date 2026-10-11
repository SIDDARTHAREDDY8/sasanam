#!/usr/bin/env python3
"""F1641 red-first: Object.assign(new Array(0),C) copy staging.

Filed 2026-10-11 (wave-420 lane 3 spec-review residual; local node validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
`new Array(0)` is an empty array -- Object.assign copies every index, node-exact (v24.20.0).
Distinct from F1595 (CLOSED: `new Array()` no-arg).
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
    ('f1641-0',
     "var C={I};var D=Object.assign(new Array(0),C);var RESULT=D.map(function(c){return String.fromCharCode(c);}).join('');")
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

    print("RESULT: " + ("BREAK" if fails == 0 else "NO-BREAK") + " (%d fails)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
