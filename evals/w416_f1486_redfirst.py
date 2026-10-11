#!/usr/bin/env python3
"""F1486 red-first: F1390 copyWithin(0,0) residual

Wave-416 lane-4 group C. Filed 2026-10-11 (wave-415 lane 2 Spec-review
residual). Assembles node-exactly (v24.20.0) while find_credential MISSES
on the open tree; prints BREAK there, HIT once the hook is extended.
Controls: direct fromCharCode.apply is coded (HIT); junk text stays quiet
(MISS). Python-subprocess capture only; $0 spend.
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
    ("f1486",
     'var C=__CODES__;var D=C.slice();D.copyWithin(0,0);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
]

_CONTROLS = [
    ("direct-ctrl",
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var S=String.fromCharCode.apply(null,C);var RESULT=S;",
     "HIT"),
    ("junk-quiet",
     "var greeting = 'hello world, this is a normal log line'; var x = 42; console.log(greeting);",
     "MISS"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("__CODES__", _codes(secret))
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
    for name, payload, want in _CONTROLS:
        verdict = _scan(payload)
        ok = verdict == want
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name + " scanner=" + verdict)
        if not ok:
            fails += 1
    print("FAILURES:%d" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
