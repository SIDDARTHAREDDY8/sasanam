#!/usr/bin/env python3
"""Wave-426 attack round 94 red-first battery for F1748 (fill-empty-range).

Break-first: scanner must MISS the filed shape on the open tree (node confirms).
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

TEMPLATE = 'var C={I};var D=C.slice();D.fill(0,C.length-C.length,C.length-C.length);var S=String.fromCharCode.apply(null,D);var RESULT=S;'

_CHILD = (
    "import os,sys;"
    "os.environ.setdefault('GOV_DEPLOYMENT_MODE','staging');"
    "os.environ.setdefault('GOV_LOG_KEY','00'*32);"
    "sys.path.insert(0,%r);sys.path.insert(0,%r);"
    "from gov.dlp import find_credential;"
    "r=find_credential(%r);"
    "print('VERDICT:'+('HIT' if r else 'MISS'))"
)


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    for line in (r.stdout or "").strip().split("\n"):
        if line.startswith("VERDICT:"):
            return line[len("VERDICT:"):]
    return "ERR:" + (r.stderr or "")[-200:]


def _node_ok(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def main():
    fails = 0
    for tag, secret in (("short", SECRET_S), ("long", SECRET_L)):
        payload = TEMPLATE.replace("{I}", _codes(secret))
        nok = _node_ok(payload, secret)
        v = _scan(payload) if nok else "NODE-INVALID"
        ok = nok and v == "MISS"
        print(("PASS" if ok else "FAIL") + " f1748 %s node_cred=%s scanner=%s" % (tag, nok, v))
        if not ok:
            fails += 1
    # junk-quiet control
    junk = "hello world, this is a plain test string with no credentials at all"
    vj = _scan(junk)
    qok = vj == "MISS"
    print(("PASS" if qok else "FAIL") + " f1748 junk-quiet scanner=%s" % vj)
    if not qok:
        fails += 1
    print("RESULT: %s (%d fails)" % ("BREAK" if fails == 0 else "NO-BREAK", fails))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
