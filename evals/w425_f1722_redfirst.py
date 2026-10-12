#!/usr/bin/env python3
"""Red-first battery for F1722 (structuredclone-options).

Wave-425 attack round 93. Genuine {I} templates (never vacuous {{I}}).
Break-first: on the open tree the scanner MISSES while node confirms the
credential assembles. Post-fix the filed shape must HIT.
"""
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"

SHAPE = 'var C={I};var D=structuredClone(C,{transfer:[]});var S=String.fromCharCode.apply(null,D);var RESULT=S;'

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
    for sname, secret in (("short", SECRET_S), ("long", SECRET_L)):
        payload = SHAPE.replace("{I}", _codes(secret))
        node_ok = _node_ok(payload, secret)
        verdict = _scan(payload) if node_ok else "NODE-FAIL"
        # Break-first expectation on the OPEN tree: node confirms, scanner MISSES
        expect_break = (os.environ.get("W425_EXPECT", "BREAK") == "BREAK")
        if expect_break:
            ok = node_ok and verdict == "MISS"
            print(("BREAK " if ok else "FAIL ") + "F1722 %s node_cred=%s scanner=%s" % (sname, node_ok, verdict))
        else:
            ok = node_ok and verdict == "HIT"
            print(("HIT-OK " if ok else "FAIL ") + "F1722 %s node_cred=%s scanner=%s" % (sname, node_ok, verdict))
        fails += 0 if ok else 1
    # junk-quiet control: plain prose stays quiet
    junk = "the quick brown fox jumps over the lazy dog"
    jv = _scan(junk)
    jok = (jv == "MISS")
    print(("CTRL-OK " if jok else "CTRL-FAIL ") + "junk-quiet -> " + jv)
    fails += 0 if jok else 1
    print("RESULT: " + ("BREAK" if (expect_break and fails == 0) else
                         "NO-BREAK" if (not expect_break and fails == 0) else
                         "FAILURES"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
