#!/usr/bin/env python3
"""F1709 red-first: array.prototype.map-1-param-function-wit

Filed 2026-10-12 02:09 UTC, wave-424 attack round 92 (local node validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
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


def _node_ok(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


_TMPLS = [
    ("f1709", 'var C={I};var D=C.map(function(c){return c;},null);var S=String.fromCharCode.apply(null,D);var RESULT=S;'),
]

_CONTROLS = [
    ("direct-ctrl", 'var C={I};var S=String.fromCharCode.apply(null,C);var RESULT=S;'),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            node = _node_ok(payload, secret)
            verdict = _scan(payload) if node else "SKIP"
            ok = node and verdict == "MISS"
            status = "BREAK" if ok else "FAIL"
            if not ok:
                fails += 1
            print("%s %s: node=%s scanner=%s -> %s" % (name, label, node, verdict, status))
    for name, tmpl in _CONTROLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            verdict = _scan(payload)
            ok = verdict == "HIT"
            if not ok:
                fails += 1
            print("%s %s: control scanner=%s -> %s" % (name, label, verdict, "OK" if ok else "FAIL"))
    junk = "the quick brown fox jumps over the lazy dog"
    v = _scan(junk)
    if v != "MISS":
        fails += 1
        print("junk-quiet: FAIL (got %s)" % v)
    else:
        print("junk-quiet: OK")
    print("RESULT: %s (%d fails)" % ("BREAK" if fails == 0 else "NO-BREAK", fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
