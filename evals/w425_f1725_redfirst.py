#!/usr/bin/env python3
"""F1725 red-first: surrogate-prefixed flat() readout residual

Filed 2026-10-12 03:37 UTC, wave-425 lane C Spec review (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.

The F1714 filing named `apply(null,C.flat())` in its failing set, but the
lane's _js_f1714_stmt_decode covers only direct/spread/call forms. This
battery pins the flat() residual.
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


def _codes_surr(s):
    return "[0xD800," + ",".join(str(ord(c)) for c in s) + "]"


def _node_ok(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return secret in line[4:]
    return False


_TMPLS = [
    ("f1725-flat", 'var C={I};var S=String.fromCharCode.apply(null,C.flat());var RESULT=S;'),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes_surr(secret))
            node = _node_ok(payload, secret)
            verdict = _scan(payload) if node else "SKIP"
            ok = node and verdict == "MISS"
            status = "BREAK" if ok else "FAIL"
            if not ok:
                fails += 1
            print("%s %s: node_cred=%s scanner=%s -> %s" % (name, label, node, verdict, status))
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
