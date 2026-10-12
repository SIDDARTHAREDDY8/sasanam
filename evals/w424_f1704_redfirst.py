#!/usr/bin/env python3
"""F1704 red-first: F1689 S2-fresh variant gap.

Wave-424 lane D. Filed 2026-10-12 01:30 UTC by wave-423 merge red-first
audit. Prints BREAK on the open tree: lane D's _js_f1689_stmt_decode
handles the S-redeclare form (var S=String.fromCharCode.apply(null,D))
but MISSES the S2-fresh variant
(var S2=String.fromCharCode.apply(null,D);var RESULT=S2;).
Close-when: decoder handles fresh-name result binding for the
charCodeAt-spread rebuild.
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


def _node_has_credential(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return secret in line[4:]
    return False


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    ("s2-fresh",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
    ("s2-fresh-arrow",
     "var C={I};var S=C.map(c=>String.fromCharCode(c)).join('');var D=[...S].map(ch=>ch.charCodeAt(0));var S2=String.fromCharCode.apply(null,D);var RESULT=S2;"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            node_ok = _node_has_credential(payload, secret)
            verdict = _scan(payload)
            ok = node_ok and verdict == "MISS"
            print(("BREAK " if ok else "FAIL ") + "%s %s node_cred=%s scanner=%s" % (name, label, node_ok, verdict))
            if not ok:
                fails += 1
    # Control: S-redeclare form still HITs (F1689 closure intact).
    p = ("var C=%s;var S=C.map(function(c){return String.fromCharCode(c);}).join('');"
         "var D=[...S].map(function(ch){return ch.charCodeAt(0);});"
         "var S=String.fromCharCode.apply(null,D);var RESULT=S;" % _codes(SECRET_S))
    v = _scan(p)
    ok = (v == "HIT")
    print(("CTRL-OK " if ok else "CTRL-FAIL ") + "s-redeclare f1689 -> " + v)
    if not ok:
        fails += 1
    print("RESULT: " + ("BREAK" if fails == 0 else "NO-BREAK") + " (%d fails)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
