#!/usr/bin/env python3
"""F1703 red-first: surrogate-code smuggling past _safe_chr-gated hooks.

Filed 2026-10-12 00:52 UTC, wave-423 lane D Spec review (local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the open
tree: prepending a surrogate code (e.g. 0xD800) to an integer code array
makes _js_f1124f1130_parse_c_decl fail closed via _safe_chr, while node
assembles the lone surrogate + full credential; find_credential MISSES.
Systemic to every hook on the shared C-decl parser.
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


def _codes_surrogate(s):
    # Prepend a surrogate code (0xD800) to the credential codes.
    return "[0xD800," + ",".join(str(ord(c)) for c in s) + "]"


def _node_has_credential(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return secret in line[4:]
    return False


_TMPLS = [
    ("surrogate-f1686",
     "var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    ("surrogate-f1687",
     "var C={I};var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    ("surrogate-f1688",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;"),
    ("surrogate-f1689",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var D=[...S].map(function(ch){return ch.charCodeAt(0);});var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes_surrogate(secret))
            node_ok = _node_has_credential(payload, secret)
            verdict = _scan(payload)
            ok = node_ok and verdict == "MISS"
            print(("BREAK " if ok else "FAIL ") + "%s %s node_cred=%s scanner=%s" % (name, label, node_ok, verdict))
            if not ok:
                fails += 1
    # Control: no-surrogate shape still HITs (F1686 closure intact).
    cs = "[" + ",".join(str(ord(c)) for c in SECRET_S) + "]"
    p = ("var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);"
         "var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
    v = _scan(p)
    ok = (v == "HIT")
    print(("CTRL-OK " if ok else "CTRL-FAIL ") + "no-surrogate f1686 -> " + v)
    if not ok:
        fails += 1
    print("RESULT: " + ("BREAK" if fails == 0 else "NO-BREAK") + " (%d fails)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
