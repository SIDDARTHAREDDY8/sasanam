#!/usr/bin/env python3
"""F1703 red-first: surrogate-code smuggling residual (wave-425 lane A).

Filed 2026-10-12 00:52 UTC (renumbered from F1690 per wave-272). Wave-424
lane D fixed the statement-decoder shared path (_js_f996f997_fcc_chr) and
_js_parse_fromcharcode_args_inner, but F1703 remains OPEN (partial).
This battery probes surrogate-camouflaged variants across statement-decoder
shapes to find remaining gaps. Prints BREAK on the open tree.
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
    # F1686-style with surrogate (statement decoder)
    ("surr-f1686",
     "var C={I};var D=C.map(function(c){return String(c);});var E=D.map(Number);var S=String.fromCharCode.apply(null,E);var RESULT=S;"),
    # F1687-style with surrogate
    ("surr-f1687",
     "var C={I};var T=C.join(',');var D=T.split(',').map(Number);var S=String.fromCharCode.apply(null,D);var RESULT=S;"),
    # F1688-style with surrogate
    ("surr-f1688",
     "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var T=S.split('').reverse().reverse().join('');var RESULT=T;"),
    # F1689-style with surrogate
    ("surr-f1689",
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
            print(("%s %s: node_cred=%s scanner=%s -> %s" % (
                name, label, node_ok, verdict, "BREAK" if ok else "FAIL")))
            if not ok:
                fails += 1
    # Control: no-surrogate shape still HITs.
    cs = "[" + ",".join(str(ord(c)) for c in SECRET_S) + "]"
    p = ("var C=%s;var D=C.map(function(c){return String(c);});var E=D.map(Number);"
         "var S=String.fromCharCode.apply(null,E);var RESULT=S;" % cs)
    v = _scan(p)
    ok = (v == "HIT")
    print(("CTRL-OK " if ok else "CTRL-FAIL ") + "no-surrogate -> " + v)
    if not ok:
        fails += 1
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
