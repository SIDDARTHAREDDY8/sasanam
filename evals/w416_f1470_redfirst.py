#!/usr/bin/env python3
"""F1470 red-first: F1362 keys-map parenthesized arrow readout residual -- `Object.keys(O).map((k)=>O[k])` assembles node-exactly while _js_f1362_stmt_decode admits bare `k=>O[k]` only.
Filed 2026-10-11, wave-415 Spec-review residual (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK per shape on the open
tree (node v24.20.0 assembles the credential, find_credential MISSES);
after closure the same shape prints CLOSED (scanner HITs). Controls
verify the pre-existing hooks in the same family still work.
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


def _node_ok(payload, secret):
    nc = subprocess.run(
        ["node", "-e",
         payload + ";console.log('OUT:'+((typeof RESULT!=='undefined')?RESULT:''));"],
        capture_output=True, text=True, timeout=30)
    for line in (nc.stdout or "").strip().split("\n"):
        if line.startswith("OUT:"):
            return line[4:] == secret
    return False


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    ('paren-keys-arrow',
     "var O={{}};var C={I};C.forEach(function(c,i){{O['k'+i]=c;}});var A=Object.keys(O).map((k)=>O[k]);var S=String.fromCharCode.apply(null,A);var RESULT=S;"),
]

_CONTROLS = [
    ("bare-keys-arrow-ctrl", "var O={};var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];C.forEach(function(c,i){O['k'+i]=c;});var A=Object.keys(O).map(k=>O[k]);var S=String.fromCharCode.apply(null,A);var RESULT=S;", True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, label in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.format(I=_codes(secret))
            ok = _node_ok(payload, secret)
            verdict = _scan(payload)
            if not ok:
                print("FAIL   %s %s node did not assemble" % (name, label))
                fails += 1
            elif verdict == "MISS":
                print("BREAK  %s %s node=ok scanner=MISS" % (name, label))
            elif verdict == "HIT":
                print("CLOSED %s %s node=ok scanner=HIT" % (name, label))
            else:
                print("FAIL   %s %s scanner=%s" % (name, label, verdict))
                fails += 1
    for name, payload, expect_hit in _CONTROLS:
        verdict = _scan(payload)
        good = (verdict == "HIT") == expect_hit
        print(("ctrl-ok " if good else "CTRL-FAIL ") + name +
              " scanner=" + verdict)
        if not good:
            fails += 1
    print("FAILURES:%d" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
