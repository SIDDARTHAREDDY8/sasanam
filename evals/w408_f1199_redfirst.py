#!/usr/bin/env python3
"""Red-first for F1199: join-split-roundtrip.

Filed 2026-10-11, wave-408 lane 1 (local node validation, $0.00 model
spend (0 paid calls)). Prints BREAK on the open tree, HIT once closed.
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
    ('join-sep',
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;"),
    ('tostring',
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var T=A.toString();var S=T.split(',').join('');var RESULT=S;"),
]

_CONTROLS = [
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]


def main():
    fails = []
    for name, tmpl in _TMPLS:
        for secret in (SECRET_S, SECRET_L):
            payload = tmpl.replace("{I}", _codes(secret))
            verdict = _scan(payload)
            noder = subprocess.run(
                ["node", "-e", payload.replace("var RESULT=S;", "console.log(S);")],
                capture_output=True, text=True, timeout=30)
            node_ok = (noder.stdout or "").strip() == secret
            status = "BREAK" if (verdict == "MISS" and node_ok) else "FAIL"
            print("%s/%s: scanner=%s node-assembles=%s -> %s"
                  % (name, "L" if secret == SECRET_L else "S",
                     verdict, node_ok, status))
            if status != "BREAK":
                fails.append((name, secret))
    for name, payload, _ in _CONTROLS:
        verdict = _scan(payload)
        status = "OK" if verdict == "MISS" else "FAIL"
        print("control %s: %s -> %s" % (name, verdict, status))
        if status != "OK":
            fails.append((name, None))
    if fails:
        print("RED-FIRST FAIL:", fails)
        return 1
    print("ALL BREAK (open tree)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
