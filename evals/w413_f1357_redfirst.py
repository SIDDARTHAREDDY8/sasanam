#!/usr/bin/env python3
"""F1357 red-first: chained join/split/join (F1199 residual) -- D.join('|').split('|').join('') in one statement

Filed 2026-10-11 09:13 UTC, wave-412 attack round 80 (local node validation, $0.00 model spend (0 paid calls).
Wave-413 lane 3: verified against the CLOSED tree -- all shapes now BLOCK (post-fix).
Note: wave-412's w412_f1357_redfirst.py used {{I}} templates producing `var C={[...]}` (SyntaxError, vacuous BREAK).
This file uses single-brace {I} templates with real payloads.
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


# Filed shapes (must BLOCK on closed tree) + generalizations
_TMPLS = [
    ("f1357-0",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT=S;"),
    # Arrow twin of the map callback
    ("f1357-arrow",
     "var C={I};var D=C.map(c=>String.fromCharCode(c));var S=D.join('|').split('|').join('');var RESULT=S;"),
    # Different separator
    ("f1357-sep",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join(':::').split(':::').join('');var RESULT=S;"),
    # Empty separator (identity)
    ("f1357-empty-sep",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('').split('').join('');var RESULT=S;"),
    # RESULT with additive literal
    ("f1357-additive",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('|').split('|').join('');var RESULT='pre-'+S;"),
]

_CONTROLS = [
    # F1199 two-statement form still blocks (control)
    ('f1199-twostatement-ctrl',
     "var C=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101];var A=C.map(function(c){return String.fromCharCode(c);});var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            # On the CLOSED tree, filed shapes must BLOCK (HIT)
            ok = (v == "HIT")
            print(("BLOCK " if ok else "MISS ") + name + "/" + tag + " -> " + v)
            if not ok:
                fails += 1
    for name, payload in _CONTROLS:
        v = _scan(payload)
        ok = (v == "HIT")
        print(("CTRL-OK " if ok else "CTRL-FAIL ") + name + " -> " + v)
        if not ok:
            fails += 1
    print("FAILURES:" + str(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
