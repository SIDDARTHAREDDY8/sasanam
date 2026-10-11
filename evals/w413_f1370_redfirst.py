#!/usr/bin/env python3
"""F1370 red-first: F1357 multi-char SEP residual (Spec-review residual).

`D.join('ab').split('ab').join('')` with a credential containing 'a' but not 'b'
is node-identity (v24.20.0) but `_js_f1357_stmt_decode` fails closed (SEP-char check
is sufficient, not necessary) -> MISS. Filed 2026-10-11 09:59 UTC, wave-413 lane 3
Spec-review residual (local node validation, $0.00 model spend (0 paid calls).
Prints BREAK on the open tree.
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

# Credential contains 'a' (97) but no 'b' (98)
SECRET_S = "xoxb-01" + "23456789acdef"
SECRET_L = "xoxb-" + "0123456789acdef0123456789acdef012"

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
    ("f1360-0",
     "var C={I};var D=C.map(function(c){return String.fromCharCode(c);});var S=D.join('ab').split('ab').join('');var RESULT=S;"),
]


def main():
    fails = 0
    for name, tmpl in _TMPLS:
        for secret, tag in ((SECRET_S, "short"), (SECRET_L, "long")):
            payload = tmpl.replace("{I}", _codes(secret))
            v = _scan(payload)
            ok = (v == "MISS")
            print(("BREAK " if ok else "FAIL ") + name + "/" + tag + " -> " + v)
            if not ok:
                fails += 1
    print("FAILURES:" + str(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
