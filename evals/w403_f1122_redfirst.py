#!/usr/bin/env python3
"""Red-first for F1122: undeclared loop variable evades the F1091 closure.

F1091 (CLOSED wave-401 lane 1) requires a declaration keyword for the
for-of loop variable ("loop var not declared" fails closed). In
sloppy mode node binds a bare identifier as a global --
`for(x of IT){...}` and `for([i,c] of C.entries()){...}` assemble
node-exactly (v24.20.0 verified, sloppy script files) while
find_credential MISSES.

Filed 2026-10-10 16:57 UTC by wave-402 lane 3 (Spec-review follow-up;
renumbered F1112->F1122 at the wave-402 merge per wave-272; local node
validation, $0.00 model spend). Prints BREAK on the open tree.

Run: ~/workspace/.gov-venv/bin/python evals/w403_f1122_redfirst.py
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
    "print('HIT' if find_credential(%r) else 'MISS')"
)


def _scan(payload):
    code = _CHILD % (REPO_ROOT, os.path.join(REPO_ROOT, "tests"), payload)
    r = subprocess.run([sys.executable, "-c", code],
                       capture_output=True, text=True, timeout=180)
    lines = (r.stdout or "").strip().split("\n")
    return lines[-1] == "HIT" if lines and lines[-1] else False


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


_TMPLS = [
    # Undeclared loop var over the bound values-iterator.
    ("undeclared-IT",
     "var C={I};var IT=C.values();var S='';for(x of IT)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    # Undeclared destructure over entries().
    ("undeclared-entries",
     "var C={I};var S='';for([i,c] of C.entries())"
     "{{S+=String.fromCharCode(c);}}var RESULT=S;"),
    # Undeclared loop var over the plain array (Spec-review HARD-1:
    # the declared twin `for(var x of C)` is an earlier hook's; the
    # undeclared variant was modeled nowhere).
    ("undeclared-C",
     "var C={I};var S='';for(x of C)"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
]


def _shapes():
    out = []
    for name, tmpl in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1122-%s-%s" % (tag, name),
                        tmpl.format(I=_codes(secret))))
    return out


SHAPES = _shapes()


def main():
    bad = 0
    for name, payload in SHAPES:
        if _scan(payload):
            print("FAIL " + name, flush=True)
        else:
            print("BREAK " + name, flush=True)
            bad += 1
    print("%d/%d BREAK" % (bad, len(SHAPES)))
    return 0 if bad else 1


if __name__ == "__main__":
    sys.exit(main())
