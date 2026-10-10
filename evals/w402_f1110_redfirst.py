#!/usr/bin/env python3
"""Red-first for F1110: inline C.values() of-source evades the F1091 closure.

F1091 (CLOSED wave-401 lane 1) models iteration-protocol staged assembly
for `for[-await]...of` over C / C.values() / C.entries(), but its hook
requires the `var IT=C.values();` binding -- the inline of-source
`for(var x of C.values()){S+=String.fromCharCode(x);}` (and the
for-await async-IIFE twin, arrow form) assemble node-exactly
(v24.20.0) while find_credential MISSES.

Filed 2026-10-10 by the wave-401 merge Spec-axis review (HARD-1
residual). Prints BREAK on the open tree, 0 BREAK on the closed tree.

Run: ~/workspace/.gov-venv/bin/python evals/w402_f1110_redfirst.py
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
    # Sync inline of-source.
    ("inline-values",
     "var C={I};var S='';for(var x of C.values())"
     "{{S+=String.fromCharCode(x);}}var RESULT=S;"),
    # For-await inline of-source, async-IIFE arrow form (filed shape).
    ("inline-values-await",
     "(async()=>{{var C={I};var S='';for await (var x of C.values())"
     "{{S+=String.fromCharCode(x);}}globalThis.RESULT=S;}})();"),
]


def _shapes():
    out = []
    for name, tmpl in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1110-%s-%s" % (tag, name),
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
