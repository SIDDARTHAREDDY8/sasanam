#!/usr/bin/env python3
"""Red-first for F1199: flat(1) on doubly-nested arrays (F1187 residual).

The F1187 hook enforces depth == 2; swapping the literal to flat(1) on the
same doubly-nested production assembles node-exactly (v24.20.0) while
find_credential MISSES. One-character attacker tweak of a CLOSED finding.
Filed 2026-10-11 (first-filing timestamp recorded in evals/FINDINGS.md entry).
Prints BREAK on the lane tree (pre-closure).
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


def _payload(tmpl, secret):
    return tmpl.replace("{I}", _codes(secret))


_TMPLS = [
    ("flat1-doublenested-fn",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(1));var RESULT=S;"),
    ("flat1-doublenested-arrow",
     "var C={I};var N=C.map(c=>[[c]]);var S=String.fromCharCode(...N.flat(1));var RESULT=S;"),
]

_CONTROLS = [
    # flat(2) twin blocks (F1187, CLOSED) -- must still HIT
    ("ctrl-f1187-flat2", "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(2));var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1199-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1199-l_%s_long" % _tname, _payload(_t, SECRET_L)))

CONTROLS = [(_n, _payload(_t, SECRET_S)) for (_n, _t, _e) in _CONTROLS]


def main():
    fails = []
    for name, payload in SHAPES:
        v = _scan(payload)
        hit = (v == "HIT")
        bad = hit or v == "ERR"
        print(("FAIL " if bad else "BREAK ") + name, flush=True)
        if bad:
            fails.append(name)
    for (name, _t, _e), (_n2, payload) in zip(_CONTROLS, CONTROLS):
        v = _scan(payload)
        hit = (v == "HIT")
        ok = (hit == _e) and v != "ERR"
        print(("ctrl-OK " if ok else "ctrl-FAIL ") + name, flush=True)
        if not ok:
            fails.append("control:" + name)
    if fails:
        print("RED-FIRST-FAIL: " + ",".join(fails))
        return 1
    print("RED-FIRST-OK: all %d shapes BREAK (scanner misses flat(1))" % len(SHAPES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
