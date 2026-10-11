#!/usr/bin/env python3
"""Red-first for F1162: sort-family no-op laundering wrappers.

Using sort()/toSorted() as a pure no-op laundering wrapper: a comparator that always returns 0 never reorders (stable), so spreading the result assembles the credential while the spread receiver is an unmodeled sort call. F1153 models sort-comparator *side-effect accumulation*; this is sort as a transparent wrapper. All assemble node-exactly (v24.20.0) while find_credential MISSES.
Filed 2026-10-10 21:30 UTC wave-405 (attack round 73, local validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
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
    return tmpl.replace("{I}", _codes(secret)).replace("{N}", str(len(secret)))


_TMPLS = [
    ("sort-noop",
     "var C={I};var D=C.slice().sort(function(){return 0;});var S=String.fromCharCode(...D);var RESULT=S;"),
    ("sort-noop-arrow",
     "var C={I};var D=C.slice().sort(()=>0);var S=String.fromCharCode(...D);var RESULT=S;"),
    ("tosorted-noop",
     "var C={I};var D=C.toSorted(function(){return 0;});var S=String.fromCharCode(...D);var RESULT=S;"),
    ("tosorted-noop-arrow",
     "var C={I};var D=C.toSorted(()=>0);var S=String.fromCharCode(...D);var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-plain-spread-blocks", "var C={I};var S=String.fromCharCode(...C);var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1162-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1162-l_%s_long" % _tname, _payload(_t, SECRET_L)))

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
    for (name, _t, expect_block), (_cn, payload) in zip(_CONTROLS, CONTROLS):
        v = _scan(payload)
        hit = (v == "HIT")
        ok = (hit == expect_block) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
