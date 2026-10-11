#!/usr/bin/env python3
"""Red-first for F1224: while-loop FormData staged reads.

While-loop FormData staged reads -- staging chars via F.append/set in
a `while(i<C.length)` loop then reading back via values() assembles
node-exactly (v24.20.0) while find_credential MISSES. 4 shapes
verified (2 productions: append/set, short + 40-char). Controls:
indexed-for twin blocks (F1193, CLOSED); junk-quiet passes. Residual
of F1193 (CLOSED): its hook models forEach/for-of/indexed-for
staging only.
Filed 2026-10-11 03:38 UTC, wave-407 lane 3 spec-review follow-up
(local node validation, $0.00 model spend (0 paid calls)). Prints
BREAK on the open tree.
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
    ("while-append",
     "var C={I};var F=new FormData();let i=0;while(i<C.length){F.append('k'+i,String.fromCharCode(C[i]));i++;}var S=Array.from(F.values()).join('');var RESULT=S;"),
    ("while-set",
     "var C={I};var F=new FormData();let i=0;while(i<C.length){F.set('k'+i,String.fromCharCode(C[i]));i++;}var S=[...F.values()].join('');var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-f1193-indexed", "var C={I};var F=new FormData();for(let i=0;i<C.length;i++){F.append('k'+i,String.fromCharCode(C[i]));}var S=Array.from(F.values()).join('');var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1224-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1224-l_%s_long" % _tname, _payload(_t, SECRET_L)))

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
