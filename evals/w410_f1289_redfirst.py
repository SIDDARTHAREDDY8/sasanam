#!/usr/bin/env python3
"""Closure verification for F1289: hasOwnProperty method-call guard.

Wave-410 lane 3. Discovered during F1280 closure: the method-call form
O.hasOwnProperty(k) assembles node-exactly (v24.20.0) but the F1280 hook
(as filed) only modeled Object.hasOwn and Object.prototype.hasOwnProperty.call.
Filed 2026-10-11 07:10 UTC as F1289 (next-free from wave-409 footer).
Prints HIT on the closed tree; exits 0 iff all shapes HIT and controls pass.
Capture via Python subprocess only.
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
    ("method-call",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(O.hasOwnProperty(k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-hasown", "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.hasOwn(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1289-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1289-s_%s_long" % _tname, _payload(_t, SECRET_L)))

CONTROLS = [(_n, _payload(_t, SECRET_S)) for (_n, _t, _e) in _CONTROLS]


def main():
    fails = []
    for name, payload in SHAPES:
        v = _scan(payload)
        ok = (v == "HIT")
        print(("HIT  " if ok else "MISS ") + name, flush=True)
        if not ok:
            fails.append(name)
    for (name, _t, expect_hit), (_cn, payload) in zip(_CONTROLS, CONTROLS):
        v = _scan(payload)
        hit = (v == "HIT")
        ok = (hit == expect_hit) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
