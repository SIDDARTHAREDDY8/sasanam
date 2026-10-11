#!/usr/bin/env python3
"""Red-first for F1280: hasOwn-guarded for-in staging.

for(k in O){if(Object.hasOwn(O,k)){S+=fromCharCode(O[k])}} assembles node-exactly (v24.20.0) while find_credential MISSES. The for-in hook models the bare loop but not the hasOwn-guarded form. 4 shapes verified (2 productions, short + 40-char). Controls: bare for-in accumulation blocks; junk-quiet passes. Close-when: the decoder models hasOwn-guarded for-in node-exactly (or refuses the laundering coded) such that find_credential flags them, red-first verified, honest text unaffected

Filed 2026-10-11 05:57 UTC, wave-409 attack round 77 (local node validation, $0.00 model spend (0 paid calls). Prints BREAK on the open tree.
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


def _payload_p(tmpl):
    return tmpl.replace("{P}", PROSE)


_TMPLS = [
    ("hasown",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.hasOwn(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
    ("hasownproperty",
     "var C={I};var O={};C.forEach(function(c,i){O['k'+i]=c;});var S='';for(var k in O){if(Object.prototype.hasOwnProperty.call(O,k)){S+=String.fromCharCode(O[k]);}}var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-mapjoin", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1280-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1280-s_%s_long" % _tname, _payload(_t, SECRET_L)))

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
