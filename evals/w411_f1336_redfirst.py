#!/usr/bin/env python3
"""Red-first for F1336: Set.forEach arrow-callback twin.

`new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));` with
empty or non-empty accumulator init assembles node-exactly (v24.20.0)
while find_credential MISSES. The F1264/F1317 decoders require the
`function(i){...}` callback form.

Filed 2026-10-11 08:20 UTC, wave-411 lane 3 spec-review residual
(local node validation, $0.00 model spend (0 paid calls). Prints
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
    ("arrow-empty",
     "var C={I};var S='';new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));var RESULT=S;"),
    ("arrow-nonempty",
     "var C={I};var S='x';new Set(C.keys()).forEach(i=>S+=String.fromCharCode(C[i]));var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-fn-empty", "var C={I};var S='';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;", True),
    ("ctrl-fn-nonempty", "var C={I};var S='x';new Set(C.keys()).forEach(function(i){S+=String.fromCharCode(C[i]);});var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]


def _payload(tmpl, secret):
    return tmpl.replace("{I}", _codes(secret))


SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1323-s_%s" % _tname, _payload(_t, SECRET_S)))

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
