#!/usr/bin/env python3
"""Red-first for F1200: F1189 form-B arrow callback (F1189 residual).

The F1189 hook's form B covers `yield* C.map(function(c){...})` but fails
closed on arrow callbacks; `yield* C.map(c=>String.fromCharCode(c))` assembles
node-exactly (v24.20.0, top-level await) while find_credential MISSES.
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
    ("yieldstar-arrow",
     "var C={I};async function*g(){yield* C.map(c=>String.fromCharCode(c));}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;"),
]

_CONTROLS = [
    # form-B fn-callback twin blocks (F1189, CLOSED) -- must still HIT
    ("ctrl-f1189-yieldstar-fn", "var C={I};async function*g(){yield* C.map(function(c){return String.fromCharCode(c);});}var S='';for await(var ch of g()){S+=ch;}var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1200-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1200-l_%s_long" % _tname, _payload(_t, SECRET_L)))

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
    print("RED-FIRST-OK: all %d shapes BREAK (scanner misses yield*-arrow)" % len(SHAPES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
