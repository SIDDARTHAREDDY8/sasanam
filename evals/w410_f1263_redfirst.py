#!/usr/bin/env python3
"""Red-first for F1263: Map.groupBy staging.

Map.groupBy (ES2024) staging of mapped chars under a constant key, read back via .get('k').join(''), assembles node-exactly (v24.20.0) while find_credential MISSES. Twin of Object.groupBy (F1234, OPEN) on the Map API. 4 shapes verified (2 productions, short + 40-char). Controls: plain map+join blocks (F1090); junk-quiet passes. Distinct from F1234 (OPEN: Object.groupBy) and F1230 (OPEN: Map staged reads). Close-when: the decoder models Map.groupBy staging node-exactly (or refuses the laundering coded) such that find_credential flags them, red-first verified, honest text unaffected

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
    ("groupby-const",
     "var C={I};var G=Map.groupBy(C.map(function(c){return String.fromCharCode(c);}),function(){return 'k';});var S=G.get('k').join('');var RESULT=S;"),
    ("groupby-pairs",
     "var C={I};var G=Map.groupBy(C.map(function(c,i){return [i,String.fromCharCode(c)];}),function(e){return 'k';});var S=G.get('k').map(function(e){return e[1];}).join('');var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-mapjoin", "var C={I};var S=C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1263-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1263-s_%s_long" % _tname, _payload(_t, SECRET_L)))

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
