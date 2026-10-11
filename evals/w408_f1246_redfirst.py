#!/usr/bin/env python3
"""Red-first for F1246: plain-while.

The plain while-loop form var i=0;while(i<C.length){S+=fromCharCode(C[i++]);} assembles
node-exactly (v24.20.0) while find_credential MISSES -- the scanner models the for-loop twin but
not the while-loop twin. Distinct from F1209 (filed: while+shift) and F1240 (filed this round:
do...while) -- plain while+index. 2 shapes verified (short + 40-char), re-verified 3x
deterministic. Controls: basic for-loop accumulation blocks; junk-quiet passes.
Filed 2026-10-11 04:35 UTC, wave-408 attack round 76 (local node validation, $0.00 model spend (0 paid calls). Prints BREAK on the open tree.
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
    return tmpl.replace("{I}", _codes(secret)).replace("{DOTS}", "." * len(secret)).replace("{N}", str(len(secret)))


_TMPLS = [
    ("while",
     "var C={I};var S='';var i=0;while(i<C.length){S+=String.fromCharCode(C[i++]);}var RESULT=S;")
]

_CONTROLS = [
    ("ctrl-basic-for", "var C={I};var S='';for(var i=0;i<C.length;i++){S+=String.fromCharCode(C[i]);}var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False)
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1246-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1246-l_%s_long" % _tname, _payload(_t, SECRET_L)))

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
