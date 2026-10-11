#!/usr/bin/env python3
"""Red-first for F1277: Block-statement wrappers defeat staged-assembly hooks.

Wrapping a staged-assembly production in if(true){}, try{}catch{}, a labeled block, for(;;){break}, do{}while(false), switch(true), or with(){} defeats the _stmtdec hooks -- verified against F1199 (CLOSED), F1200 (CLOSED), and F1203 (CLOSED) productions. All assemble node-exactly (v24.20.0) while find_credential MISSES. 10 shapes verified (5 productions, short + 40-char). Controls: the unwrapped productions block (F1199/F1200/F1203); junk-quiet passes. Distinct from F1195 (CLOSED: expression wrappers). Close-when: the decoder models block-wrapped staged assembly node-exactly (or refuses the laundering coded) such that find_credential flags them, red-first verified, honest text unaffected

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
    ("if-f1199",
     "var C={I};var S='';if(true){var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}var RESULT=S;"),
    ("try-f1199",
     "var C={I};var S='';try{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var P=J.split('|:|').join('');S=P;}catch(e){}var RESULT=S;"),
    ("label-f1199",
     "var C={I};var S='';blk:{var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');S=J.split('|:|').join('');}var RESULT=S;"),
    ("forbreak-f1199",
     "var C={I};var S='';for(;;){var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');S=J.split('|:|').join('');break;}var RESULT=S;"),
    ("with-f1199",
     "var C={I};var S='';with({A:C.map(function(x){return String.fromCharCode(x);})}){S=A.join('');}var RESULT=S;"),
]

_CONTROLS = [
    ("ctrl-f1199-bare", "var C={I};var A=C.map(function(x){return String.fromCharCode(x);});var J=A.join('|:|');var S=J.split('|:|').join('');var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1277-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1277-s_%s_long" % _tname, _payload(_t, SECRET_L)))

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
