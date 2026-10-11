#!/usr/bin/env python3
"""Red-first for F1228: flat() depth-literal variants (F1222 residual).

`flat(0)`, `flat(3)`, `flat(10)`, `flat(-1)`, `flat(1.5)`, `flat(0x2)`,
`flat(Infinity)`, `flat()` (no arg, defaults to depth 1), `flat(NaN)`,
`flat(null)`, `flat(undefined)`, `flat("2")`, and `flat("x")` on the
F1187/F1222 `C.map(c=>[[c]])` production all assemble node-exactly
(v24.20.0) while find_credential MISSED. Residual of F1222 (CLOSED):
the widened hook enforced depth in {1,2}.

Filed 2026-10-11 04:32 UTC, wave-408 lane 4 (local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.

Spec-review update 2026-10-11: added NaN/null/undefined/string depths
(all node-verified to assemble via ToIntegerOrInfinity coercion).
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
    ("flat0",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(0));var RESULT=S;"),
    ("flat3",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(3));var RESULT=S;"),
    ("flat10",
     "var C={I};var N=C.map(c=>[[c]]);var S=String.fromCharCode(...N.flat(10));var RESULT=S;"),
    ("flat-neg1",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(-1));var RESULT=S;"),
    ("flat-1.5",
     "var C={I};var N=C.map(c=>[[c]]);var S=String.fromCharCode(...N.flat(1.5));var RESULT=S;"),
    ("flat-hex",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(0x2));var RESULT=S;"),
    ("flat-infinity",
     "var C={I};var N=C.map(c=>[[c]]);var S=String.fromCharCode(...N.flat(Infinity));var RESULT=S;"),
    ("flat-noarg",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat());var RESULT=S;"),
    ("flat-nan",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(NaN));var RESULT=S;"),
    ("flat-null",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(null));var RESULT=S;"),
    ("flat-undefined",
     "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(undefined));var RESULT=S;"),
    ("flat-str2",
     'var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat("2"));var RESULT=S;'),
    ("flat-strx",
     'var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat("x"));var RESULT=S;'),
]

_CONTROLS = [
    ("ctrl-f1187-flat2", "var C={I};var N=C.map(function(c){return [[c]];});var S=String.fromCharCode(...N.flat(2));var RESULT=S;", True),
    ("junk-quiet", "The quarterly financial summary shows revenue growth.", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    SHAPES.append(("f1228-s_%s_short" % _tname, _payload(_t, SECRET_S)))
    SHAPES.append(("f1228-l_%s_long" % _tname, _payload(_t, SECRET_L)))

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
