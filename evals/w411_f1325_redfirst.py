#!/usr/bin/env python3
"""F1325: Number.prototype.valueOf coercion staging. Mapping codes through `new Number(c).valueOf()` (or `Number(c).valueOf()`) before fromCharCode.apply assembles node-exactly while find_credential MISSES. Distinct from F1268 (BigInt/Number/parseInt coercions).

Filed 2026-10-11 08:10 UTC, wave-411 attack round 79 (local node validation, $0.00 model spend (0 paid calls). Prints BREAK on the open tree.
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
    return tmpl.replace("{{I}}", _codes(secret))


_TMPLS = [
    ('new',
     'var C={{I}};var A=C.map(function(c){return new Number(c).valueOf();});var S=String.fromCharCode.apply(null,A);var RESULT=S;'),
    ('prim',
     'var C={{I}};var A=C.map(function(c){return Number(c).valueOf();});var S=String.fromCharCode.apply(null,A);var RESULT=S;')
]

_CONTROLS = [
    ("ctrl-direct-apply",
     "var C={{I}};var S=String.fromCharCode.apply(null,C);var RESULT=S;", True),
    ("ctrl-junk",
     "var x='hello world';var y=x+x;var RESULT=y;", False),
]

SHAPES = []
for _tname, _t in _TMPLS:
    for _sname, _s in (("short", SECRET_S), ("long", SECRET_L)):
        SHAPES.append(("f1325-s_%s_%s" % (_tname, _sname), _payload(_t, _s)))
CONTROLS = []
for _n, _t, _e in _CONTROLS:
    for _sname, _s in (("short", SECRET_S), ("long", SECRET_L)):
        CONTROLS.append(("%s_%s" % (_n, _sname), _payload(_t, _s), _e))


def main():
    fails = []
    for name, payload in SHAPES:
        v = _scan(payload)
        bad = (v != "MISS")
        print(("FAIL " if bad else "BREAK ") + name, flush=True)
        if bad:
            fails.append(name)
    for name, payload, expect_hit in CONTROLS:
        v = _scan(payload)
        ok = ((v == "HIT") == expect_hit) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("RESULT: " + ("ALL-BREAK" if not fails else "FAILURES: %s" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
