#!/usr/bin/env python3
"""Red-first for F1131: array-copy staged spread residuals.

spreading array *copies* beyond F1120's slice/`[].concat`/Array.of coverage: `...C.splice(0)`, `...C.concat([])`, `...new Array(...C)`, `...C.map(identity)`, and `...new Array(len).fill(0).map((_,i)=>C[i])` all assemble node-exactly (v24.20.0) while find_credential MISSES. 10 shapes verified (5 productions, short + 40-char).
On the open tree find_credential MISSES each shape (prints BREAK, one
scanner call per fresh process); on the closed tree each is flagged.
Filed 2026-10-10 18:13 UTC wave-403 (attack round 71, local validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
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


_TMPLS = [
    ('splice',
     'var C={{I}};var S=String.fromCharCode(...C.splice(0));var RESULT=S;'),
    ('concat-empty',
     'var C={{I}};var S=String.fromCharCode(...C.concat([]));var RESULT=S;'),
    ('new-array',
     'var C={{I}};var S=String.fromCharCode(...new Array(...C));var RESULT=S;'),
    ('map-identity',
     'var C={{I}};var S=String.fromCharCode(...C.map(function(c){return c;}));var RESULT=S;'),
    ('fill-map',
     'var C={{I}};var S=String.fromCharCode(...new Array(C.length).fill(0).map(function(_,i){return C[i];}));var RESULT=S;'),
]


def _shapes():
    out = []
    for name, t in _TMPLS:
        for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
            out.append(("f1131-%s-%s" % (tag, name),
                        t.replace("{{I}}", _codes(secret))))
    return out


SHAPES = _shapes()

_CONTROLS = [
    ('aa-plain-spread-blocks',
     'var C={{I}};var S=String.fromCharCode(...C);var RESULT=S;',
     True),
    ('junk-quiet',
     "(function(){var s='ab';return s;})()",
     False),
]


def _cshapes():
    out = []
    for name, t, _ in _CONTROLS:
        out.append((name, t.replace("{{I}}", _codes(SECRET_S))))
    return out


CONTROLS = _cshapes()


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
