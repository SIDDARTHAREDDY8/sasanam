#!/usr/bin/env python3
"""Red-first for F1194: integrity-method wrapper staged reads (wave-407
lane 3 wrapper).

Thin wrapper extending the wave-406 attack round-74 red-first
SHAPES/CONTROLS (evals/w406_f1194_redfirst.py) with the spec-review
extension shapes (2026-10-11): `C.slice(0)`, `Array.from(C)`,
`[...C]` copy arms, and whitespace-tolerant spellings. Filed
2026-10-11 01:43 UTC by wave-406 attack round 74 (local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the
open tree; on the closed tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import w406_f1194_redfirst as _base  # noqa: E402

_NEW_TMPLS = [
    ("slice0",
     "var C={I};var S=String.fromCharCode(...Object.freeze(C.slice(0)));var RESULT=S;"),
    ("array-from",
     "var C={I};var S=String.fromCharCode(...Object.seal(Array.from(C)));var RESULT=S;"),
    ("spread-copy",
     "var C={I};var S=String.fromCharCode(...Object.preventExtensions([...C]));var RESULT=S;"),
    ("ws",
     "var C = {J} ; var S = String . fromCharCode ( ... Object . seal ( C ) ) ; var RESULT = S ;"),
]


def _spaced(secret):
    return "[ " + " , ".join(str(ord(c)) for c in secret) + " ]"


def _payload2(tmpl, secret):
    return tmpl.replace("{I}", _base._codes(secret)).replace(
        "{J}", _spaced(secret))


SHAPES = list(_base.SHAPES)
for _tname, _t in _NEW_TMPLS:
    SHAPES.append(("f1194-x_%s_short" % _tname,
                   _payload2(_t, _base.SECRET_S)))
    SHAPES.append(("f1194-x_%s_long" % _tname,
                   _payload2(_t, _base.SECRET_L)))

CONTROLS = _base.CONTROLS


def main():
    fails = []
    for name, payload in SHAPES:
        v = _base._scan(payload)
        hit = (v == "HIT")
        bad = hit or v == "ERR"
        print(("FAIL " if bad else "BREAK ") + name, flush=True)
        if bad:
            fails.append(name)
    for (name, _t, expect_block), (_cn, payload) in zip(_base._CONTROLS,
                                                        CONTROLS):
        v = _base._scan(payload)
        hit = (v == "HIT")
        ok = (hit == expect_block) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL"
          % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
