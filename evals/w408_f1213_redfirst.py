#!/usr/bin/env python3
"""Red-first for F1213: JSON char-array roundtrip (wave-408 lane 3 wrapper).

Thin wrapper extending the wave-407 attack round-75 red-first
SHAPES/CONTROLS (evals/w407_f1213_redfirst.py) with generalization
twins (arrow map callback, whitespace-tolerant spellings). Filed
2026-10-11 03:06 UTC by wave-407 attack round 75 (local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the
open tree; on the closed tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import w407_f1213_redfirst as _base  # noqa: E402

_NEW_TMPLS = [
    ("arrow",
     "var C={I};var A=C.map(c=>String.fromCharCode(c));var J=JSON.stringify(A);var B=JSON.parse(J);var S=B.join('');var RESULT=S;"),
    ("inline",
     "var C={I};var A=C.map(function(c){return String.fromCharCode(c);});var B=JSON.parse(JSON.stringify(A));var S=B.join('');var RESULT=S;"),
    ("ws",
     "var C = {I} ; var A = C . map ( function ( c ) { return String . fromCharCode ( c ) ; } ) ; var J = JSON . stringify ( A ) ; var B = JSON . parse ( J ) ; var S = B . join ( '' ) ; var RESULT = S ;"),
]

SHAPES = list(_base.SHAPES)
for _tname, _t in _NEW_TMPLS:
    SHAPES.append(("f1213-s_%s_short" % _tname, _base._payload(_t, _base.SECRET_S)))
    SHAPES.append(("f1213-l_%s_long" % _tname, _base._payload(_t, _base.SECRET_L)))

CONTROLS = list(_base.CONTROLS)
_CONTROLS = list(_base._CONTROLS)


def main():
    fails = []
    for name, payload in SHAPES:
        v = _base._scan(payload)
        hit = (v == "HIT")
        bad = hit or v == "ERR"
        print(("FAIL " if bad else "BREAK ") + name, flush=True)
        if bad:
            fails.append(name)
    for (name, _t, expect_block), (_cn, payload) in zip(_CONTROLS, CONTROLS):
        v = _base._scan(payload)
        hit = (v == "HIT")
        ok = (hit == expect_block) and v != "ERR"
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name, flush=True)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
