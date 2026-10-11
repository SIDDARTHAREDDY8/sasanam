#!/usr/bin/env python3
"""Red-first for F1195: expression-wrapper laundering (wave-407 lane 3
wrapper).

Thin wrapper extending the wave-406 attack round-74 red-first
SHAPES/CONTROLS (evals/w406_f1195_redfirst.py) with the spec-review
extension shapes (2026-10-11): templates with literal prefix/suffix,
`<expr>+''`, `'x'+<expr>`, stacked `String(`${...}`)` wrappers,
inline-production wrappers, and whitespace-tolerant spellings. Filed
2026-10-11 01:43 UTC by wave-406 attack round 74 (local node
validation, $0.00 model spend (0 paid calls)). Prints BREAK on the
open tree; on the closed tree each shape is flagged.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import w406_f1195_redfirst as _base  # noqa: E402

_NEW_TMPLS = [
    ("tmpl-pre",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=`x${H.join('')}`;var RESULT=S;"),
    ("tmpl-post",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=`${H.join('')}y`;var RESULT=S;"),
    ("suffix-empty",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=H.join('')+'';var RESULT=S;"),
    ("stacked",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=String(`${H.join('')}`);var RESULT=S;"),
    ("inline-pre",
     "var C={I};var S='x'+C.map(function(c){return String.fromCharCode(c);}).join('');var RESULT=S;"),
    ("ws",
     "var C={I};var H=C.map(function(c){return String.fromCharCode(c);});var S=String ( H . join ( '' ) );var RESULT=S;"),
]


def _payload2(tmpl, secret):
    return tmpl.replace("{I}", _base._codes(secret))


SHAPES = list(_base.SHAPES)
for _tname, _t in _NEW_TMPLS:
    SHAPES.append(("f1195-x_%s_short" % _tname,
                   _payload2(_t, _base.SECRET_S)))
    SHAPES.append(("f1195-x_%s_long" % _tname,
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
