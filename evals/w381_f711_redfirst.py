#!/usr/bin/env python3
"""Red-first for F711: integer object members above 2**53 mis-decode in
F535 direct member-read positions (same bug class as F699, which covers
with-scope positions).

`_js_parse_canonical_int` returns plain `str`, so integer provenance is
lost and the F535 member-read path emits the canonical decimal text
while the engine's float64 rounds it (node v24.20.0).

Prints BREAK when the decoder produces a node-INEXACT value;
HELD when it fails closed (None) or decodes node-exactly.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import _try_js_expr_decode_all  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_B = "456789" + "abcdef"

# (name, payload, node-exact value)
SHAPES = [
    ("bigint-dot-read",
     "({x:9007199254740993}).x+'" + _B + "'",
     "9007199254740992" + _B),
    ("bigint-bracket-read",
     "({x:9007199254740993})['x']+'" + _B + "'",
     "9007199254740992" + _B),
]

CONTROLS = [
    ("small-int-still-exact",
     "({x:42}).x+'" + _B + "'",
     "42" + _B),
    ("quoted-bigint-string-exact",
     "({x:'9007199254740993'}).x+'" + _B + "'",
     "9007199254740993" + _B),
    ("values-join-fails-closed",
     "Object.values({x:9007199254740993}).join('')",
     None),  # want None: fail closed (no variant)
]


def main():
    breaks, held = 0, 0
    for name, payload, want in SHAPES + CONTROLS:
        try:
            got = _try_js_expr_decode_all(payload)
        except Exception as e:  # noqa: BLE001 -- loud, never silent
            print("%s: ERROR(%r)" % (name, e))
            breaks += 1
            continue
        # BREAK = node-inexact decode; HELD = fail-closed or exact.
        is_break = got != want
        print("%s: %s (got %r)" % (name,
                                   "BREAK(mis-decode)" if is_break else "HELD",
                                   got))
        if is_break:
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
