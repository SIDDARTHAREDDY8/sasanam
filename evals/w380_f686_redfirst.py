#!/usr/bin/env python3
"""Red-first for F686: integer object members above 2**53 mis-decode in
with-scope resolution (F667 overstatement).

F667 (CLOSED, wave-379 lane 5) claims node-exact with-scope resolution
("fail closed, never mis-decoded"), but an integer member above 2**53
mis-decodes: the engine's float64 rounds the literal, while the decoder
emits the canonical text. _js_parse_canonical_int returns plain str, so
the `not isinstance(v, _JSNumStr)` guard in the F667 scope filter is
dead code on this path.

Prints BREAK when the decoder produces a node-INEXACT value;
HELD when it fails closed (None) or decodes node-exactly.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import _try_js_expr_decode_all  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

# (name, payload, node-exact value or None if node throws)
SHAPES = [
    ("bigint-with",
     "(function(){var o={x:9007199254740993};with(o){return x+'" + _B + "';}})()",
     "9007199254740992" + _B),
    ("bigint-with-2",
     "(function(){var o={x:9999999999999999};with(o){return x;}})()",
     "10000000000000000"),
]

CONTROLS = [
    ("small-int-still-exact",
     "(function(){var o={x:42};with(o){return x+'" + _B + "';}})()",
     "42" + _B),
    ("quoted-bigint-string-exact",
     "(function(){var o={x:'9007199254740993'};with(o){return x+'" + _B + "';}})()",
     "9007199254740993" + _B),
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
        is_break = got is not None and got != want
        print("%s: %s" % (name, "BREAK(mis-decode)" if is_break else "HELD"))
        if is_break:
            breaks += 1
        else:
            held += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
