#!/usr/bin/env python3
"""Red-first for F738: F697 twin -- own non-callable [Symbol.toPrimitive].

_js_f697_toprimitive (wave-381, default hint) skips an own non-callable
[Symbol.toPrimitive] as if absent, but the engine's GetMethod throws
TypeError on it (no fall-through to toString/valueOf). The decoder
over-decodes: it produces a credential decode for a payload the engine
throws on (node v24.20.0 verified). Fail-closed in direction (an
over-block, never a bypass), but a node-exactness violation of the
F697 closure's own contract.

Prints BREAK when the over-decode reproduces (open tree), HELD when
the shape fails closed.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("f738-s1",
     "(function(){var o={[Symbol.toPrimitive]:'x',"
     "toString:function(){return '%s';}};return o+'%s';})()" % (_A, _B), True),
    ("f738-s2",
     "(function(){var o={[Symbol.toPrimitive]:'x',"
     "valueOf:function(){return '%s';}};return o+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("plain-concat-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\' ;return s;})()'", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, overdecodes in SHAPES:
        hit = find_credential(payload) is not None
        # BREAK = the over-decode reproduces (decoder blocks a throwing shape)
        is_break = overdecodes and hit
        print("%s: %s" % (name, "BREAK(over-decodes)" if is_break else "HELD(fail-closed)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
