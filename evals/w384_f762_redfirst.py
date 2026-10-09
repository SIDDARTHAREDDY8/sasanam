#!/usr/bin/env python3
"""Red-first for F762: non-string primitive Symbol.toPrimitive returns not modeled.

The decoder's ToPrimitive coercion (shared _js_f697_toprimitive, used by
F697's literal form and F743's assigned form) fails closed when the
coercion body resolves to a non-string: but node v24.20.0 String()-coerces
number/boolean returns (only Object returns throw TypeError), so a
numeric-returning toPrimitive launders credential fragments while the
decoder produces zero variants.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
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
    ("s1", "(function(){var o={};o[Symbol.toPrimitive]=function(){return 120;};return String.fromCharCode(o)+'xb-0123'+'§B';})()".replace("§B", _B), True),
    ("s2", "(function(){var o={[Symbol.toPrimitive]:function(){return 111;}};return String.fromCharCode(o)+'xb-0123'+'§B';})()".replace("§B", _B), True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
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
