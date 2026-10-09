#!/usr/bin/env python3
"""Red-first for F888: whitespace between `.` and the method name in the
native postfix chain.

_js_parse_postfix does not skip whitespace between the dot and the
method name, so `a. flat()` (ordinary engine-tolerated whitespace) has
no production anywhere in the decoder. Distinct from F802 (CLOSED -- the
no-space twin blocks coded; this gap is in the shared postfix chain,
not the F802 parser).
Filed 2026-10-09 05:40:54 UTC wave-386 lane 4 (spec-review hard finding
on the F802 closure).
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
    ("s1",
     "(function(){var a=[['%s'],['%s']];return a. flat().join('');})()" % (_A, _B),
     True),
    ("s2",
     "[['%s'],['%s']]. flat().join('')" % (_A, _B),
     True),
]

CONTROLS = [
    # no-space twin blocks coded (F802 CLOSED).
    ("nospace-twin-blocks",
     "(function(){var a=[['%s'],['%s']];return a.flat().join('');})()" % (_A, _B),
     True),
    # tab whitespace twin is engine-identical to the space.
    ("tab-ws",
     "(function(){var a=[['%s'],['%s']];return a.\tflat().join('');})()" % (_A, _B),
     True),
    # method-name prefix confusion stays fail-closed: `. flatx(` is not
    # a modeled method.
    ("unknown-method-fails-closed",
     "(function(){var a=[['%s'],['%s']];return a. flatx().join('');})()" % (_A, _B),
     False),
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
