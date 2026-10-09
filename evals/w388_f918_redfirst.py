#!/usr/bin/env python3
"""Red-first for F918: comments between `.` and the native postfix method name.

F888 (CLOSED, wave-387 lane 15) covers WHITESPACE between `.` and the method
name (`a. flat()`), matching _js_skip_ws's " \\t\\n\\r" coverage, but a JS
comment in the same position (`a./*x*/flat()`) is engine-valid
(node v24.20.0: token-identical to `a.flat()`) while _js_parse_postfix does
not skip it, so the laundering shape resolves node-exactly while the decoder
produces zero variants.
Filed wave-387 lane 15 (Spec-review residual of the F888 work; node v24.20.0).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
    ("block-comment-iife",
     "(function(){var a=[['%s'],['%s']];return a./*x*/flat().join('');})()" % (_A, _B),
     True),
    ("block-comment-bare",
     "[['%s'],['%s']]./*x*/flat().join('')" % (_A, _B),
     True),
]

CONTROLS = [
    # whitespace twin blocks coded (F888)
    ("whitespace-twin",
     "(function(){var a=[['%s'],['%s']];return a. flat().join('');})()" % (_A, _B),
     True),
    # no-space twin blocks coded
    ("nospace-twin",
     "(function(){var a=[['%s'],['%s']];return a.flat().join('');})()" % (_A, _B),
     True),
    # junk-quiet control: no credential at all
    ("junk-quiet",
     "(function(){var a=[['ab'],['cd']];return a./*x*/flat().join('');})()",
     False),
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
