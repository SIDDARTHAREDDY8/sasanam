#!/usr/bin/env python3
"""Red-first for F628: decodeURIComponent fragment laundering.

F576 (CLOSED) models the full-credential roundtrip decodeURIComponent(encodeURIComponent('f1f2')) as a control, but FRAGMENT forms -- encoding one fragment and concatenating around the decode -- escape: the F611 fragment precedent (filed against F445's full-credential base64 gate) applies.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ('decode-fragment',
     "decodeURIComponent('%(A1)s'+encodeURIComponent('%(A2)s'))"
     % {"A1": A1, "A2": A2}, True),
    ('decode-split',
     "decodeURIComponent(encodeURIComponent('%(A1)s')+encodeURIComponent('%(A2)s'))"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f576-control-blocks',
     "decodeURIComponent(encodeURIComponent('%(A1)s%(A2)s'))"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
