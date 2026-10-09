#!/usr/bin/env python3
"""Red-first for F820: Array copyWithin/reverse reads.

The decoder has no copyWithin/reverse statement production: both
resolve node-exactly while the decoder produces zero variants
(splice is F767, fill is F773/F681).

CORRECTION (2026-10-09, wave-386 lane 13): the attack lane's filed
s2 shape `var a=['xoxb-0123','456789abcdef'];a.reverse()` does NOT
recover the credential at runtime -- node v24.20.0 yields
'456789abcdefxoxb-0123', which contains no contiguous credential.
The fragments must be ordered so reverse()+join recovers:
`var a=['456789abcdef','xoxb-0123']`. This red-first uses the
node-verified credential-recovering shape; the F820 finding
itself (no reverse/copyWithin statement production) is genuine.

Filed 2026-10-09 03:25 UTC wave-385 attack round 53; shape
corrected 2026-10-09 wave-386 lane 13 (node-verified).
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
    ("s1-copywithin",
     "(function(){var a=['%s','z','%s'];a.copyWithin(1,0,1);return a[0]+a[2];})()" % (_A, _B),
     True),
    ("s2-reverse",
     "(function(){var a=['%s','%s'];a.reverse();return a.join('');})()" % (_B, _A),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
