#!/usr/bin/env python3
"""Red-first for F875: getOwnPropertyNames/key iteration.

The decoder models `for-in` but not key-list mapping: `Object.getOwnPropertyNames(o).map(k=>o[k])`
and the `Object.keys` twin resolve node-exactly while the decoder produces zero variants.
Close-when: the decoder models key-list iteration node-exactly (or refuses the laundering
coded) such that find_credential flags them, red-first verified, honest text unaffected.
Filed 2026-10-09 05:30 UTC wave-386 (attack round 54).
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
    ("s1-getOwnPropertyNames",
     "(function(){var o={k:'%s'};return Object.getOwnPropertyNames(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B),
     True),
    ("s2-ObjKeys",
     "(function(){var o={k:'%s'};return Object.keys(o).map(function(k){return o[k];})[0]+'%s';})()" % (_A, _B),
     True),
    ("s3-arrow",
     "(function(){var o={k:'%s'};return Object.keys(o).map(k=>o[k])[0]+'%s';})()" % (_A, _B),
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
