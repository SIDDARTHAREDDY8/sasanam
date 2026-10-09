#!/usr/bin/env python3
"""Red-first for F795: optional-chaining direct method calls.

The decoder models `.method(args)` on array/string receivers but the
`?.method(args)` form resolves to a _JSMethodRef whose direct-call step
is never dispatched to the method grammar: every modeled method is
bypassable via `?.` (the receiver is provably non-null, so `?.` is
engine-identical to `.` -- node v24.20.0).
Filed 2026-10-09 03:26:22 UTC wave-385 lane 3.
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
     "['" + _A + "','" + _B + "']?.join('')",
     True),
    ("s2",
     "[['" + _A + "'],['xx']]?.find(function(a){return true;})[0][0]+'" + _B + "'",
     True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("dot-join-blocks",
     "['" + _A + "','" + _B + "'].join('')",
     True),  # control: the dot form blocks coded
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
        held += 1 if ok else 0
        breaks += 0 if ok else 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
