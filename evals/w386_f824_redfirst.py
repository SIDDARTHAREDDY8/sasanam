#!/usr/bin/env python3
"""Red-first for F824: non-integer Iterator.prototype.drop arguments.

F793 (CLOSED wave-385 lane 16) models `.drop(n)` for non-negative
integer literals only. Node (v24.20.0) applies ToNumber then
ToIntegerOrInfinity to the argument: `drop(1.5)` truncates to 1 and
`drop("1")` coerces to 1, so both filed shapes node-evaluate to the
exact credential while the decoder produces zero variants
(fail-closed miss). Node also throws RangeError when !(n >= 0)
(negatives AND NaN) -- those fail closed on both sides, correctly.
Filed 2026-10-09 03:37:08 UTC, wave-385 lane 16 (spec-review residual
of the F793 closure); renumbered F795->F824 at the wave-385 merge
(wave-272 rule: attack round 53 filed F795 first).
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
    ("s1-float",
     "(function(){return [...['xx','%s','%s'].values().drop(1.5)]"
     ".join('');})()" % (_A, _B),
     True),
    ("s2-string",
     "(function(){return [...['xx','%s','%s'].values().drop(\"1\")]"
     ".join('');})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\\\\\'ab\\\\\\\\';return s;})()'", False),
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
