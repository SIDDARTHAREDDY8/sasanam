#!/usr/bin/env python3
"""Red-first for F725: __lookupGetter__ legacy API reads

The decoder has no __lookupGetter__ production: retrieving the getter function and invoking it recovers the fragment while the decoder produces zero variants. Read-side twin of F703 (__defineGetter__, filed round 49).
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
    ("f725-s1",
     "(function(){var o={get x(){return '%s';}};var g=o.__lookupGetter__('x');return g.call(o)+'%s';})()" % (_A, _B), True),
    ("f725-s2",
     "(function(){var o={};o.__defineGetter__('y',function(){return '%s';});return o.__lookupGetter__('y').call(o)+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("plain-concat-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
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
