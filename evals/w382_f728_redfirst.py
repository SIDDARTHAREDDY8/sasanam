#!/usr/bin/env python3
"""Red-first for F728: generator .next().value member reads

The decoder models generator yield bodies (F494/F619/F656) but not .next().value member reads on the iterator: the yielded fragment is read directly while the decoder produces zero variants. Distinct from F656 (sequenced .next() reads inside IIFEs).
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
    ("f728-s1",
     "(function(){function* g(){yield '%s';}var it=g();return it.next().value+'%s';})()" % (_A, _B), True),
    ("f728-s2",
     "(function(){function* g(){yield '%s';yield '%s';}var it=g();return it.next().value+it.next().value;})()" % (_A, _B), True),
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
