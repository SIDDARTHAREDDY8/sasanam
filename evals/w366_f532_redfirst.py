#!/usr/bin/env python3
"""Red-first for F532: quadruple-nested bracket member key on ARRAY receivers.

F532 CLOSED 2026-10-07 wave-366 merge (honest F527 generalization, F514 precedent):
the F527 key fold is receiver-agnostic, so both shapes now block. This battery
asserts the closure (shapes HELD).

F527 models quadruple-nested bracket member keys on STRING receivers
('f1'[[[[['concat'][0]]][0]][0]]). An ARRAY receiver (['f1']) is a
different receiver class: Array.prototype.concat exists, so
['f1'][[[[['concat'][0]]][0]][0]]('f2') node-evaluates (v24.20.0) to
['f1','f2'] while the decoder produces zero variants. Distinct from F527
(string receivers) by the same receiver-class argument F514 used against
F507. Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
    ("quad-array-literal",
     "['%(A1)s'][[[[['concat'][0]]][0]][0]]('%(A2)s').join('')"
     % {"A1": A1, "A2": A2}, True),
    ("quad-array-ctor",
     "new Array('%(A1)s')[[[[['concat'][0]]][0]][0]]('%(A2)s').join('')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f527-string-quad-closed",  # F527 CLOSED wave-366 lane 2 -- now blocks
     "'%(A1)s'[[[[['concat'][0]]][0]][0]]('%(A2)s')" % {"A1": A1, "A2": A2}, True),
    ("direct-array-concat-held",
     "['%s'].concat('%s').join('')" % (A1, A2), True),
    ("junk-quiet",
     "['ab'][[[[['concat'][0]]][0]][0]]('cd').join('')", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        # F532 CLOSED: shapes must now be HELD (blocked)
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        # f527-string-quad-closed expects a HIT (want_hit=True since wave-366 lane 2)
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
