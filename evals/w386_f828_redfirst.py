#!/usr/bin/env python3
"""Red-first for F828: empty-class prototype method reads (closure check).

F828 was filed 2026-10-09 03:43:50 UTC by wave-385 lane 10 (spec-axis
review HARD finding on the F781 closure note; renumbered F796->F828 at the
wave-385 merge; wave-272 rule) and CLOSED in the same wave by adding the
empty-class branch to the F781 statement loop (mirroring the F780 class
branch). This red-first verifies the closure HOLDS on the merged tree:
all shapes must block (0 BREAK). Node ground truth v24.20.0.
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
     "(function(){class C{}C.prototype.m=function(){return '%s';};return new C().m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){class C{}C.prototype['m']=function(){return '%s';};var o=new C();return o['m']()+'%s';})()" % (_A, _B),
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
    for name, payload, recovers in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == recovers
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
