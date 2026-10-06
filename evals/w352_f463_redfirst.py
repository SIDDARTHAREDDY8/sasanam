#!/usr/bin/env python3
"""Red-first for F463: calling join as a tagged template bypasses the bounded static JS-expression decoder.

['frag1','frag2'].join`` `` (join invoked as a tag with an empty template) node-evaluates to the credential: the template-strings array [''] becomes the separator. The decoder never models tag-call syntax, so the shape fails closed with zero decode variants, while the plain credential blocks coded.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: plain credential blocks coded; junk variant quiet; the
neighboring closed shape blocks.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"
C1 = "xoxb-" + "012345678"
C2 = "89abcdef"
BT = chr(96)  # backtick

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("tagged-template-join", "['%s','%s'].join%s%s" % (A1, A2, BT, BT), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab','cd'].join%s%s" % (BT, BT), False),
    ("neighbor-blocks", "['%s','%s'].join('')" % (A1, A2), True),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
