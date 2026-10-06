#!/usr/bin/env python3
"""Red-first for F465: .padStart credential assembly bypasses the bounded static JS-expression decoder.

'89abcdef'.padStart(21,'xoxb-012345678') node-evaluates to the 21-char credential: the pad string fills the left. The decoder models no padding primitive, so the shape fails closed with zero decode variants, while the plain credential blocks coded. Note: the round-19 shape 'b'.padStart(20,'a...') tripped the plain slack seam on this credential (its pad string matched xoxb-[A-Za-z0-9-]{10,}); this red-first uses the fragment-split form where neither literal matches the rule, so the MISS is the decoder's, not the seam's.

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

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("padstart", "'%s'.padStart(21,'%s')" % (C2, C1), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "'89abcd'.padStart(21,'xoxb-012345678')", False),
    ("neighbor-blocks", A1 + A2, True),
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
