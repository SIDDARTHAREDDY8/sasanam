#!/usr/bin/env python3
"""Red-first for F466: an unmodeled no-op chain step (.slice) bypasses the bounded static JS-expression decoder.

['frag1','frag2'].slice(0,2).join('') node-evaluates to the credential: slice(0,2) is a no-op on the two-element fragment array. The decoder's chain grammar knows no .slice step, so the whole chain fails closed with zero decode variants, while the plain credential blocks coded. Distinct from F448 (callback body shapes): a missing chain-grammar step, not a callback.

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
    ("slice-noop", "['%s','%s'].slice(0,2).join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab','cd'].slice(0,2).join('')", False),
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
