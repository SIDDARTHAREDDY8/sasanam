#!/usr/bin/env python3
"""Red-first for F454: the multi-argument Array constructor bypasses the
bounded static JS-expression decoder.

gov/dlp.py `_js_parse_array_constructor` models only the single-integer
`Array(N)` form (F443); `Array.of(...)` was added by F446. But
`Array('frag','frag')` / `new Array('frag','frag')` -- the multi-argument
constructor, which node evaluates to the fragment list (node-verified) --
fails closed ("bad Array args") and yields zero decode variants, while the
plain credential blocks coded. The F446 close-when promised "Array.of (and
the other Array factory forms the decoder claims no model of) decode within
the same budgets" -- the multi-arg constructor is such a form and does not
decode. Distinct from F446 (Array.of factory): different syntactic form,
different parser branch.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: Array(N) frag-join-concat blocks (F443 shape); Array.of blocks
(F446 shape); junk multi-arg Array quiet; plain credential blocks coded.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "4567" + "89abcdef"

SHAPES = [
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("array-multi", "Array('%s','%s').join('')" % (A1, A2), True),
    ("new-array-multi", "new Array('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("array-n-fill", "Array(2).fill('x').join('')", False),  # junk: quiet
    ("array-multi-junk", "Array('ab','cd').join('')", False),  # junk: quiet
    ("plain-credential", A1 + A2, True),
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
