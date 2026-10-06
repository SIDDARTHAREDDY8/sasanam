#!/usr/bin/env python3
"""Red-first for F471: Object.assign([], [...]) array-copy factory bypasses
the bounded static JS-expression decoder.

Object.assign([],['frag1','frag2']).join('') node-evaluates to the
credential (node v24.20.0 verified): Object.assign copies the fragment
array into a fresh array, which join('') then assembles. The same
mechanism covers the spread-copy form [...['frag1','frag2']].join(''),
also node-verified to the credential and also missed. The decoder models
no array-copy factory at all. Distinct from F466 (unmodeled no-op chain
steps on an existing array -- slice/flat/splice) and from F468
(reflection-API construction): this is a copy factory, not a chain step
and not reflection. The plain credential blocks coded.

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Controls: plain credential blocks coded; junk variants quiet.
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
    ("object-assign-copy",
     "Object.assign([],['%s','%s']).join('')" % (A1, A2), True),
    ("spread-copy",
     "[...['%s','%s']].join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet-assign",
     "Object.assign([],['ab','cd']).join('')", False),
    ("junk-quiet-spread",
     "[...['ab','cd']].join('')", False),
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
