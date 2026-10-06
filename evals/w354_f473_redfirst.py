#!/usr/bin/env python3
"""Red-first for F473: array-receiver paren .concat bypasses the bounded
static JS-expression decoder.

['frag1'].concat(['frag2']).join(''), [].concat(...['frag1'],...['frag2'])
.join(''), ['frag1','frag2'].concat([]).join(''),
Array(1).fill('frag1').concat('frag2').join('') and
Array(1).fill('frag1').concat(...['frag2']).join('') all node-evaluate to
the credential, but the decoder's paren-concat branch fails closed on
_JSArr receivers ("method on unjoined array") -- a deliberate boundary
that real engines do not share. Distinct from F462 (string-receiver
spread concat, closed wave-353): this is the ARRAY-receiver class.

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Controls: plain credential blocks coded; junk variant quiet; the F462
string-receiver spread shape blocks (closure holds).
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
    ("litarr-concat-litarr",
     "['%s'].concat(['%s']).join('')" % (A1, A2), True),
    ("empty-concat-spread",
     "[].concat(...['%s'],...['%s']).join('')" % (A1, A2), True),
    ("litarr-concat-empty",
     "['%s','%s'].concat([]).join('')" % (A1, A2), True),
    ("fill-concat-strarg",
     "Array(1).fill('%s').concat('%s').join('')" % (A1, A2), True),
    ("fill-concat-spreadarg",
     "Array(1).fill('%s').concat(...['%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab'].concat(['cd']).join('')", False),
    ("neighbor-f462-closed", "''.concat(...['%s','%s'])" % (A1, A2), True),
    ("neighbor-join", "['%s','%s'].join('')" % (A1, A2), True),
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
