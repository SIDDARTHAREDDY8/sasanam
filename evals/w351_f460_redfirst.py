#!/usr/bin/env python3
"""Red-first for F460: `.map(String)` -- the string-coercion idiom -- bypasses
the bounded static JS-expression decoder's map handling.

F437/F448 model the identity map (`x=>x`, `x=>{return x;}`,
`function(x){return x;}`). But `.map(String)` -- passing the String
constructor as the callback, the standard string-coercion idiom --
evaluates to the identity over string fragments in node (node-verified:
`['a','b'].map(String)` is `['a','b']`) and yields zero decode variants.
Distinct from F448 (block-body identity): the mechanism is a non-identity
function reference as the callback, not a callback body shape.
Model-proposed (gpt-4o-mini round-19 B5 join-form proposals validated
locally).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: identity map blocks (F437 shape); junk String-map quiet; plain
credential blocks coded.
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
    ("map-string", "['%s','%s'].map(String).join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("map-identity", "['%s','%s'].map(x=>x).join('')" % (A1, A2), True),
    ("map-string-junk", "['ab','cd'].map(String).join('')", False),
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
