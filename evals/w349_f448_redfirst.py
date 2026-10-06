#!/usr/bin/env python3
"""Red-first for F448: .map with a block-body identity callback bypasses
the identity-map passthrough.

gov/dlp.py models the identity `.map` passthrough for the concise arrow
`x=>x` and the function form `function(x){return x;}` (F437), but not
the block-body arrow `x=>{return x;}` -- node-verified to be exactly the
identity map. So `['frag','frag'].map(x=>{return x;}).join('')`
evaluates to the credential in node but yields no decode variant.

Prints BREAK when the expression MISSES (open tree), HELD when blocked.
Controls: concise `x=>x` blocks (F437 shape); function-form blocks;
verbatim credential blocks via the raw-text rule; junk map is quiet.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-abc123"
B = "def" + "456"
CRED = A + B
ARR = "['" + A + "','" + B + "']"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("map-blockbody-identity", ARR + ".map(x=>{return x;}).join('')", True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("map-concise-identity", ARR + ".map(x=>x).join('')", True),  # F437 shape blocks
    ("map-function-identity", ARR + ".map(function(x){return x;}).join('')", True),  # F437 shape blocks
    ("map-blockbody-junk", "['aa','bb'].map(x=>{return x;}).join('')", False),  # no credential: quiet
    ("plain-credential", CRED, True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        # BREAK = genuine miss: real engine recovers, scanner misses.
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
