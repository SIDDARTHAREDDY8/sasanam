#!/usr/bin/env python3
"""Red-first for F459: positional/index `.filter` predicates bypass the
bounded static JS-expression decoder.

F447 closed truthiness-preserving `.filter` predicates (`x=>x!==''`,
`x=>!!x`, `x=>x.length>0`, bare `x=>x`, ...). But positional predicates --
`(x,i)=>i<2`, `(x,i)=>i!==2` -- select elements by INDEX, not truthiness: a
different predicate class the F447 close-when ("truthy-preserving filter
predicates decode") does not cover. `['p','q','zz'].filter((x,i)=>i<2)`
evaluates to `['p','q']` in node (node-verified) and yields zero decode
variants in the static decoder. Distinct from F447 (truthiness class) and
from the F447 documented residuals (loose !=, length variants, block
bodies): the mechanism is index comparison, not a truthiness test.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: truthiness filter blocks (F447 shape); junk positional filter
quiet; plain credential blocks coded.
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
    ("filter-idx-lt", "['%s','%s','zz'].filter((x,i)=>i<2).join('')"
     % (A1, A2), True),
    ("filter-idx-ne", "['%s','%s','zz'].filter((x,i)=>i!==2).join('')"
     % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("filter-truthy", "['%s','%s',''].filter(x=>x!=='').join('')"
     % (A1, A2), True),  # F447 shape
    ("filter-idx-junk", "['ab','cd','ef'].filter((x,i)=>i<2).join('')",
     False),
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
