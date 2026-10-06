#!/usr/bin/env python3
"""Red-first for F443: JS higher-order array/string assembly primitives evade
the F430/F434 JS-expression decoder.

find_credential decodes quoted '+' concat, String.fromCharCode, .concat(),
.repeat(), and array-literal .join() -- but higher-order assembly shapes
evaluate to the credential in a real JS engine while missing the decoder:
  .map(s=>s).join("")      (higher-order pass-through)
  .filter(Boolean).join("") (falsy-filter assembly)
  Array(N).fill(frag).join(sep).concat(rest) (constructor assembly)

Prints BREAK when the shapes MISS (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-" + "abc" + "123"
B = "def" + "456"
CRED = A + B

SHAPES = [
    ('map-join', '["' + A + '","' + B + '"].map(s=>s).join("")'),
    ('filter-join', '["' + A + '","","' + B + '"].filter(Boolean).join("")'),
    ('fill-join-concat',
     'Array(2).fill("' + "xox" + "b-" + "abc" + '").join("123").concat("' + B + '")'),
    ('fill-join', 'Array(1).fill("' + A + '").join("' + B + '")'),
]

CONTROLS = [
    ('plain-credential', CRED, True),   # must block
    ('honest-array', '["red","green","blue"].map(s=>s).join(", ")', False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print("%s: %s" % (name, "HELD(blocks)" if hit else "BREAK(miss)"))
        if hit:
            held += 1
        else:
            breaks += 1
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
