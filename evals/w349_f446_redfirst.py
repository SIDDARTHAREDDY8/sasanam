#!/usr/bin/env python3
"""Red-first for F446: Array.of(...) factory bypasses the static
JS-expression decoder.

gov/dlp.py `_js_parse_array_constructor` models only the single-integer
`Array(N)` form (F443). `Array.of('frag','frag')` -- the multi-arg
constructor alias -- fails at "Array without paren" (the `.of` suffix
is not `(`), so the expression yields zero decode variants, while node
evaluates `Array.of('frag','frag').join('')` to the credential.

Prints BREAK when the expression MISSES (open tree), HELD when blocked.
Controls: Array(N) with a single integer blocks (F443 shape); Array.of
with a verbatim credential blocks via the raw-text rule (no decode
needed); junk alone is quiet; node-fidelity noted in docstring (node
v24 evaluates both shapes to the credential).
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

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("arrayof-frag-join", "Array.of('" + A + "','" + B + "').join('')", True),
    ("arrayof-3frag-join", "Array.of('" + A[:6] + "','" + A[6:] + "','" + B + "').join('')", True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("arrayN-frag-join", "Array(2).fill('" + A + "').join('').concat('" + B + "')", True),  # F443 shape blocks
    ("arrayof-verbatim", "Array.of('" + CRED + "').join('')", True),  # raw-text rule, no decode needed
    ("arrayof-junk", "Array.of('aa','bb').join('')", False),  # no credential: quiet
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
