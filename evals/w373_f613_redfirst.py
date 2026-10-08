#!/usr/bin/env python3
"""Red-first for F613: String.raw tag template in non-leading positions.

F463 (wave-353 lane 2, CLOSED) models the String.raw TAG form in the leading
primary position (`String.raw`f1`+'f2'` blocks coded) and the substitution
form (`String.raw`${'f1'}${'f2'}` blocks coded); F493/F551/F575 (CLOSED)
cover the call forms. But the tag parser only fires in the leading-primary
position: the three shapes below all node-evaluate to the exact credential
(v24.20.0) while the decoder produces zero variants. Distinct from F463
(leading/substitution tag forms, CLOSED) and F493/F551/F575 (call forms).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ("rawtag-rhs-of-plus",
     "'" + A1 + "'+String.raw`" + A2 + "`", True),
    ("rawtag-parenthesized",
     "(String.raw`" + A1 + "`)+'" + A2 + "'", True),
    ("rawtag-array-join",
     "[String.raw`" + A1 + "`,String.raw`" + A2 + "`].join('')", True),
]

CONTROLS = [
    ("rawtag-leading-blocked",
     "String.raw`" + A1 + "`+'" + A2 + "'", True),
    ("rawtag-substitution-blocked",
     "String.raw`${'" + A1 + "'}${'" + A2 + "'}`", True),
    ("junk-quiet",
     "\"(function(){var s='ab';return s;})()\"", False),
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
