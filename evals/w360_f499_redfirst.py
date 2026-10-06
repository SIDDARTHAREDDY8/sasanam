#!/usr/bin/env python3
"""Red-first for F499: spread of string literals in array literals. The F471
closure ("iterable-spread of strings -- documented candidate residual")
models [...['f1','f2']] (spread of an array literal) but fails closed on
spread of a STRING literal: [...'f1'] iterates the string's characters, and
node assembles the credential. All shapes node-evaluate (v24.20.0) to the
exact credential while the decoder produces zero variants. Distinct from F471
(array-literal spread, closed) and F494 (non-literal iterables -- here the
operand IS a literal, so F494's fail-closed close-when would not cover it).
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
    ("string-spread-two",
     "[...'%s', ...'%s'].join('')" % (A1, A2), True),
    ("string-spread-wrapped",
     "String([...'%s', ...'%s'].join(''))" % (A1, A2), True),
    ("string-spread-concat",
     "[...'%s'].join('') + [...'%s'].join('')" % (A1, A2), True),
]

CONTROLS = [
    ("array-spread-held",
     "[...['%s','%s']].join('')" % (A1, A2), True),  # F471 closed
    ("junk-quiet",
     "[...'ab', ...'cd'].join('')", False),
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
