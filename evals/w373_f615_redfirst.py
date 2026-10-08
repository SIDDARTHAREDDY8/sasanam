#!/usr/bin/env python3
"""Red-first for F615: Map.values() spread into call arguments.

F608 (OPEN, wave-373 lane 4 closing it) covers Set spread into call
arguments, but the spread SOURCE production matters: spreading
Map.values() -- a different iterable source per the F500/F505 precedent --
has no modeled path: the three shapes below all node-evaluate to the exact
credential (v24.20.0) while the decoder produces zero variants. Distinct
from F608 (Set spread sources; F608's filed shapes and close-when are
Set-specific).
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

SRC = "new Map([['a','" + A1 + "'],['b','" + A2 + "']]).values()"

SHAPES = [
    ("mapvals-spread-rest",
     "((...a)=>a.join(''))(..." + SRC + ")", True),
    ("mapvals-spread-fixed",
     "((a,b)=>a+b)(..." + SRC + ")", True),
    ("mapvals-spread-call",
     "((a,b)=>a+b).call(null,..." + SRC + ")", True),
]

CONTROLS = [
    ("mapvals-array-spread-blocked",
     "[..." + SRC + "].join('')", True),
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
