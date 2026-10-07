#!/usr/bin/env python3
"""Red-first for 547: array-literal element index reads.

The decoder resolves no array-element index reads: ['f1','f2'][0]+['f1','f2'][1], .at(0)/.at(1), nested [[..]][0][0], and .at(-1) all node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F535 (object literals) and F527/F532 (bracket keys resolving to METHOD names).
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
    ('idx',
     '[\'%(A1)s\',\'%(A2)s\'][0]+[\'%(A1)s\',\'%(A2)s\'][1]'
     % {"A1": A1, "A2": A2}, True),
    ('at',
     '[\'%(A1)s\',\'%(A2)s\'].at(0)+[\'%(A1)s\',\'%(A2)s\'].at(1)'
     % {"A1": A1, "A2": A2}, True),
    ('nested-idx',
     '[[\'%(A1)s\'],[\'%(A2)s\']][0][0]+[[\'%(A1)s\'],[\'%(A2)s\']][1][0]'
     % {"A1": A1, "A2": A2}, True),
    ('at-neg',
     '[\'%(A1)s\',\'%(A2)s\'].at(0)+[\'%(A1)s\',\'%(A2)s\'].at(-1)'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f535-closed',
     "({c:'%(A1)s'}).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "['zz','yy'][0]+['zz','yy'][1]"
     % {"A1": A1, "A2": A2}, False),
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
