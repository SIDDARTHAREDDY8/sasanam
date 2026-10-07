#!/usr/bin/env python3
"""Red-first for 564: String.split laundering.

The decoder models match/replace (validated HELD this round) but not split: 'f1,f2'.split(',').join(''), the ';' variant, and the limit form all node-evaluate to the exact credential (v24.20.0) with zero decoder variants. Distinct per builtin semantics (split yields arrays).
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
    ('comma',
     '\'%(A1)s,%(A2)s\'.split(\',\').join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('semi',
     '\'%(A1)s;%(A2)s\'.split(\';\').join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('limit',
     '\'%(A1)s,%(A2)s\'.split(\',\',2).join(\'\')'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('match-held',
     "'--%(A1)s--%(A2)s--'.match(/--(.*)--(.*)--/).slice(1).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "'zz,yy'.split(',').join('')"
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
