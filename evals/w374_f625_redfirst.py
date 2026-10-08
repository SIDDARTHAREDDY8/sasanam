#!/usr/bin/env python3
"""Red-first for F625: Map entries()/keys() spread into call arguments.

F615 (OPEN) covers Map.values() spread into call args, but the spread SOURCE production matters per the F500/F505 precedent: entries() and keys() are different iterable sources with no modeled path.
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
    ('entries-spread',
     "((...a)=>a.map(e=>e[1]).join(''))(...new Map([['a','%(A1)s'],['b','%(A2)s']]).entries())"
     % {"A1": A1, "A2": A2}, True),
    ('entries-fixed',
     "((a,b)=>a[1]+b[1])(...new Map([['a','%(A1)s'],['b','%(A2)s']]).entries())"
     % {"A1": A1, "A2": A2}, True),
    ('keys-spread',
     "((...a)=>a.join(''))(...new Map([['%(A1)s','x'],['%(A2)s','y']]).keys())"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f608-blocks',
     "((...a)=>a.join(''))(...new Set(['%(A1)s','%(A2)s']))"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
