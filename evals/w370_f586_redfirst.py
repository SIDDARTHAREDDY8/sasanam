#!/usr/bin/env python3
"""Red-first for 586: parenthesized new-expression receivers.

The decoder models `new Map(...)` and `new WeakRef(...)` receivers only in the UNPARENTHESIZED spelling: (new Map([['c','f1']])).get('c')+'f2' and (new WeakRef({c:'f1'})).deref().c+'f2' node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F563/F539 (unparen spellings, CLOSED).
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
    ('map-paren',
     '"(new Map([[\'c\',\'%(A1)s\']])).get(\'c\')+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('weakref-paren',
     '"(new WeakRef({c:\'%(A1)s\'})).deref().c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('map-unparen-blocked',
     '"new Map([[\'c\',\'%(A1)s\']]).get(\'c\')+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('weakref-unparen-blocked',
     '"new WeakRef({c:\'%(A1)s\'}).deref().c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(new Map([[\'c\',\'ab\']])).get(\'c\')"'
     % {"A1": A1, "A2": A2}, False)
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
