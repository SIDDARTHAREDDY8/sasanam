#!/usr/bin/env python3
"""Red-first for 572: WeakMap.get reads.

The decoder models no WeakMap semantics: a persistent object key threads the credential through set/get while the decoder sees only opaque calls. Both the pair-list constructor form and the set-chain form node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F563 (Map.get) and F549 (getOwnPropertyDescriptor); F500/F505 precedent (unmodeled builtins).
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
    ('weakmap-pairs',
     "(function(){var k={};var m=new WeakMap([[k,'%(A1)s']]);return m.get(k);})()+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ('weakmap-setchain',
     "(function(){var k={};return new WeakMap().set(k,'%(A1)s').get(k);})()+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f563-open-still-misses',
     "new Map([['c','%(A1)s']]).get('c')+'%(A2)s'"
     % {"A1": A1, "A2": A2}, False),
    ('junk-quiet',
     "(function(){var k={};return new WeakMap().set(k,'zz').get(k);})()+'yy'"
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
