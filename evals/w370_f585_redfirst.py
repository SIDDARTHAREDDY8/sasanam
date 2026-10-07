#!/usr/bin/env python3
"""Red-first for 585: structuredClone of Map objects.

F536 closed structuredClone laundering for plain objects/arrays, but a cloned Map is still a Map: structuredClone(new Map([['c','f1']])).get('c')+'f2' node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F536 (plain values) and F563 (Map.get on literals).
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
    ('sclone-map',
     '"structuredClone(new Map([[\'c\',\'%(A1)s\']])).get(\'c\')+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('sclone-map2',
     '"structuredClone(new Map([[\'a\',\'%(A1)s\'],[\'b\',\'%(A2)s\']])).get(\'a\')+structuredClone(new Map([[\'a\',\'%(A1)s\'],[\'b\',\'%(A2)s\']])).get(\'b\')"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('sclone-plain-blocked',
     '"structuredClone({c:\'%(A1)s\'}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"structuredClone(new Map([[\'c\',\'ab\']])).get(\'c\')"'
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
