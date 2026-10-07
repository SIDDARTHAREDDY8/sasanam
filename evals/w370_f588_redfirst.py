#!/usr/bin/env python3
"""Red-first for 588: Reflect.get with Symbol.for keys.

F540 closed Reflect.get on literals with string-literal keys and F552 closed Symbol.for member reads, but their composition misses: Reflect.get({[Symbol.for('c')]:'f1'},Symbol.for('c'))+'f2' node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F540 (string keys) and F552 (member-read position).
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
    ('reflectget-sym',
     '"Reflect.get({[Symbol.for(\'c\')]:\'%(A1)s\'},Symbol.for(\'c\'))+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('reflectget-sym-nest',
     '"Reflect.get({[Symbol.for(\'k\')]:{c:\'%(A1)s\'}},Symbol.for(\'k\')).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('reflectget-str-blocked',
     '"Reflect.get({c:\'%(A1)s\'},\'c\')+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"Reflect.get({c:\'ab\'},\'c\')"'
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
