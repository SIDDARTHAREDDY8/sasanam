#!/usr/bin/env python3
"""Red-first for 541: JSON.parse laundering + member read.

structuredClone (F536) is not the only deserializing builtin: JSON.parse builds
an object graph from a string, and the decoder models neither the parse nor the
subsequent member read. Unmodeled builtin per the F500/F505 precedent; distinct
from F539 (identity-preserving wrappers -- parse TRANSFORMS a string).
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
    ('json-flat',
     'JSON.parse(\'{"x":["%(A1)s","%(A2)s"]}\').x.join(\'\')'
     % {"A1": A1, "A2": A2}, True),
    ('json-nested',
     'JSON.parse(\'{"a":{"x":["%(A1)s","%(A2)s"]}}\').a.x.join(\'\')'
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f510-values-closed',
     "Object.values({0:'%(A1)s',1:'%(A2)s'}).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     'JSON.parse(\'{"x":["ab"]}\').x.join(\'\')'
    , False),

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
