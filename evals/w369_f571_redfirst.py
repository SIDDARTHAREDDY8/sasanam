#!/usr/bin/env python3
"""Red-first for 571: JSON.stringify round-trip laundering.

F541 (CLOSED) models JSON.parse of string literals, but not the round-trip: JSON.parse(JSON.stringify(X)) rebuilds the credential-bearing value from a call result the decoder never interprets. Both the object form and the plain-string form node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. F481-class composition gap of the F541 closure.
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
    ('json-obj-rt',
     "JSON.parse(JSON.stringify({c:'%(A1)s'})).c+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
    ('json-str-rt',
     "JSON.parse(JSON.stringify('%(A1)s'))+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f541-closed',
     'JSON.parse(\'{"c":"%(A1)s"}\').c+\'%(A2)s\''
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "JSON.parse(JSON.stringify({c:'zz'})).c+'yy'"
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
