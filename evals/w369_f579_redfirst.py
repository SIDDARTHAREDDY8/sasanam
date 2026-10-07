#!/usr/bin/env python3
"""Red-first for 579: Reflect.ownKeys terminal index reads.

ownKeys returns the key LIST -- indexing it and reading back through the literal composes a credential the decoder cannot thread: ({c:'f1',d:'f2'})[Reflect.ownKeys(...)[0]]+...[1] node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F549 (getOwnPropertyDescriptor, OPEN -- different builtin, returns descriptors not keys).
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
    ('ownkeys-2key',
     "({c:'%(A1)s',d:'%(A2)s'})[Reflect.ownKeys({c:'%(A1)s',d:'%(A2)s'})[0]]+({c:'%(A1)s',d:'%(A2)s'})[Reflect.ownKeys({c:'%(A1)s',d:'%(A2)s'})[1]]"
     % {"A1": A1, "A2": A2}, True),
    ('ownkeys-nested',
     "({x:{y:'%(A1)s'}})[Reflect.ownKeys({x:0})[0]].y+'%(A2)s'"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f549-open-still-misses',
     "Object.getOwnPropertyDescriptor({c:'%(A1)s'},'c').value+'%(A2)s'"
     % {"A1": A1, "A2": A2}, False),
    ('junk-quiet',
     "({c:'zz'})[Reflect.ownKeys({c:'zz'})[0]]+'yy'"
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
