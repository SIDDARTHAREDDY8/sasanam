#!/usr/bin/env python3
"""Red-first for 595: JSON.stringify of nested ARRAY values.

F571 (wave-370 lane 2, CLOSED) models the stringify/parse round-trip for string literals, arrays of string literals, and F535 object literals -- but array VALUES nested inside objects or arrays are not serialized: JSON.parse(JSON.stringify({a:['f1','f2']})).a.join('') and JSON.parse(JSON.stringify([['f1'],['f2']])).flat().join('') both node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F571 (nested array values, a different value class). Filed at the wave-370 merge (merge verification of lane 8's unfiled U-stringify-nest ride).
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
    ("nest-arr-in-obj",
     "JSON.parse(JSON.stringify({a:['%s','%s']})).a.join('')" % (A1, A2),
     True),
    ("nest-arr-in-arr",
     "JSON.parse(JSON.stringify([['%s'],['%s']])).flat().join('')" % (A1, A2),
     True),
]

CONTROLS = [
    ("f571-top-array-blocked",
     "JSON.parse(JSON.stringify(['%s','%s'])).join('')" % (A1, A2),
     True),
    ("f571-nested-obj-blocked",
     "JSON.parse(JSON.stringify({o:{c:'%s'}})).o.c+'%s'" % (A1, A2),
     True),
    ("junk-quiet",
     "JSON.parse(JSON.stringify({a:['zz','yy']})).a.join('')",
     False),
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
