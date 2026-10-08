#!/usr/bin/env python3
"""Red-first for 598: JSON.stringify of derived (non-literal) arrays.

F571 (CLOSED) models the stringify/parse round-trip for string-literal arrays, but arrays DERIVED from Set/Map iteration -- Array.from(new Set(...)), [...new Set(...)], Array.from(map.values()) -- are not serialized: all three shapes node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F571 (literal arrays, CLOSED) and F595 (nested array values, OPEN).
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
    ('stringify-set-arrayfrom',
     '\"JSON.parse(JSON.stringify(Array.from(new Set([\'%(A1)s\',\'%(A2)s\'])))).join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
    ('stringify-set-spread',
     '\"JSON.parse(JSON.stringify([...new Set([\'%(A1)s\',\'%(A2)s\'])])).join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
    ('stringify-mapvalues',
     '\"JSON.parse(JSON.stringify(Array.from(new Map([[\'a\',\'%(A1)s\'],[\'b\',\'%(A2)s\']]).values()))).join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('stringify-literal-blocked',
     '\"JSON.parse(JSON.stringify([\'%(A1)s\',\'%(A2)s\'])).join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '\"\"(function(){var s=\'ab\';return s;})()\"\"'
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
