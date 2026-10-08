#!/usr/bin/env python3
"""Red-first for 600: Map keys iteration reads.

F589 (OPEN) covers Map ENTRIES iteration ([...map.entries()][0][1], .map(e=>e[1])), but the KEYS iterator -- Array.from(map.keys()), [...map.keys()], map.keys().forEach -- is a different read path: all three shapes node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F589 (entries iteration) and F563 (.get dispatch, CLOSED).
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
    ('map-keys-arrayfrom',
     '\"Array.from(new Map([[\'%(A1)s\',1],[\'%(A2)s\',2]]).keys()).join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
    ('map-keys-spread',
     '\"[...new Map([[\'%(A1)s\',1],[\'%(A2)s\',2]]).keys()].join(\'\')\"'
     % {"A1": A1, "A2": A2}, True),
    ('map-keys-foreach',
     '\"(function(){var s=\'\';new Map([[\'%(A1)s\',1],[\'%(A2)s\',2]]).keys().forEach(function(k){s+=k;});return s;})()\"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('map-get-blocked',
     '\"new Map([[\'c\',\'%(A1)s\']]).get(\'c\')+\'%(A2)s\'\"'
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
