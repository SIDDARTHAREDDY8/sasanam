#!/usr/bin/env python3
"""Red-first for 602: Set iteration reads.

Set iteration -- for-of over a Set and Set.prototype.forEach -- has no modeled read path: both shapes node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F589 (Map entries, OPEN); the [...new Set(...)] spread IS modeled (control).
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
    ('set-forof',
     '\"(function(){var s=\'\';for(var x of new Set([\'%(A1)s\',\'%(A2)s\'])){s+=x;}return s;})()\"'
     % {"A1": A1, "A2": A2}, True),
    ('set-foreach',
     '\"(function(){var s=\'\';var st=new Set([\'%(A1)s\',\'%(A2)s\']);st.forEach(function(x){s+=x;});return s;})()\"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('set-spread-blocked',
     '\"[...new Set([\'%(A1)s\',\'%(A2)s\'])].join(\'\')\"'
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
