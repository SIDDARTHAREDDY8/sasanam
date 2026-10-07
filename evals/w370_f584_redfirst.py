#!/usr/bin/env python3
"""Red-first for 584: URLSearchParams.getAll multi-value reads.

F576 filed .get() on URLSearchParams; .getAll() returns the value ARRAY, a different method the decoder does not model: new URLSearchParams('q=f1&q=f2').getAll('q').join('') node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F576 (single .get).
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
    ('getall',
     '"new URLSearchParams(\'q=%(A1)s&q=%(A2)s\').getAll(\'q\').join(\'\')"'
     % {"A1": A1, "A2": A2}, True),
    ('getall-slice',
     '"new URLSearchParams(\'q=%(A1)s&q=%(A2)s&q=zz\').getAll(\'q\').slice(0,2).join(\'\')"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('f576-closed-now-blocks',  # wave-370 merge: F576 CLOSED by lane 2; control flipped (wave-305 class)
     '"new URLSearchParams(\'q=%(A1)s\').get(\'q\')+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"new URLSearchParams(\'q=ab\').getAll(\'q\').join(\'\')"'
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
