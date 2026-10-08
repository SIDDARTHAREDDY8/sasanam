#!/usr/bin/env python3
"""Red-first for 599: URLSearchParams.append then getAll.

F584 (OPEN) covers getAll on constructor strings and F576 (CLOSED) covers .get, but statement-form append() mutations followed by getAll() escape: the constructor-string model never sees the appended pairs. Both shapes node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F584 (constructor-string getAll) and F576 (.get, CLOSED).
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
    ('usp-append-getall',
     '\"(function(){var p=new URLSearchParams(\'q=%(A1)s\');p.append(\'q\',\'%(A2)s\');return p.getAll(\'q\').join(\'\');})()\"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-append-double',
     '\"(function(){var p=new URLSearchParams(\'\');p.append(\'q\',\'%(A1)s\');p.append(\'q\',\'%(A2)s\');return p.getAll(\'q\').join(\'\');})()\"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('usp-ctor-get-blocked',
     '\"\"new URLSearchParams(\'q=%(A1)s%(A2)s\').get(\'q\')\"\"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-append-get-blocked',
     '\"(function(){var p=new URLSearchParams(\'\');p.append(\'q\',\'%(A1)s%(A2)s\');return p.get(\'q\');})()\"'
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
