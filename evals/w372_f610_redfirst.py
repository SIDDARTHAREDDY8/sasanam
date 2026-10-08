#!/usr/bin/env python3
"""Red-first for F610: URLSearchParams.set mutation then .get read.

F599 (OPEN, wave-372 lane 3 closing it) models append/set statement-form mutations followed by getAll(); F576 (CLOSED) models .get on constructor strings. But a set() mutation read back via .get() is a different read path: set() OVERWRITES (engine-exact: first N-pair takes the value, other N-pairs dropped) while get() returns the first value -- the shapes below all node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Verified still missing on the F599-closed lane tree (wave-372 lane 3, commit a28c474e), so it survives F599's closure. Distinct from F599 (append->getAll) and F576 (.get on constructor strings, CLOSED).
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
    ('usp-set-get-ctor',
     '"(function(){var p=new URLSearchParams(\'q=xx\');p.set(\'q\',\'%(A1)s\');return p.get(\'q\')+\'%(A2)s\';})()"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-set-get-empty',
     '"(function(){var p=new URLSearchParams(\'\');p.set(\'q\',\'%(A1)s\');return p.get(\'q\')+\'%(A2)s\';})()"'
     % {"A1": A1, "A2": A2}, True),
    ('usp-set-get-const',
     '"(function(){const p=new URLSearchParams(\'q=zz\');p.set(\'q\',\'%(A1)s\');return p.get(\'q\')+\'%(A2)s\';})()"'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('usp-ctor-get-blocked',
     '""new URLSearchParams(\'q=%(A1)s%(A2)s\').get(\'q\')""'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '""(function(){var s=\'ab\';return s;})()""'
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
