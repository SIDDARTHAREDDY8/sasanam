#!/usr/bin/env python3
"""Red-first for F622: Object.keys + computed bracket reads on var-bound objects.

F612 (OPEN) covers Object.values/Object.entries through var-bound intermediates and F535 (CLOSED) covers literal-key member reads, but enumerating keys and reading back through COMPUTED brackets (`o[k[0]]`) escapes both: the key list is data, not syntax.
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
    ('keys-bracket',
     "(function(){var o={a:'%(A1)s',b:'%(A2)s'};var k=Object.keys(o);return o[k[0]]+o[k[1]];})()"
     % {"A1": A1, "A2": A2}, True),
    ('keys-map',
     "(function(){var o={a:'%(A1)s',b:'%(A2)s'};return Object.keys(o).map(k=>o[k]).join('');})()"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f583-blocks',
     "Object.keys({'%(A1)s':1,'%(A2)s':1}).join('')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
