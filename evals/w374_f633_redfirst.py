#!/usr/bin/env python3
"""Red-first for F633: BigInt-to-string fragment assembly.

Unmodeled atom (F611 fragment precedent): the decoder has no model of BigInt literals, so String(123n)/`${123n}` digit fragments are invisible while node converts them exactly; padStart itself is modeled (control blocks).
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
    ('bigint-concat',
     "('"+A1[:5]+"'+String(123n)+'"+A2+"')"
     , True),
    ('bigint-template',
     "`"+A1[:5]+"${123n}"+A2+"`"
     , True),
    ('bigint-padstart',
     "('"+A1[:4]+"-'+String(123n).padStart(4,'0')+'"+A2+"')"
     , True),
]

CONTROLS = [
    ('padstart-modeled-blocks',
     "('"+A1[:4]+"-'+'123'.padStart(4,'0')+'"+A2+"')", True),
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
