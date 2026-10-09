#!/usr/bin/env python3
"""Red-first for F765: RegExp match/matchAll extraction (char-class bodies).

The decoder models match/matchAll only for F603 regex-plain bodies
(F694); bodies with character classes / `+` quantifiers (e.g.
/xoxb-[0-9]+/) have no production: they resolve node-exactly while the
decoder produces zero variants.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    # Filed shape 1: match with char-class body, m[0].
    ("s1",
     "(function(){var m='xx%syy'.match(/xoxb-[0-9]+/);return m[0]+'%s';})()" % (_A, _B),
     True),
    # Filed shape 2: matchAll with char-class body, m[0][0].
    ("s2",
     "(function(){var m=[...'xx%syy'.matchAll(/xoxb-[0-9]+/g)];return m[0][0]+'%s';})()" % (_A, _B),
     True),
    # Filed variant: match with capture group, m[1] recovers the credential.
    ("s3",
     "(function(){var m='xx%syy'.match(/(xoxb-[0-9]+)/);return m[1]+'%s';})()" % (_A, _B),
     True),
    # Filed variant: matchAll with capture group, m[0][1].
    ("s4",
     "(function(){var m=[...'xx%syy'.matchAll(/(xoxb-[0-9]+)/g)];return m[0][1]+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
