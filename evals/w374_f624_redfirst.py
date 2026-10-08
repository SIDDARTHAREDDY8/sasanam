#!/usr/bin/env python3
"""Red-first for F624: String.prototype.slice() with trimming bounds.

F466 (CLOSED) models .slice(start[,end]) on parsed string ARRAYS, but on STRING values the slice step is unmodeled: only identity slices reduce (and then only via the substring scan when the pre-image already contains a credential-shaped run). Trimming slices that assemble the credential from sub-credential runs escape.
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
    ('slice-trim',
     '"xx%(A1)s".slice(2)+\'%(A2)s\''
     % {"A1": A1, "A2": A2}, True),
    ('slice-trim-bounded',
     '"xx%(A1)syy".slice(2,11)+\'%(A2)s\''
     % {"A1": A1, "A2": A2}, True),
    ('slice-trim-varbound',
     '(function(){var s="xx%(A1)s";return s.slice(2)+\'%(A2)s\';})()'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('identity-slice-blocks',
     '"%(A1)s%(A2)s".slice(0,25)'
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
