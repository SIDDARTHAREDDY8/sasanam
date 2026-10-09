#!/usr/bin/env python3
"""Red-first for F764: slice-family residuals (substr, substring arg-swap).

The decoder models slice (F624/F537) but not the legacy substr() nor
substring()'s argument-swap semantics (substring(9,0) == substring(0,9)):
both resolve node-exactly while the decoder produces zero variants.
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
    # Filed shape 1: substr with negative start.
    ("s1",
     "(function(){var s='xx%s';return s.substr(-9)+'%s';})()" % (_A, _B),
     True),
    # Filed shape 2: substring argument swap.
    ("s2",
     "(function(){var s='%sxx';return s.substring(9,0)+'%s';})()" % (_A, _B),
     True),
    # Filed variant: substr(start, length).
    ("s3",
     "(function(){var s='xx%syy';return s.substr(2,9)+'%s';})()" % (_A, _B),
     True),
    # Filed variant: substring(11,2) swap recovering the credential.
    ("s4",
     "(function(){var s='ab%szz';return s.substring(11,2)+'%s';})()" % (_A, _B),
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
