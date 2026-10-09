#!/usr/bin/env python3
"""Red-first for F832: plain .join reads on a var-bound array.

The F434 join production fires for inline array literals and F802
(wave-386 lane 4, closing) models flat/flatMap on var-bound arrays, but
a plain .join('') on a var-bound array has no production:
(function(){var a=['f1','f2'];return a.join('');})() node-evaluates to
the exact credential while the decoder produces zero variants.
Filed 2026-10-09 wave-386 lane 4 (F802 differential review).
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
    ("s1",
     "(function(){var a=['%s','%s'];return a.join('');})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var a=['%s','%s'];return a['join']('');})()" % (_A, _B),
     True),
]

CONTROLS = [
    # inline twin blocks (F434)
    ("inline-blocks",
     "['%s','%s'].join('')" % (_A, _B), True),
    # flat-first var-bound blocks (F802 closed)
    ("f802-closed-blocks",
     "(function(){var a=[['%s'],['%s']];return a.flat().join('');})()"
     % (_A, _B), True),
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
