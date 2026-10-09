#!/usr/bin/env python3
"""Red-first for F935: zero-width-steganography strip via unicode-escape regex class.

the decoder's F603/F765 regex grammars do not support \\uXXXX escapes in character classes: a zero-width-space-steganographed credential (the Barracuda dual-target class) stripped by .replace(/[\\u200b-\\u200d\\ufeff]/g,'') resolves node-exactly while the decoder fails closed with zero variants. The raw-text ZWSP case is already blocked (control); the plain-credential twin blocks coded via the raw regex.
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("s1",
     "(function(){return 'xox\\u200bb-0123456789abcdef'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()",
     True),
    ("s2-long",
     "(function(){return 'xox\\u200bb-0123456789abcdef0123456789abcdef012'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()",
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("twin-plain-replace",
     "(function(){return 'xoxb-0123456789abcdef'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()", True),
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
