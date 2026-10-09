#!/usr/bin/env python3
"""Red-first for F935: zero-width steganography stripped via a
unicode-escape regex class.

The decoder's F603/F765 regex grammars did not support \\uXXXX escapes
in character classes, so a zero-width-space-steganographed credential
(the Barracuda 2026-10-07 dual-target class) stripped by
.replace(/[\\u200b-\\u200d\\ufeff]/g,'') resolved node-exactly while
the decoder failed closed with zero variants. The raw-text ZWSP case
was already blocked; the plain-credential twin blocks coded.
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
Closed wave-389: _f935_class_escape admits \\uXXXX in F765 classes
(+ term position), and the replace dispatch gained an F765-grammar
branch ("" / "g" flags).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("s1",
     "(function(){return 'xox\\u200bb-0123456789abcdef'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()",
     True),
    ("s2-long",
     "(function(){return 'xox\\u200bb-0123456789abcdef0123456789abcdef012'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()",
     True),
    # Lane generalizations (node-exact, v24.20.0):
    ("g-single-escape",
     "(function(){return 'xox\\u200bb-0123456789abcdef'.replace(/[\\u200b]/g,'');})()",
     True),
    ("g-non-strip-class",
     # credential already clean; class strips nothing -- still flags
     "(function(){return 'xoxb-0123456789abcdef'.replace(/[\\u200b-\\u200d]/g,'');})()",
     True),
    ("g-first-only",
     # no "g" flag: first match only -- the single ZWSP is stripped
     "(function(){return 'xox\\u200bb-0123456789abcdef'.replace(/[\\u200b]/,'');})()",
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("twin-plain-replace",
     "(function(){return 'xoxb-0123456789abcdef'.replace(/[\\u200b-\\u200d\\ufeff]/g,'');})()",
     True),
]

# Fail-closed bounds: these must NOT decode (safe misses).
BOUNDS = [
    # out-of-order escape range: the engine throws SyntaxError
    "(function(){return 'ab'.replace(/[\\u200d-\\u200b]/g,'');})()",
    # lone surrogate escape: UTF-16 code-unit semantics unmodeled
    "(function(){return 'ab'.replace(/[\\ud800]/g,'');})()",
    # non-global flags change semantics
    "(function(){return 'a\\u200bb'.replace(/[\\u200b]/gi,'');})()",
    # bad escape: the engine does NOT throw (Annex B identity escape
    # makes [\\u20] == [u20]) -- the decoder fails closed (residual,
    # rejected, never mis-decoded)
    "(function(){return 'u20'.replace(/[\\u20]/g,'-');})()",
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
    for i, payload in enumerate(BOUNDS):
        hit = find_credential(payload) is not None
        ok = not hit
        print("bound-%d: %s" % (i, "HELD(bound-ok)" if ok else "BREAK(bound-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
