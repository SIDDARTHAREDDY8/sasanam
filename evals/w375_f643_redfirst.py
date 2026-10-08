#!/usr/bin/env python3
"""Red-first for F643: String.fromCharCode/fromCodePoint with typed-array args.

F500 (CLOSED) covers String.fromCharCode with plain numeric args, plain-array
spread, and .apply/.call with plain arrays -- but a TYPED-ARRAY argument
(Uint8Array spread or .apply with a Uint8Array) has no modeled path: node
decodes the bytes exactly while the decoder produces zero variants.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F3 = _B
# Byte arrays computed at runtime from concatenation-derived fragments: no
# credential literal anywhere in this file.
_U8 = ",".join(str(b) for b in (_A[:5] + _A[5:][1:]).encode("latin-1"))

SHAPES = [
    ("fromcharcode-u8-spread",
     "String.fromCharCode(...new Uint8Array([%s]))+'%s'" % (_U8, _F3), True),
    ("fromcharcode-u8-apply",
     "String.fromCharCode.apply(null,new Uint8Array([%s]))+'%s'" % (_U8, _F3), True),
    ("fromcodepoint-u8-spread",
     "String.fromCodePoint(...new Uint8Array([%s]))+'%s'" % (_U8, _F3), True),
]

CONTROLS = [
    # F500 (CLOSED): plain numeric args still block.
    ("fromcharcode-plain-blocks",
     "String.fromCharCode(120,111,120,98,45)+'123'+'%s'" % _F3, True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
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
