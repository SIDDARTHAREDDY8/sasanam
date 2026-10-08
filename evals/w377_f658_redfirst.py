#!/usr/bin/env python3
"""Red-first for F658: flatMap with literal-array-returning callback.

F554 (CLOSED) models only the `.bind`-bound flatMap triple path. A DIRECT flatMap call whose callback returns a literal fragment array, composed with .join, assembles the credential node-exactly (v24.20.0) while the decoder misses.
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

SHAPES = [
    ("flatmap-function-callback",
     "['x'].flatMap(function(){return ['" + _A + "','" + _B + "'];}).join('')"),
    ("flatmap-arrow-callback",
     "['x'].flatMap(()=>['" + _A + "','" + _B + "']).join('')"),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['" + _A + "','" + _B + "'].join('')", True),
    ("junk-quiet",
     "['x'].flatMap(()=>['jx']).join('')", False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
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
