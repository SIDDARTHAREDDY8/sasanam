#!/usr/bin/env python3
"""Red-first for F709: loop += accumulation: the decoder models straight-line conca

loop += accumulation: the decoder models straight-line concatenation (F655, CLOSED) but fails closed on counted loops; r+=frags[i] accumulates the exact credential (node v24.20.0) while the decoder produces zero variants. Distinct from F655 (straight-line).
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
    ("for-plus-eq",
     "(function(){var r='';for(var i=0;i<2;i++){r+=['%s','%s'][i];}return r;})()" % (_A, _B), True),
    ("while-plus-eq",
     "(function(){var r='';var i=0;while(i<2){r+=['%s','%s'][i];i++;}return r;})()" % (_A, _B), True)
]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
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
