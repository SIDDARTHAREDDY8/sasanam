#!/usr/bin/env python3
"""Red-first for F671: member reads in IIFE-return additive position.

Member reads in IIFE-return additive position bypass the decoder: the statement-level additive grammar routes member reads (F535), but the IIFE-body return additive grammar does not, so o.x+'f2', {x}.x+'f2', and o.x+o.y inside (function(){return ...})() assemble node-exactly (v24.20.0) while the decoder produces zero variants. Distinct from F665 (the ?.-specific gap, which misses even at statement level).
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
_BT = chr(96)

SHAPES = [
    ("varbound-dot",
     "(function(){var o={x:'xoxb-0123'};return o.x+'456789abcdef';})()", True),
    ("inline-dot",
     "(function(){return {x:'xoxb-0123'}.x+'456789abcdef';})()", True),
    ("varbound-double",
     "(function(){var o={x:'xoxb-0123',y:'456789abcdef'};return o.x+o.y;})()", True),]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("statement-dot-twin-blocks",
     "({x:'xoxb-0123'}).x+'456789abcdef'", True),
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
