#!/usr/bin/env python3
"""Red-first for F673: object-construction member reads beyond F663/F664/F671.

Object-construction member reads beyond F663/F664/F671: defineProperties-installed getters, Object.entries/Object.values destructuring, computed-key literals, Object.create prototype reads, and hasOwn-guarded reads. F671 files plain-literal member reads in IIFE-return position; these are distinct source productions.
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
    ("defineprop-getter",
     "(function(){var o={};Object.defineProperties(o,{x:{get:function(){return 'xoxb-0123';}}});return o.x+'456789abcdef';})()", True),
    ("entries-destr",
     "(function(){var [[k,v]]=Object.entries({x:'xoxb-0123'});return v+'456789abcdef';})()", True),
    ("values-destr",
     "(function(){var [v]=Object.values({x:'xoxb-0123'});return v+'456789abcdef';})()", True),
    ("computed-key",
     "(function(){var k='x';var o={[k]:'xoxb-0123'};return o.x+'456789abcdef';})()", True),
    ("create",
     "(function(){var o=Object.create({x:'xoxb-0123'});return o.x+'456789abcdef';})()", True),
    ("hasown",
     "(function(){var o={x:'xoxb-0123'};return (Object.hasOwn(o,'x')?o.x:'junk')+'456789abcdef';})()", True),
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
