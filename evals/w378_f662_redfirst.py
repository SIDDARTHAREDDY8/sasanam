#!/usr/bin/env python3
"""Red-first for F662: class fragment sources.

Class declarations have no modeled path in the bounded static JS-expression decoder: static fields, static blocks, static getters, and instance fields all assemble the credential node-exactly (v24.20.0) while the decoder produces zero variants.
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
    ("static-field",
     "(function(){class C{static x='xoxb-0123';}return C.x+'456789abcdef';})()", True),
    ("static-block",
     "(function(){let s='';class C{static{s='xoxb-0123';}}s+='456789abcdef';return s;})()", True),
    ("static-getter",
     "(function(){class C{static get x(){return 'xoxb-0123';}}return C.x+'456789abcdef';})()", True),
    ("instance-field",
     "(function(){class C{x='xoxb-0123';}return new C().x+'456789abcdef';})()", True),
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
