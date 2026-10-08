#!/usr/bin/env python3
"""Red-first for F707: Proxy getOwnPropertyDescriptor-trap descriptor reads: the de

Proxy getOwnPropertyDescriptor-trap descriptor reads: the decoder models the get trap (F642) and getPrototypeOf (F675) but not the getOwnPropertyDescriptor trap; the trap returning a data descriptor whose .value reads the fragment is exact in node (v24.20.0) while the decoder produces zero variants.
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
    ("gopd-trap",
     "(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Object.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B), True),
    ("gopd-trap-reflect",
     "(function(){var t={x:'%s'};var p=new Proxy(t,{getOwnPropertyDescriptor:function(tr,pr){return {value:tr[pr],configurable:true};}});return Reflect.getOwnPropertyDescriptor(p,'x').value+'%s';})()" % (_A, _B), True)
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
