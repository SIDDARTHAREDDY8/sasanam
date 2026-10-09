#!/usr/bin/env python3
"""Red-first for F852: Proxy getOwnPropertyDescriptor trap.

The decoder models Proxy get traps (F642/F800) but not
getOwnPropertyDescriptor traps: `Object.getOwnPropertyDescriptor(p,'k').value`
resolves node-exactly while the decoder produces zero variants. Close-when:
the decoder models getOwnPropertyDescriptor traps node-exactly (or refuses
the laundering coded) such that find_credential flags them, red-first
verified, honest text unaffected.
Filed 2026-10-09 05:30 UTC wave-386 (attack round 54).
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
     "(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:"
     "function(t,k){return {value:t[k],configurable:true};}});"
     "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var p=new Proxy({k:'%s'},{getOwnPropertyDescriptor:"
     "function(t,k){var d=Object.getOwnPropertyDescriptor(t,k);return d;}});"
     "return Object.getOwnPropertyDescriptor(p,'k').value+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("get-twin-blocks",
     "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});"
     "return p.anything+'%s';})()" % (_A, _B), True),
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
