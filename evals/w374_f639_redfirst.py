#!/usr/bin/env python3
"""Red-first for F639: nested var-bound Object.values/entries paths.

F612 (CLOSED, wave-374 lane 1) resolves Object.values/Object.entries through a
var-bound intermediate, but member-access paths ON the intermediate escape:
Object.values(o.x) where o is the var-bound object is not routed by the F612
model (which requires the bare bound ident as the call argument).
Filed 2026-10-08 at wave-374 merge (merge-time re-verification of lane 1's
F612 closure, local node validation, $0 spend); LOW, OPEN.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ('nested-values',
     "(function(){var o={x:{p:'%(A1)s'},y:{q:'%(A2)s'}};"
     "return Object.values(o.x).concat(Object.values(o.y)).join('');})()"
     % {"A1": A1, "A2": A2}, True),
    ('nested-entries',
     "(function(){var o={x:{p:'%(A1)s'},y:{q:'%(A2)s'}};"
     "return Object.entries(o.x).map(e=>e[1]).join('')"
     "+Object.entries(o.y).map(e=>e[1]).join('');})()"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f612-bare-values-blocks',
     "(function(){var o={a:'%(A1)s',b:'%(A2)s'};return Object.values(o).join('');})()"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
