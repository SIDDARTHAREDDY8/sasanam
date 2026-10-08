#!/usr/bin/env python3
"""Red-first for F636: bind-on-bound-function chains.

F614 (CLOSED, wave-374 lane 3) models a single .call/.apply/.bind on a
function-expression receiver, but a SECOND .bind (or .apply) on the already
bound function escapes: the decoder's F614 route requires the receiver to be
a bare function expression, not a bound-function value.
Filed 2026-10-08 at wave-374 merge (merge-time re-verification of lane 3's
F614 closure, local node validation, $0 spend); LOW, OPEN.
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
    ('bind-bind-chain',
     "((a)=>(a+'%(A2)s')).bind(null,'%(A1)s').bind(null)()"
     % {"A1": A1, "A2": A2}, True),
    ('bind-then-apply',
     "((a,b)=>a+b).bind(null,'%(A1)s').apply(null,['%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f614-single-bind-blocks',
     "((a)=>(a+'%(A2)s')).bind(null,'%(A1)s')()" % {"A1": A1, "A2": A2}, True),
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
