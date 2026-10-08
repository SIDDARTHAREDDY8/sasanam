#!/usr/bin/env python3
"""Red-first for F637: .bind on indexed thunks (F614 x F620 composition).

F614 (CLOSED) models .call/.apply/.bind on function-expression receivers and
F620 (CLOSED, wave-374 lane 7) models direct invocation of indexed thunks, but
.bind applied to an indexed thunk element -- then invoked -- escapes both:
the receiver is a member expression (not a bare function expression for F614)
and the invocation is indirect (not direct for F620).
Filed 2026-10-08 at wave-374 merge (merge-time re-verification of lanes 3/7,
local node validation, $0 spend); LOW, OPEN.
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
    ('bind-indexed-thunk',
     "(function(){var f=[()=>'%(A1)s',()=>'%(A2)s'];var g=f[0].bind(null);return g()+f[1]();})()"
     % {"A1": A1, "A2": A2}, True),
    ('bind-indexed-thunk-args',
     "(function(){var f=[(a)=>a+'%(A2)s'];return f[0].bind(null,'%(A1)s')();})()"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f620-direct-thunk-blocks',
     "(function(){var f=[()=>'%(A1)s',()=>'%(A2)s'];return f[0]()+f[1]();})()"
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
