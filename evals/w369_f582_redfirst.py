#!/usr/bin/env python3
"""Red-first for F582: extra call args beyond arity on F519-class targets.

F519 (wave-367 lane 2) closed Reflect.apply((a,b)=>a+b, null, ['f1','f2'])
with exact-arity matching, but the engine fills params positionally and
IGNORES extras: Reflect.apply((a,b)=>a+b, null, ['f1','f2','junk'])
node-evaluates to the exact credential (v24.20.0) while the decoder fails
closed on the arity mismatch (zero variants). Re-filed as a new finding
(rather than silently patched into F519) per the red-first audit rule;
caught by the wave-369 lane 4 two-axis code review while closing F556.
Renumbered F570->F582 at the wave-369 merge (attack round 37 filed F570
first at 20:41 UTC; wave-272 rule).
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
    ('extra-args-arrow',
     "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s','junk'])"
     % {"A1": A1, "A2": A2}, True),
    ('extra-args-fnexpr',
     "Reflect.apply(function(a,b){return a+b;},null,['%(A1)s','%(A2)s','junk','more'])"
     % {"A1": A1, "A2": A2}, True),
    ('extra-args-unused-param',
     "Reflect.apply(function(a,b,c){return a+b;},null,['%(A1)s','%(A2)s','zz','junk'])"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f519-exact-arity',
     "Reflect.apply((a,b)=>a+b,null,['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply((a,b)=>a+b,null,['zz','yy','junk'])", False),
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
