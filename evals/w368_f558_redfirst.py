#!/usr/bin/env python3
"""Red-first for 558: object-pattern destructuring in Reflect.apply targets.

F545 filed object-pattern destructuring in IIFE dispatch and F546 filed arguments-enumerating bodies in Reflect.apply dispatch; the composition -- object patterns in a Reflect.apply TARGET -- escapes both: const and var forms node-evaluate to the exact credential (v24.20.0) with zero decoder variants. F519xF533-style composition gap (cf. F546's own rationale).
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
    ('const',
     'Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, True),
    ('var',
     'Reflect.apply(function(){var {0:x,1:y}=arguments;return x+y;},null,[\'%(A1)s\',\'%(A2)s\'])'
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f524-closed',
     "(function(){const [a,b]=arguments;return a+b;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply(function(){const {0:a,1:b}=arguments;return a+b;},null,['zz','yy'])"
     % {"A1": A1, "A2": A2}, False),
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
