#!/usr/bin/env python3
"""Red-first for 544: Spread in Reflect.apply args array.

F519 models Reflect.apply with a literal args array; F531 models spread in the
.bind ARGUMENTS -- but a spread in the APPLY args array itself
(Reflect.apply(fn, null, [...['f1','f2']])) escapes the F519 literal-array
grammar while node evaluates it identically.
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
    ('spread-args-direct',
     "Reflect.apply(function(a,b){return a+b;}, null, [...['%(A1)s','%(A2)s']])"
     % {"A1": A1, "A2": A2}, True),
    ('spread-args-call-indirect',
     "Reflect.apply.call(Reflect, function(a,b){return a+b;}, null, [...['%(A1)s','%(A2)s']])"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f519-literal-args-closed',
     "Reflect.apply(function(a,b){return a+b;}, null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "Reflect.apply(function(a,b){return a+b;}, null, [...['ab','cd']])"
    , False),

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
