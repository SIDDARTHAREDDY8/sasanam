#!/usr/bin/env python3
"""Red-first for 545: Object-pattern destructuring of arguments.

F524 models ARRAY-pattern destructuring (const [a,b]=arguments -- the closure
grammar is explicitly (var|const|let) [n0(, n1)?] = arguments; the battery pins
only array-pattern boundaries). Object-pattern destructuring
(const {0:a,1:b}=arguments) is a different binding mechanism (key-based, not
index-based) that the decoder does not model. Round-34's battery docstring
lumped it under F524, but F524's executable spec (code + pinned boundaries)
covers array patterns only.
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
    ('objpattern-const',
     "(function(){const {0:a,1:b}=arguments;return a+b;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('objpattern-var',
     "(function(){var {0:x,1:y}=arguments;return x+y;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),

]

CONTROLS = [
    ('f524-array-pattern-closed',
     "(function(){const [a,b]=arguments;return a+b;})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "(function(){const {0:a,1:b}=arguments;return a+b;})('ab','cd')"
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
