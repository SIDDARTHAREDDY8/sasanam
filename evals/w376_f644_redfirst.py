#!/usr/bin/env python3
"""Red-first for F644: object/array-pattern destructuring of literal sources.

F545 (CLOSED) models object-pattern destructuring of `arguments` and
F524 array-pattern destructuring of `arguments`, but destructuring a LITERAL
source has no modeled path: the binding mechanism is the same, the source
class is new.
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("destructure-object-shorthand",
     "(function(){var {a,b}={a:'%s',b:'%s%s'};return a+b;})()" % (_F1, _F2, _F3), True),
    ("destructure-object-rename",
     "(function(){var {a:x,b:y}={a:'%s',b:'%s%s'};return x+y;})()" % (_F1, _F2, _F3), True),
    ("destructure-array-literal",
     "(function(){var [a,b]=['%s','%s%s'];return a+b;})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f545-arguments-still-blocks",
     "(function(){const {0:a,1:b}=arguments;return a+b;})('%s','%s%s')" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var {a,b}={a:'jx',b:'jy'};return a+b;})()", False),
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
