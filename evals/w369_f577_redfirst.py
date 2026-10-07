#!/usr/bin/env python3
"""Red-first for 577: arrow-IIFE rest-parameter bindings.

F516 (CLOSED) covers arguments bindings in function-expression IIFEs, but arrow IIFEs bind via rest parameters: ((...a)=>a[0]+a[1])('f1','f2') node-evaluates to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F516 (arguments), F519 (Reflect.apply arrow targets, CLOSED), F522/F528 (function-expression IIFE targets), F556 (bind-bound arrows, OPEN).
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
    ('arrow-rest',
     "((...a)=>a[0]+a[1])('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('arrow-rest-call',
     "((...a)=>a[0]+a[1]).call(null,'%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f516-closed',
     "(function(){var a=arguments;return a[0]+a[1]})('%(A1)s','%(A2)s')"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     "((...a)=>a[0]+a[1])('zz','yy')"
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
