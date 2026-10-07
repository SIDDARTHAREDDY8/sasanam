#!/usr/bin/env python3
"""Red-first for 591: Object.defineProperty accessor descriptors.

F550/F578 closed defineProperty with VALUE descriptors and function-expression GETTERS, but arrow-function getters (concise and block bodies) and function-expression SETTERS invoke unmodeled code: all three shapes node-evaluate to the exact credential (v24.20.0) while the decoder produces zero variants. Distinct from F550 (value descriptors, CLOSED).
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
    ('accessor-arrow',
     '"Object.defineProperty({},\'c\',{get:()=>\'%(A1)s\'}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('accessor-arrow-block',
     '"Object.defineProperty({},\'c\',{get:()=>{return \'%(A1)s\';}}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('accessor-setter',
     '"(function(){var o={};Object.defineProperty(o,\'c\',{set:function(v){this._c=v;}});o.c=\'%(A1)s\';return o._c+\'%(A2)s\';})()"'
     % {"A1": A1, "A2": A2}, True)
]

CONTROLS = [
    ('getter-fnexpr-blocked',
     '"Object.defineProperty({},\'c\',{get:function(){return \'%(A1)s\';}}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('value-blocked',
     '"Object.defineProperty({},\'c\',{value:\'%(A1)s\'}).c+\'%(A2)s\'"'
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"Object.defineProperty({},\'c\',{get:()=>\'ab\'}).c"'
     % {"A1": A1, "A2": A2}, False)
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
