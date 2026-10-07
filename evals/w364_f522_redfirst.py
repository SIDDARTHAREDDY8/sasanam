#!/usr/bin/env python3
"""Red-first for F522: Reflect.apply with an IIFE-evaluated function target.

F519 models Reflect.apply with arrow/fn-expr literal targets, but the
TARGET can itself be the result of an immediately-invoked function
expression: Reflect.apply((() => (a,b)=>a+b)(), null, ['f1','f2']) and
Reflect.apply((function(){return (a,b)=>a+b})(), null, ['f1','f2']) both
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Distinct from F519 (literal targets) and F521
(.bind-bound targets). Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
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
    ("iife-arrow-target",
     "Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (A1, A2), True),
    ("iife-fnexpr-target",
     "Reflect.apply((function(){return (a,b)=>a+b})(), null, ['%s','%s'])" % (A1, A2), True),
]

CONTROLS = [
    ("f519-arrow-target-open",  # F519 OPEN (filed shape, must still miss)
     "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (A1, A2), False),
    ("junk-quiet",
     "Reflect.apply((() => (a,b)=>a+b)(), null, ['ab','cd'])", False),
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
