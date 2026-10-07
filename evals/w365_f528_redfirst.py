#!/usr/bin/env python3
"""Red-first for F528: Reflect.apply with complex IIFE-evaluated function targets.

F522 models Reflect.apply whose target is a single expression-bodied
IIFE result ((() => (a,b)=>a+b)()). Two richer IIFE value-production
mechanisms escape it: a NESTED IIFE ((() => ((() => (a,b)=>a+b))())())
and a BLOCK-BODIED IIFE with an intermediate variable
((() => { var f = (a,b)=>a+b; return f; })()). Both node-evaluate
(v24.20.0) to the exact credential while the decoder produces zero
variants. Distinct from F522 (single expression-bodied IIFE) and F519
(literal targets). Prints BREAK when a payload MISSES (open tree),
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
    ("nested-iife-target",
     "Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
    ("block-bodied-iife-target",
     "Reflect.apply((() => { var f = (a,b)=>a+b; return f; })(), null, ['%(A1)s','%(A2)s'])"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f522-expr-iife-closed",  # F522 CLOSED (wave-365 lane 2) -- now blocks coded
     "Reflect.apply((() => (a,b)=>a+b)(), null, ['%s','%s'])" % (A1, A2), True),
    ("f519-literal-target-held",  # F519 CLOSED wave-364 lane 1
     "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply((() => ((() => (a,b)=>a+b))())(), null, ['ab','cd'])", False),
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
