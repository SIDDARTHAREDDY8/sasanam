#!/usr/bin/env python3
"""Red-first for F519: Reflect.apply with a function-valued target.

F469/F504/F506 all model Reflect.apply with Array.prototype.concat-family
targets, but the TARGET itself can be an arrow function or function
expression: Reflect.apply((a,b)=>a+b, null, ['f1','f2']). The direct
Reflect.apply anchor matches, yet the unmodeled target class means the
decoder produces zero variants. Both shapes node-evaluate (v24.20.0) to
the exact credential. Prints BREAK when a payload MISSES (open tree),
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
    ("reflect-arrow-target",
     "Reflect.apply((a,b)=>a+b, null, ['%s','%s'])" % (A1, A2), True),
    ("reflect-fnexpr-target",
     "Reflect.apply(function(a,b){return a+b}, null, ['%s','%s'])" % (A1, A2), True),
]

CONTROLS = [
    ("f469-concat-target-held",
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.apply((a,b)=>a+b, null, ['ab','cd'])", False),
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
