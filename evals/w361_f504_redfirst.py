#!/usr/bin/env python3
"""Red-first for F504: bracket/template/nested-bracket member access on
Reflect.apply, plus dot-form Reflect.apply with a non-prototype method target.
F469 models Reflect.apply(Array.prototype.concat,...) (dot form, prototype
target) and F480 models Reflect.apply/Reflect['apply'] with the bare Array
target; the Reflect NAMESPACE member access in non-dot spellings, and
array-literal method targets, bypass both anchors. All shapes node-evaluate
(v24.20.0) to the exact credential while the decoder produces zero variants.
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
    ("reflect-bracket-apply",
     "Reflect['apply']([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
    ("reflect-template-apply",
     "Reflect[`apply`]([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
    ("reflect-nested-bracket-apply",
     "Reflect[['apply'][0]]([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
    ("reflect-dot-method-target",
     "Reflect.apply([].concat, [], ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f469-dot-prototype-target-held",
     "Reflect.apply(Array.prototype.concat,[],[['%s'],['%s']]).join('')" % (A1, A2), True),  # F469 closed
    ("f480-bracket-array-target-held",
     "Reflect['apply'](Array, Array, [['%s'],['%s']]).join('')" % (A1, A2), True),  # F480 closed
    ("junk-quiet",
     "Reflect['apply']([].concat, [], ['ab','cd']).join('')", False),
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
