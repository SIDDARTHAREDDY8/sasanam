#!/usr/bin/env python3
"""Red-first for F498: bracket-form Reflect['construct'] dispatch. The F480
closure models Reflect.construct (dot form) and documents "Reflect['construct']
bracket inequivalence is a documented scope boundary (residual candidate)":
the bracket-string member access on the Reflect namespace bypasses the anchor.
Both shapes node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Distinct from F469 (Reflect.apply dot form) and F480
(Reflect.apply / .apply / .call bracket forms -- construct is unmodeled).
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
    ("reflect-bracket-construct",
     "Reflect['construct'](Array, ['%s','%s']).join('')" % (A1, A2), True),
    ("reflect-bracket-construct-ctor",
     "Reflect['construct']([].constructor, ['%s','%s']).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("dot-construct-held",
     "Reflect.construct(Array, ['%s','%s']).join('')" % (A1, A2), True),  # dot form blocked
    ("junk-quiet",
     "Reflect['construct'](Array, ['ab','cd']).join('')", False),
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
