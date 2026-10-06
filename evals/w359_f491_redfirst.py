#!/usr/bin/env python3
"""Red-first for F491: Reflect.get / property-descriptor indirection at dispatch targets. F469 models Reflect.apply and F480 models bracket member access, but reaching the method via Reflect.get(X,'m').call or Object.getOwnPropertyDescriptor(X,'m').value.call bypasses both: all shapes node-evaluate (v24.20.0) to the exact credential while the decoder produces zero variants. Distinct from F469 (Reflect.apply call form) and F480 (static-method bracket access).
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
    ("reflect-get-call",
     "Reflect.get(Array.prototype,'concat').call([], '%s','%s').join('')" % (A1, A2), True),
    ("gopd-value-call",
     "Object.getOwnPropertyDescriptor(Array.prototype,'concat').value.call([], '%s','%s').join('')" % (A1, A2), True),
    ("reflect-get-ctor-of",
     "Reflect.get([].constructor,'of')('%s','%s').join('')" % (A1, A2), True),
    ("reflect-get-array-of",
     "Reflect.get(Array,'of')('%s','%s').join('')" % (A1, A2), True),
    ("reflect-get-slice",
     "Reflect.get(Array.prototype,'slice').call(['%s','%s'], 0).join('')" % (A1, A2), True),
    ("gopd-join-call",
     "Object.getOwnPropertyDescriptor(Array.prototype,'join').value.call(['%s','%s'], '')" % (A1, A2), True),
    ("gopd-ctor-of",
     "Object.getOwnPropertyDescriptor([].constructor,'of').value('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f478-dot-held",
     "[].concat.call([], '%s','%s').join('')" % (A1, A2), True),
    ("junk-quiet",
     "Reflect.get(Array.prototype,'concat').call([], 'ab','cd').join('')", False),
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
