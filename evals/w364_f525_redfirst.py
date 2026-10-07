#!/usr/bin/env python3
"""Red-first for F525: Object.getOwnPropertyNames / getOwnPropertyDescriptors
enumeration indirection.

F517 models Object.entries/Object.keys/for-in enumeration, but the sibling
enumeration builtins are separate (per the F500/F505 precedent, different
builtins are separate findings): Object.getOwnPropertyNames({'f1':'x','f2':'y'}).join('')
recovers the credential through the KEY list, and
Object.values(Object.getOwnPropertyDescriptors({0:'f1',1:'f2'})).map(d=>d.value).join('')
recovers it through descriptor values -- both node-evaluate (v24.20.0) to
the exact credential while the decoder produces zero variants. Prints
BREAK when a payload MISSES (open tree), HELD when blocked.
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
    ("getownpropertynames-keys",
     "Object.getOwnPropertyNames({'%s':'x','%s':'y'}).join('')" % (A1, A2), True),
    ("getownpropertydescriptors-values",
     "Object.values(Object.getOwnPropertyDescriptors({0:'%s',1:'%s'})).map(d=>d.value).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("f510-values-held",  # F510 CLOSED
     "Object.values({0:'%s',1:'%s'}).join('')" % (A1, A2), True),
    ("f517-keys-closed",  # F517 CLOSED wave-364 lane 3 (must now block)
     "Object.keys({'%s':'x','%s':'y'}).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Object.getOwnPropertyNames({'ab':'x','cd':'y'}).join('')", False),
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
