#!/usr/bin/env python3
"""Red-first for F510: Object.values indirection on objects holding fragments.
The decoder models object-literal array-like receivers (F487) and their
freeze/seal-wrapped dispatch forms (F502/F503), but the Object.values call site
-- which enumerates an object's values into an array -- is unmodeled for plain,
frozen, sealed, and nested objects alike: Object.values({0:'f1',1:'f2'}),
Object.values(Object.freeze({...})), Object.values(Object.seal({...})), and
Object.values(Object.freeze(Object.entries({...}).reduce(...))) all
node-evaluate (v24.20.0) to the exact credential while the decoder produces zero
variants. Distinct from F508 (Array.from call site -- different builtin, per the
F500/F505 precedent). Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
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
    ("values-plain",
     "Object.values({0:'%s',1:'%s'}).join('')" % (A1, A2), True),
    ("values-freeze",
     "Object.values(Object.freeze({0:'%s',1:'%s'})).join('')" % (A1, A2), True),
    ("values-seal",
     "Object.values(Object.seal({0:'%s',1:'%s'})).join('')" % (A1, A2), True),
    ("values-nested",
     "Object.values(Object.freeze(Object.entries({0:'%s',1:'%s'}).reduce((o,[k,v])=>(o[k]=v,o),{}))).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "Object.values({0:'ab',1:'cd'}).join('')", False),
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
