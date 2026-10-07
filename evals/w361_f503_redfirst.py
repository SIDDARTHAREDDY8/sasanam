#!/usr/bin/env python3
"""Red-first for F503: Object.seal / Object.preventExtensions-wrapped array-like
receivers at dispatch targets. F502 covers Object.freeze receivers; seal and
preventExtensions are DIFFERENT builtins with different integrity semantics,
and the decoder anchors neither wrapper at dispatch targets: the wrapper call
returns the same object (node-verified identity), but the receiver grammar only
models plain literals and F489/F502 shapes. All shapes node-evaluate
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
    ("seal-call",
     "Array.prototype.concat.call(Object.seal(['%s','%s']), []).join('')" % (A1, A2), True),
    ("preventext-call",
     "Array.prototype.concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (A1, A2), True),
    ("seal-objlike",
     "Array.prototype.join.call(Object.seal({length:2,0:'%s',1:'%s'}), '')" % (A1, A2), True),
    ("preventext-objlike",
     "Array.prototype.join.call(Object.preventExtensions({length:2,0:'%s',1:'%s'}), '')" % (A1, A2), True),
    ("seal-apply",
     "Array.prototype.concat.apply(Object.seal(['%s','%s']), [[]]).join('')" % (A1, A2), True),
    ("preventext-arrlit-dispatch",
     "[].concat.call(Object.preventExtensions(['%s','%s']), []).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("direct-seal-join-held",
     "Object.seal(['%s','%s']).join('')" % (A1, A2), True),  # direct method call: decoder models
    ("direct-preventext-concat-held",
     "Object.preventExtensions(['%s','%s']).concat([]).join('')" % (A1, A2), True),  # direct method call: decoder models
    ("junk-quiet",
     "Array.prototype.concat.call(Object.seal(['ab','cd']), []).join('')", False),
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
