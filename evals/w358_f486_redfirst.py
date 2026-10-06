#!/usr/bin/env python3
"""Red-first for F486: .call/.apply dispatch on STATIC factory methods.
F478 covers .call/.apply on PROTOTYPE methods; F476 covers the factories
in DIRECT form; F458 covers String.fromCharCode direct. Dispatching the
factories themselves -- Array.of.call, [].constructor.of.call,
String.fromCharCode.apply -- bypasses all three anchors. All shapes
node-evaluate (v24.20.0) to the exact credential while the decoder
produces zero variants. Distinct from F478 (prototype methods), F476
(direct factory), F458 (direct fromCharCode), F480-A (dispatch of the
constructor itself).
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
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

SHAPES = [
    ("arrayof-call",
     "Array.of.call([], '%s','%s').join('')" % (A1, A2), True),
    ("ctor-of-call",
     "[].constructor.of.call([].constructor, '%s','%s').join('')" % (A1, A2), True),
    ("fcc-apply",
     "String.fromCharCode.apply(null, [%s])" % ", ".join(str(c) for c in FCC), True),
]

CONTROLS = [
    ("junk-quiet",
     "Array.of.call([], 'ab','cd').join('')", False),
    ("neighbor-f476-held",
     "[].constructor.of('%s','%s').join('')" % (A1, A2), True),
    ("neighbor-f478-held",
     "Array.prototype.concat.call([], '%s','%s').join('')" % (A1, A2), True),
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
