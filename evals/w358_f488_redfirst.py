#!/usr/bin/env python3
"""Red-first for F488: direct invocation of constructor-function spellings
through non-identifier callees. The decoder anchors the Array constructor
call on the identifier form (Array('f1','f2') blocks coded); the same
function reached as ([].constructor)(...) or
Object.getPrototypeOf([]).constructor(...) bypasses the anchor. All
shapes node-evaluate (v24.20.0) to the exact credential while the
decoder misses. Distinct from F476 (the .of factory) and F480-A
(call/apply DISPATCH of the constructor -- here there is no dispatch,
just a differently-spelled direct call).
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
    ("ctor-paren-call",
     "([].constructor)('%s','%s').join('')" % (A1, A2), True),
    ("ctor-getproto-call",
     "Object.getPrototypeOf([]).constructor('%s','%s').join('')" % (A1, A2), True),
    ("ctor-bracket-paren-call",
     "([]['constructor'])('%s','%s').join('')" % (A1, A2), True),
    ("ctor-getproto-bracket-call",
     "(Object.getPrototypeOf([])['constructor'])('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "([].constructor)('ab','cd').join('')", False),
    ("identifier-form-held",
     "Array('%s','%s').join('')" % (A1, A2), True),
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
