#!/usr/bin/env python3
"""Red-first for F495: method invocation through local variable bindings. The decoder anchors dispatch on member-expression callees; reaching the same function through a destructured or aliased binding -- const {concat} = Array.prototype; concat.call(...), let c = [].concat; c.call(...), const K = [].constructor; K.of(...) -- node-evaluates (v24.20.0) to the exact credential while the decoder produces zero variants. No filed finding covers free-variable callees.
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
    ("destructure-call",
     "const {concat} = Array.prototype; concat.call([], '%s','%s').join('')" % (A1, A2), True),
    ("alias-call",
     "let c = [].concat; c.call([], '%s','%s').join('')" % (A1, A2), True),
    ("alias-ctor-of",
     "const K = [].constructor; K.of('%s','%s').join('')" % (A1, A2), True),
]

CONTROLS = [
    ("direct-dispatch-held",
     "[].concat.call([], '%s','%s').join('')" % (A1, A2), True),
    ("junk-quiet",
     "const {concat} = Array.prototype; concat.call([], 'ab','cd').join('')", False),
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
