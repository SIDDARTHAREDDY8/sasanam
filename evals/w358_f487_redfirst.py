#!/usr/bin/env python3
"""Red-first for F487: .call dispatch on ARRAY-LIKE (non-array) receivers.
The wave-357 F478 closure validates the receiver as a parsed array or
string; the engine accepts any array-like ({length, indexed elements})
for join/slice/filter. All shapes node-evaluate (v24.20.0) to the exact
credential while the decoder misses. Distinct from F478 (array/string
receivers hold) and F473 (array-receiver modeling).
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
    ("join-arraylike",
     "Array.prototype.join.call({length:2, 0:'%s', 1:'%s'}, '')" % (A1, A2), True),
    ("slice-arraylike",
     "Array.prototype.slice.call({length:2, 0:'%s', 1:'%s'}, 0).join('')" % (A1, A2), True),
    ("filter-arraylike",
     "Array.prototype.filter.call({length:2, 0:'%s', 1:'%s'}, x=>true).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "Array.prototype.join.call({length:2, 0:'ab', 1:'cd'}, '')", False),
    ("neighbor-f478-held",
     "Array.prototype.join.call(['%s','%s'], '')" % (A1, A2), True),
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
