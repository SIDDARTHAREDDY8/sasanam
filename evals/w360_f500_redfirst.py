#!/usr/bin/env python3
"""Red-first for F500: spread args in String.fromCharCode. The decoder models
String.fromCharCode with literal numeric args (direct form blocks coded), but
a spread argsList -- String.fromCharCode(...[120,111,...]) -- bypasses the arg
parser while node evaluates it identically. Both shapes node-evaluate
(v24.20.0) to the exact credential while the decoder produces zero variants.
Distinct from F462 (spread-args CONCAT, closed wave-353 -- this is a different
call site with char-code semantics, not string-fragment semantics).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A2 = "456789" + "abcdef"

SHAPES = [
    ("fromcharcode-spread-partial",
     "String.fromCharCode(...[120, 111, 120, 98, 45, 48, 49, 50, 51]) + '%s'" % A2, True),
    ("fromcharcode-spread-full",
     "String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102])", True),
]

CONTROLS = [
    ("direct-fromcharcode-held",
     "String.fromCharCode(120,111,120,98,45,48,49,50,51) + '%s'" % A2, True),  # literal args blocked
    ("junk-quiet",
     "String.fromCharCode(...[97, 98])", False),
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
