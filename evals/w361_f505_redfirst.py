#!/usr/bin/env python3
"""Red-first for F505: String.fromCodePoint with spread args. F500 covers
spread args in String.fromCharCode; fromCodePoint is a DIFFERENT builtin
(Unicode code points, surrogate-pair semantics) with its own call site, and
the decoder's arg-list parser only models the fromCharCode site. All shapes
node-evaluate (v24.20.0) to the exact credential while the decoder produces
zero variants. Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

CODES = "120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102"

SHAPES = [
    ("fromcodepoint-spread",
     "String.fromCodePoint(...[%s])" % CODES, True),
    ("fromcodepoint-two-spreads",
     "String.fromCodePoint(...[120,111,120,98,45,48,49,50,51], ...[52,53,54,55,56,57,97,98,99,100,101,102])", True),
]

CONTROLS = [
    ("f458-fromcharcode-direct-held",
     "String.fromCharCode(%s)" % CODES, True),  # F458/F480: direct fromCharCode blocks coded
    ("junk-quiet",
     "String.fromCodePoint(...[97,98])", False),
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
