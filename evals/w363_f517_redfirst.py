#!/usr/bin/env python3
"""Red-first for F517: object enumeration indirection (entries/keys/for-in).

F510 models Object.values indirection; the sibling enumeration builtins
Object.entries and Object.keys, and the for-in statement, are unmodeled.
All three shapes node-evaluate (v24.20.0) to the exact credential while
the decoder produces zero variants. Prints BREAK when a payload MISSES
(open tree), HELD when blocked.
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
    ("entries-map",
     "Object.entries({0:'%s',1:'%s'}).map(p=>p[1]).join('')" % (A1, A2), True),
    ("keys-join",
     "Object.keys({'%s':'x','%s':'y'}).join('')" % (A1, A2), True),
    ("for-in-loop",
     "(function(){var r='';var o={m:'%s',n:'%s'};for(var k in o)r+=o[k];return r})()" % (A1, A2), True),
]

CONTROLS = [
    ("f510-values-open",
     "Object.values({0:'%s',1:'%s'}).join('')" % (A1, A2), False),
    ("junk-quiet",
     "Object.entries({0:'ab',1:'cd'}).map(p=>p[1]).join('')", False),
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
