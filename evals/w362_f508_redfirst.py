#!/usr/bin/env python3
"""Red-first for F508: Array.from with a mapping function or non-literal source.
F494 closed spread of non-literal iterables and the decoder models the plain
Array.from(['f1','f2']) call site, but Array.from with a MAPPING function
(Array.from(['f1','f2'], x=>x)), with an ARRAY-LIKE source
(Array.from({length:2, 0:'f1', 1:'f2'})), or with a Set source
(Array.from(new Set(['f1','f2']))) bypasses the call-site parser: the source /
mapper grammar only models the literal-array, mapper-less shape. All shapes
node-evaluate (v24.20.0) to the exact credential while the decoder produces zero
variants. Prints BREAK when a payload MISSES (open tree), HELD when blocked.
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
    ("from-with-mapper",
     "Array.from(['%s','%s'], x=>x).join('')" % (A1, A2), True),
    ("from-arraylike-source",
     "Array.from({length:2, 0:'%s', 1:'%s'}).join('')" % (A1, A2), True),
    ("from-set-source",
     "Array.from(new Set(['%s','%s'])).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("from-plain-held",
     "Array.from(['%s','%s']).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Array.from(['ab','cd'], x=>x).join('')", False),
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
