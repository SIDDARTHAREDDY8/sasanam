#!/usr/bin/env python3
"""Red-first for F479: join() coercion of non-string array elements.

The static JS-expression decoder's array parser fails closed on array
literals containing null / undefined / nested-array elements, so the whole
array is never decoded. But the real engine coerces those elements inside
.join(''): null/undefined become "", nested arrays stringify one level.
Every shape below node-evaluates (v24.20.0) to the exact credential while
the decoder produces zero variants.

Distinct from F477 (implicit String() coercion of non-string *arguments* --
a different parser path) and from F475 (filter over-decode on mixed-type
arrays -- the opposite direction: over-decode vs fail-closed miss).

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
    # (name, payload, real-engine-recovers-credential [node-verified])
    ("join-null-tail",
     "['%s','%s',null].join('')" % (A1, A2), True),
    ("join-undefined-tail",
     "['%s','%s',undefined].join('')" % (A1, A2), True),
    ("join-nested-array",
     "['%s',['%s']].join('')" % (A1, A2), True),
    ("join-null-mid",
     "['%s',null,'%s'].join('')" % (A1, A2), True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("junk-quiet", "['ab','cd',null].join('')", False),
    ("neighbor-plain-join",
     "['%s','%s'].join('')" % (A1, A2), True),
    ("neighbor-f475-numeric",
     "['%s',1,'%s'].join('')" % (A1, A2), True),
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
