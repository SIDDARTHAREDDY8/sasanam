#!/usr/bin/env python3
"""Red-first for F511: Array.prototype.splice.call/.apply dispatch is unmodeled.
The decoder models direct .splice() on array literals and models slice.call on
both plain arrays and array-like receivers (F487), but the splice method has no
.call/.apply dispatch entry at all: Array.prototype.splice.call(['f1','f2'],0,2)
and Array.prototype.splice.call({length:2,0:'f1',1:'f2'},0,2) both node-evaluate
(v24.20.0) to the exact credential while the decoder produces zero variants.
Distinct from F487 (receiver class -- this breaks on plain arrays too) and from
the modeled slice.call analog. Prints BREAK when a payload MISSES (open tree),
HELD when blocked.
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
    ("splice-call-plainarr",
     "Array.prototype.splice.call(['%s','%s'],0,2).join('')" % (A1, A2), True),
    ("splice-call-arraylike",
     "Array.prototype.splice.call({length:2,0:'%s',1:'%s'},0,2).join('')" % (A1, A2), True),
]

CONTROLS = [
    ("splice-direct-held",
     "['%s','%s'].splice(0,2).join('')" % (A1, A2), True),
    ("slice-call-held",
     "Array.prototype.slice.call(['%s','%s'],0).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Array.prototype.splice.call(['ab','cd'],0,2).join('')", False),
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
