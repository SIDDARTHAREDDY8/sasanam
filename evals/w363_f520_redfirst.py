#!/usr/bin/env python3
"""Red-first for F520: Array.fromAsync dispatch unmodeled.

F508 models the synchronous Array.from with mapper/array-like/Set
sources, but the async sibling Array.fromAsync has no dispatch entry at
all: Array.fromAsync(['f1','f2']).then(a=>a.join('')) node-evaluates
(v24.20.0) to the exact credential while the decoder produces zero
variants. Prints BREAK when a payload MISSES (open tree), HELD when
blocked.
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
    ("fromasync-then",
     "Array.fromAsync(['%s','%s']).then(a=>a.join(''))" % (A1, A2), True),
    ("fromasync-set",
     "Array.fromAsync(new Set(['%s','%s'])).then(a=>a.join(''))" % (A1, A2), True),
]

CONTROLS = [
    ("f508-from-plain-held",
     "Array.from(['%s','%s']).join('')" % (A1, A2), True),
    ("junk-quiet",
     "Array.fromAsync(['ab','cd']).then(a=>a.join(''))", False),
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
