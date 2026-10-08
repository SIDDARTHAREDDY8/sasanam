#!/usr/bin/env python3
"""Red-first for F618: Promise resolution callbacks assemble fragments.

The bounded static JS-expression decoder has no model of promise
resolution: Promise.all/Promise.race values resolved into .then callbacks
(or awaited in an async IIFE) assemble credential fragments invisibly --
the three shapes below all node-evaluate to the exact credential
(v24.20.0; verified via async node drivers) while the decoder produces
zero variants. No existing finding covers promise callbacks; distinct from
F609 (replace-with-function callbacks -- a different builtin).
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
    ("promise-all-then-join",
     "Promise.all([Promise.resolve('" + A1 + "'),Promise.resolve('" + A2 + "')])"
     ".then(a=>a.join(''))", True),
    ("promise-all-destructure",
     "Promise.all([Promise.resolve('" + A1 + "'),Promise.resolve('" + A2 + "')])"
     ".then(([a,b])=>a+b)", True),
    ("promise-race-then",
     "Promise.race([Promise.resolve('" + A1 + "')]).then(v=>v+'" + A2 + "')", True),
]

CONTROLS = [
    ("sync-join-blocked",
     "['" + A1 + "','" + A2 + "'].join('')", True),
    ("junk-quiet",
     "\"(function(){var s='ab';return s;})()\"", False),
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
