#!/usr/bin/env python3
"""Red-first for F621: Object.assign mutated-target reads.

F593 (CLOSED) models `Object.assign({}, CHAIN)` with member reads on the call result and F605 (CLOSED) generalizes the operand grammar, but a var-bound target mutated by an assign STATEMENT and read back through Object.values/entries escapes: the decoder never models the mutation of the target binding.
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
    ('assign-values',
     "(function(){var t={};Object.assign(t,{a:'%(A1)s',b:'%(A2)s'});return Object.values(t).join('');})()"
     % {"A1": A1, "A2": A2}, True),
    ('assign-entries',
     "(function(){var t={};Object.assign(t,{a:'%(A1)s',b:'%(A2)s'});return Object.entries(t).map(e=>e[1]).join('');})()"
     % {"A1": A1, "A2": A2}, True),
    ('assign-ctor-target',
     "(function(){var t=new Object();Object.assign(t,{a:'%(A1)s',b:'%(A2)s'});return Object.values(t).join('');})()"
     % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ('f605-blocks',
     "(function(){var r={};var m=new WeakMap([[r,{c:'%(A1)s'}]]);return Object.assign({x:1},m.get(r)).c+'%(A2)s';})()"
     % {"A1": A1, "A2": A2}, True),
    ('junk-quiet',
     '"(function(){var s=\'ab\';return s;})()"', False),
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
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
