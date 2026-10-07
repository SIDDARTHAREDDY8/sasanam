#!/usr/bin/env python3
"""Red-first for F527: quadruple-nested bracket member keys on string receivers.

F515 models double-nested array-index-folded keys ([['concat'][0]]) on
string-literal receivers and F523 models the triple-nested form
([[['concat'][0]]][0]). A FOURTH nesting level escapes the
triple-specific fold: 'f1'[[[[['concat'][0]]][0]][0]]('f2') and the
boxed-String variant both node-evaluate (v24.20.0) to the exact
credential while the decoder produces zero variants. Distinct from
F523 (triple) and F515 (double) by the same depth argument F523 used
against F515. Prints BREAK when a payload MISSES (open tree), HELD
when blocked.
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
    ("quad-nested-string-literal",
     "'%(A1)s'[[[[['concat'][0]]][0]][0]]('%(A2)s')" % {"A1": A1, "A2": A2}, True),
    ("quad-nested-boxed-string",
     "String('%(A1)s')[[[[['concat'][0]]][0]][0]](String('%(A2)s'))" % {"A1": A1, "A2": A2}, True),
]

CONTROLS = [
    ("f523-triple-closed",  # F523 CLOSED (wave-365 lane 3) -- now blocks coded
     "'%s'[[[['concat'][0]]][0]]('%s')" % (A1, A2), True),
    ("f507-single-bracket-held",  # F507 CLOSED
     "'%s'['concat']('%s')" % (A1, A2), True),
    ("junk-quiet",
     "'ab'[[[[['concat'][0]]][0]][0]]('cd')", False),
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
