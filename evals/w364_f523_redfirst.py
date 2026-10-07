#!/usr/bin/env python3
"""Red-first for F523: triple-nested bracket member keys on string receivers.

F515 models array-index-folded keys ([['concat'][0]]) on string-literal
receivers and F514 (narrowed) models nested-bracket keys on String-object
receivers, but a THIRD nesting level escapes both: 'f1'[[[['concat'][0]]][0]]('f2')
and String('f1')[[[['concat'][0]]][0]](String('f2')) both node-evaluate
(v24.20.0) to the exact credential while the decoder produces zero
variants. Distinct from F515 (double-nested) and F514 (nested on
String-objects). Prints BREAK when a payload MISSES (open tree), HELD
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
    ("triple-nested-string-literal",
     "'%s'[[[['concat'][0]]][0]]('%s')" % (A1, A2), True),
    ("triple-nested-boxed-string",
     "String('%s')[[[['concat'][0]]][0]](String('%s'))" % (A1, A2), True),
]

CONTROLS = [
    ("f507-single-bracket-held",  # F507 CLOSED
     "''['concat']('%s','%s')" % (A1, A2), True),
    ("f515-double-nested-closed",  # F515 CLOSED wave-364 lane 2 (must now block)
     "'%s'[['concat'][0]]('%s')" % (A1, A2), True),
    ("junk-quiet",
     "'ab'[[[['concat'][0]]][0]]('cd')", False),
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
