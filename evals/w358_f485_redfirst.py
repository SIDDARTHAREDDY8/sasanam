#!/usr/bin/env python3
"""Red-first for F485: array-literal edge spellings beyond F479's modeled
element classes. F479 models null/undefined/booleans and SINGLE-LEVEL
nested string arrays (holes and deeper nesting documented fail-closed).
The engine is more generous: sparse holes elide in .join(''), a trailing
comma parses fine, and depth-2+ nesting stringifies recursively. All
shapes node-evaluate (v24.20.0) to the exact credential while the
decoder misses. Distinct from F479 (its modeled shapes hold).
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
FCC = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

SHAPES = [
    ("join-hole",
     "['%s',,'%s'].join('')" % (A1, A2), True),
    ("concat-hole",
     "[].concat(['%s',,'%s'],[]).join('')" % (A1, A2), True),
    ("join-trailing-comma",
     "['%s','%s',].join('')" % (A1, A2), True),
    ("join-double-nested",
     "['%s',[['%s']]].join('')" % (A1, A2), True),
    ("join-triple-nested",
     "['%s',[[['%s']]]].join('')" % (A1, A2), True),
]

CONTROLS = [
    ("junk-quiet",
     "['ab',,'cd'].join('')", False),
    ("neighbor-f479-null-held",
     "['%s',null,'%s'].join('')" % (A1, A2), True),
    ("neighbor-f479-nested1-held",
     "[['%s'],['%s']].join('')" % (A1, A2), True),
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
