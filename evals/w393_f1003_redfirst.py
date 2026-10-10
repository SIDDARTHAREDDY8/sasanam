#!/usr/bin/env python3
"""Red-first for F1003: comma-sequence assembly (wave-393 lane 5).

`var s;s="f1",s+="f2";var RESULT=s;` -- a statement-position
comma-operator sequence of assignment operands assembles node-exactly
(v24.20.0 verified); no comma-sequence production with assignment
operands is modeled (F982 covers only accumulation/`++`/`--` operands).

Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1003-s0",
     'var s;s="xoxb-0123",s+="456789abcdef";var RESULT=s;'),
    ("f1003-s1",
     'var s;s="xox",s+="b-0123456789abcdef0123456789abcdef012";var RESULT=s;'),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-fcc-blocks",
     'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);',
     True),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
