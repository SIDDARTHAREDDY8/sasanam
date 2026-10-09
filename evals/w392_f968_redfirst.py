#!/usr/bin/env python3
"""Red-first for F968: Object.fromEntries fragment reassembly (F905 residual).

F905 (CLOSED) models Object.entries inside for-of; the merged tree blocks
the literal-pair fromEntries forms via the F949 top-level rewrite + F947
prop-assembly composition (wave-391 merge red-first audit). RESIDUAL OPEN:
the Object.entries -> Object.fromEntries round-trip still breaks.
Filed 2026-10-09 16:02 UTC wave-391 (attack round 59).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Fragments built via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("f968-rt",
     "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;" % (_A, _B)),
    ("f968-rt-40",
     "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;" % (_F1, _F2)),
    ("f968-rt-bracket",
     "var e=Object.entries({a:'%s',b:'%s'});var o=Object.fromEntries(e);var RESULT=o['a']+o['b'];" % (_A, _B)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    # Literal-pair fromEntries now blocks via F949+F947 composition (merge residual).
    ("twin-literal-fe-blocks",
     "var o=Object.fromEntries([['a','%s'],['b','%s']]);var RESULT=o.a+o.b;" % (_A, _B),
     True),
]


def _check(payload, expect_block):
    hit = find_credential(payload) is not None
    return hit == expect_block, hit


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        ok, hit = _check(payload, expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
