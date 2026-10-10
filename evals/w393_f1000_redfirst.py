#!/usr/bin/env python3
"""Red-first for F1000: assignment-operator assembly.

||= / += / member += fragment accumulation assembles node-exactly; no
assignment-operator production is modeled. Filed 2026-10-09 18:38 UTC
wave-392 (attack round 60).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("f1000-logor-plus",
     'var s="";s||="%s";s+="%s";var RESULT=s;' % (_A, _B)),
    ("f1000-logor-plus-40",
     'var s="";s||="%s";s+="%s";var RESULT=s;' % (_F1, _F2)),
    ("f1000-member-plus",
     'var o={v:""};o.v+="%s";o.v+="%s";var RESULT=o.v;' % (_A, _B)),
    ("f1000-member-plus-40",
     'var o={v:""};o.v+="%s";o.v+="%s";var RESULT=o.v;' % (_F1, _F2)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks",
     "var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);",
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
