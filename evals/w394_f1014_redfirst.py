#!/usr/bin/env python3
"""Red-first for F1014: new Function fragment body (wave-394 lane 3).

new Function("return \\"frag\\"+\\"frag\\"")() assembles node-exactly;
no new-Function production is modeled.
All shapes node-verified (v24.20.0). Short + 40-char split credentials.
Filed 2026-10-10 04:11 UTC (attack round 61).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

_A = "xoxb-" + "012"
_B = "3456789" + "abcdef"
_A40 = "xox"
_B40 = "b-0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("f1014-s0-filed",
     'var RESULT=new Function("return \\"%s\\"+\\"%s\\"")();' % (_A, _B)),
    ("f1014-s1-40char",
     'var RESULT=new Function("return \\"%s\\"+\\"%s\\"")();' % (_A40, _B40)),
    ("f1014-s2-no-new",
     'var RESULT=Function("return \\"%s\\"+\\"%s\\"")();' % (_A, _B)),
    ("f1014-s3-squote-semibody",
     "var RESULT=new Function('return \\'%s\\'+\\'%s\\';')();" % (_A, _B)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
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
