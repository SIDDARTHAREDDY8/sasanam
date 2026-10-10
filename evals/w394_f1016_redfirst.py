#!/usr/bin/env python3
"""Red-first for F1016: push assembly (wave-394 lane 3).

a=["frag"];a.push("frag");a.join("") assembles node-exactly;
no push-assembly production is modeled.
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
    ("f1016-s0-filed",
     'var a=["%s"];a.push("%s");var RESULT=a.join("");' % (_A, _B)),
    ("f1016-s1-40char",
     'var a=["%s"];a.push("%s");var RESULT=a.join("");' % (_A40, _B40)),
    ("f1016-s2-multiarg",
     'var a=["%s"];a.push("3456","%s");var RESULT=a.join("");' % (_A, _B[4:])),
    ("f1016-s2b-multipush",
     'var a=["xoxb-"];a.push("012");a.push("%s");var RESULT=a.join("");' % _B),
    ("f1016-s3-sep-noop-push",
     'var a=["xoxb","0123456789abcdef"];a.push();var RESULT=a.join("-");'),
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
