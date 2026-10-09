#!/usr/bin/env python3
"""Red-first for F978: Array.prototype.splice reassembly.

Filed 2026-10-09 16:02 UTC wave-391 (attack round 59), closed wave-392 lane 3.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("f978-sp",
     "var q=['x','xoxb-0123','y','456789abcdef','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');"),
    ("f978-sp-40",
     "var q=['x','xox','y','b-0123456789abcdef0123456789abcdef012','z'];q.splice(0,1);q.splice(1,1);q.splice(2,1);var RESULT=q.join('');"),
    ("f978-ins",
     "var q=['xoxb-0123'];q.splice(1,0,'456789abcdef');var RESULT=q.join('');"),
    ("f978-ins-multi",
     "var q=['xoxb-0123','x'];q.splice(1,0,'456789abcdef','y');q.splice(2,2);var RESULT=q.join('');"),
    ("f978-join-dq",
     "var q=['xoxb-0123','456789abcdef'];var RESULT=q.join(\"\");"),
    ("f978-neg",
     "var q=['xoxb-0123','pad','456789abcdef'];q.splice(1,1);var RESULT=q.join('');"),
    ("f978-omit",
     "var q=['xoxb-0123','junk1','junk2'];q.splice(1);q.splice(1,0,'456789abcdef');var RESULT=q.join('');"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-join-blocks",
     "['%s','%s'].join('')" % (_A, _B),
     True),
    ("honest-splice-quiet",
     "var q=['a','b'];q.splice(0,1);var RESULT=q.join('');",
     False),
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
