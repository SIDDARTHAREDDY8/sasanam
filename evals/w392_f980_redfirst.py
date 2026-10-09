#!/usr/bin/env python3
"""Red-first for F980: arguments-object spread into fromCharCode.

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
    ("f980-args",
     "var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';"),
    ("f980-args-40",
     'var RESULT=(function(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50);'),
    ("f980-named",
     "var RESULT=(function f(){return String.fromCharCode(...arguments);})(120,111,120,98,45,48,49,50,51)+'456789abcdef';"),
    ("f980-spaces",
     "var RESULT=(function(){ return String.fromCharCode(...arguments); })(120, 111, 120, 98, 45, 48, 49, 50, 51)+'456789abcdef';"),
    ("f980-hex",
     "var RESULT=(function(){return String.fromCharCode(...arguments);})(0x78,0x6f,0x78,0x62,0x2d,0x30,0x31,0x32,0x33)+'456789abcdef';"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-args-join-blocks",
     "(function(){return [...arguments].join('');})('%s','%s')" % (_A, _B),
     True),
    ("honest-arrow-quiet",
     "(function(){var s='ab';return s;})()",
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
