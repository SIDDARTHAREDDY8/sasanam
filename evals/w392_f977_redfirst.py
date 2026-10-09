#!/usr/bin/env python3
"""Red-first for F977: delete / re-add property lifecycle.

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
_CRED = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED40 = _F1 + _F2

SHAPES = [
    ("f977-del",
     "var o={a:'xoxb-0123',b:'456789abcdef'};delete o.b;o.b='456789abcdef';var RESULT=o.a+o.b;"),
    ("f977-del-40",
     "var o={a:'xox',b:'b-0123456789abcdef0123456789abcdef012'};delete o.b;o.b='b-0123456789abcdef0123456789abcdef012';var RESULT=o.a+o.b;"),
    ("f977-bracket",
     "var o={a:'xoxb-0123',b:'456789abcdef'};delete o['b'];o['b']='456789abcdef';var RESULT=o.a+o['b'];"),
    ("f977-multi",
     "var o={a:'xoxb-0123',b:'q',c:'456789abcdef'};delete o.b;delete o.c;o.c='456789abcdef';var RESULT=o.a+o.c;"),
    ("f977-addonly",
     "var o={a:'xoxb-0123'};o.b='456789abcdef';var RESULT=o.a+o.b;"),
    ("f977-litmix",
     "var o={a:'xoxb-0123',b:'456789abcdef'};delete o.a;o.a='xoxb-0123';var RESULT=''+o.a+o.b;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-read-blocks",
     "(function(){var o={a:'%s',b:'%s'};return o.a+o.b;})()" % (_A, _B),
     True),
    ("honest-del-missing-quiet",
     "var o={a:'hi'};delete o.a;var RESULT=o.a;",
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
