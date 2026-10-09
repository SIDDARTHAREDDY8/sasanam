#!/usr/bin/env python3
"""Red-first for F981: pop-based accumulation (F938 residual).

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
    ("f981-pop",
     "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;"),
    ("f981-pop-40",
     "var q=['b-0123456789abcdef0123456789abcdef012','xox'];var s='';while(q.length){s=s+q.pop();}var RESULT=s;"),
    ("f981-prepend",
     "var q=['xoxb-0123','456789abcdef'];var s='';while(q.length){s=q.pop()+s;}var RESULT=s;"),
    ("f981-do",
     "var q=['456789abcdef','xoxb-0123'];var s='';do{s+=q.pop();}while(q.length);var RESULT=s;"),
    ("f981-concat",
     "var q=['456789abcdef','xoxb-0123'];var s='';while(q.length>0){s=s.concat(q.pop());}var RESULT=s;"),
    ("f981-let",
     "let q=['456789abcdef','xoxb-0123'];let s='';while(q.length){s+=q.pop();}var RESULT=s;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-shift-blocks",
     "(function(){var q=['%s','%s'];var s='';while(q.length){s+=q.shift();}return s;})()" % (_A, _B),
     True),
    ("honest-pop-quiet",
     "var q=['a','b'];var s='';while(q.length){s+=q.pop();}var RESULT=s;",
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
