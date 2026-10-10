#!/usr/bin/env python3
"""Red-first for F992: Error.message reads.

new Error(frag).message concatenations assemble node-exactly (v24.20.0).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f992-s0",
     'var e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";'),
    ("f992-s1",
     'var e=new Error("xox");var RESULT=e.message+"b-0123456789abcdef0123456789abcdef012";'),
    # generalizations (all node-verified v24.20.0; all credential-shaped)
    ("f992-g-let", 'let e=new Error("xoxb-0123");var RESULT=e.message+"456789abcdef";'),
    ("f992-g-bracket", 'var e=new Error("xoxb-0123");var RESULT=e["message"]+"456789abcdef";'),
    ("f992-g-no-new", 'var e=Error("xoxb-0123");var RESULT=e.message+"456789abcdef";'),
    ("f992-g-mixed", 'var e=new Error("xox");var RESULT="xoxb-0123"+e.message+"456789abcdef";'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks", 'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);', True),
    ("wrong-member-quiet", 'var e=new Error("ab");var RESULT=e.msg+"cd";', False),
    ("trailing-stmt-quiet", 'var e=new Error("ab");var RESULT=e.message+"cd";var x=1;', False),
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
