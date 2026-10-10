#!/usr/bin/env python3
"""Red-first for F1048: Error cause-chain reads.

var e=new Error("a",{cause:new Error("b",{cause:"frag"})});var RESULT=e.cause.cause+"frag";
assembles node-exactly (v24.20.0); the decoder's Error production models only the
single-level cause read (AA control: new Error("x",{cause:"frag"}) + e.cause read
blocks coded), so the nested .cause.cause chain misses. Distinct vs F992 (CLOSED:
Error.message reads).
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1048-s0",
     'var e=new Error("a",{cause:new Error("b",{cause:"xoxb-01"})});var RESULT=e.cause.cause+"23456789abcdef";'),
    ("f1048-s1-40",
     'var e=new Error("a",{cause:new Error("b",{cause:"xox"})});var RESULT=e.cause.cause+"b-0123456789abcdef0123456789abcdef012";'),
    ("f1048-s2-named",
     'var inner=new Error("b",{cause:"xoxb-01"});var e=new Error("a",{cause:inner});var RESULT=e.cause.cause+"23456789abcdef";'),
]

CONTROLS = [
    # AA: single-level cause read is modeled -- blocks coded.
    ("aa-single-cause-blocks",
     'var e=new Error("x",{cause:"xoxb-01"});var RESULT=e.cause+"23456789abcdef";', True),
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
