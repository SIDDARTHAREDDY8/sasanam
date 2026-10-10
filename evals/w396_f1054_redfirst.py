#!/usr/bin/env python3
"""Red-first for F1054: RegExp match-group fragment assembly.

"k1=frag k2=frag".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/) fragments reassembled
via m.groups.x+m.groups.y (named) or m[1]+m[2] (numbered) assemble node-exactly
(v24.20.0); the decoder's RegExp production covers only .source reads (F993,
CLOSED) -- match-result group reads miss.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1054-s0-named",
     'var m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;'),
    ("f1054-s1-named-40",
     'var m="k1=xox k2=b-0123456789abcdef0123456789abcdef012".match(/k1=(?<x>\\S+)\\sk2=(?<y>\\S+)/);var RESULT=m.groups.x+m.groups.y;'),
    ("f1054-s2-numbered",
     'var m="k1=xoxb-01 k2=23456789abcdef".match(/k1=(\\S+)\\sk2=(\\S+)/);var RESULT=m[1]+m[2];'),
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
