#!/usr/bin/env python3
"""Red-first for F1061: Map.get dual-staged fragment reads (F971 residual).

F971 (CLOSED wave-392 lane 2) models a single Map.get read concatenated with a
literal (m.get('a')+'frag'); staging BOTH fragments in the Map and reading
m.get("a")+m.get("b") assembles node-exactly (v24.20.0) but misses the hook's
grammar. AA control: the single-get+literal twin blocks coded.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1061-s0",
     'var m=new Map([["a","xoxb-01"],["b","23456789abcdef"]]);var RESULT=m.get("a")+m.get("b");'),
    ("f1061-s1-40",
     'var m=new Map([["a","xox"],["b","b-0123456789abcdef0123456789abcdef012"]]);var RESULT=m.get("a")+m.get("b");'),
]

CONTROLS = [
    # AA: single-get+literal is modeled by F971 -- blocks coded.
    ("aa-single-get-blocks",
     'var m=new Map([["a","xoxb-01"]]);var RESULT=m.get("a")+"23456789abcdef";', True),
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
