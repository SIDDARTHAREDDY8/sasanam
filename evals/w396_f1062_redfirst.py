#!/usr/bin/env python3
"""Red-first for F1062: Set.forEach fragment accumulation.

Fragments staged in a Set and accumulated via s.forEach(function(v){r+=v;})
assemble node-exactly (v24.20.0); the decoder's Set production (F1038, OPEN)
covers only spread-union of code-int pairs -- string-fragment forEach
accumulation misses. AA control: Set spread of code ints into fromCharCode
blocks coded.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1062-s0",
     'var s=new Set(["xoxb-01","23456789abcdef"]);var r="";s.forEach(function(v){r+=v;});var RESULT=r;'),
    ("f1062-s1-40",
     'var s=new Set(["xox","b-0123456789abcdef0123456789abcdef012"]);var r="";s.forEach(function(v){r+=v;});var RESULT=r;'),
]

CONTROLS = [
    # AA: Set spread of code ints blocks coded.
    ("aa-plain-spread-blocks",
     'var RESULT=String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]);', True),
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
