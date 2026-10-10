#!/usr/bin/env python3
"""Red-first for F1007: parseInt hex code ints into fromCharCode.

String.fromCharCode(parseInt('78',16),...) assembles node-exactly; the decoder has no parseInt-radix production. 2 shapes verified (short + 40-char). -- unmodeled; all shapes node-verified (v24.20.0).
Filed 2026-10-10 04:09 UTC wave-393 (attack round 61, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1007-s0",
     "var RESULT=String.fromCharCode(parseInt('78',16),parseInt('6f',16),parseInt('78',16),parseInt('62',16),parseInt('2d',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16));"),
    ("f1007-s1",
     "var RESULT=String.fromCharCode(parseInt('78',16),parseInt('6f',16),parseInt('78',16),parseInt('62',16),parseInt('2d',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16),parseInt('30',16),parseInt('31',16),parseInt('32',16),parseInt('33',16),parseInt('34',16),parseInt('35',16),parseInt('36',16),parseInt('37',16),parseInt('38',16),parseInt('39',16),parseInt('61',16),parseInt('62',16),parseInt('63',16),parseInt('64',16),parseInt('65',16),parseInt('66',16),parseInt('30',16),parseInt('31',16),parseInt('32',16));"),
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
