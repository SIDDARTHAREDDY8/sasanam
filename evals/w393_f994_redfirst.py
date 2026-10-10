#!/usr/bin/env python3
"""Red-first for F994: arguments indexed reads.

arguments[0]+arguments[1] inside an IIFE assembles node-exactly (v24.20.0);
F980 covers only String.fromCharCode(...arguments) spread. Prints BREAK
when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f994-s0",
     '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xoxb-0123","456789abcdef");'),
    ("f994-s1",
     '(function(){var RESULT=arguments[0]+arguments[1];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");'),
    # generalizations (all node-verified v24.20.0; all credential-shaped)
    ("f994-g-3args", '(function(){var RESULT=arguments[0]+arguments[2];return RESULT;})("xoxb-0123456789","junk","abcdef");'),
    ("f994-g-single", '(function(){var RESULT=arguments[0];return RESULT;})("xoxb-0123456789abcdef");'),
    ("f994-g-ws", '(function(){var RESULT=arguments[ 0 ]+arguments[ 1 ];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks", 'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);', True),
    ("params-fail-closed", '(function(x){var RESULT=arguments[0];return RESULT;})("ab");', False),
    ("oob-fails-closed", '(function(){var RESULT=arguments[5];return RESULT;})("ab");', False),
    ("length-fails-closed", '(function(){var RESULT=arguments.length;return RESULT;})("ab");', False),
    ("rest-belongs-to-f995", '(function(...a){var RESULT=a[0];return RESULT;})("ab");', False),
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
