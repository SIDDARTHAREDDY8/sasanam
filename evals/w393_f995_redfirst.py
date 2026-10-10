#!/usr/bin/env python3
"""Red-first for F995: rest-parameter indexed reads.

(...a)=>a[0]+a[1] over fragment call args assembles node-exactly (v24.20.0);
no rest-parameter production is modeled. Prints BREAK when a payload
MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f995-s0",
     '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xoxb-0123","456789abcdef");'),
    ("f995-s1",
     '(function(...a){var RESULT=a[0]+a[1];return RESULT;})("xox","b-0123456789abcdef0123456789abcdef012");'),
    # generalizations (all node-verified v24.20.0; all credential-shaped)
    ("f995-g-reorder", '(function(...zz){var RESULT=zz[1]+zz[0];return RESULT;})("abcdef","xoxb-0123456789");'),
    ("f995-g-3", '(function(...a){var RESULT=a[0]+a[1]+a[2];return RESULT;})("xoxb-0123","456789","abcdef");'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks", 'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);', True),
    ("oob-fails-closed", '(function(...a){var RESULT=a[9];return RESULT;})("a");', False),
    ("arguments-name-fails-closed", '(function(...arguments){var RESULT=arguments[0];return RESULT;})("a");', False),
    ("plain-arguments-belongs-to-f994", '(function(){var RESULT=arguments[0];return RESULT;})("ab");', False),
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
