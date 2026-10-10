#!/usr/bin/env python3
"""Red-first for F1033: RegExp replace-callback code mapping.

String.replace with a callback mapping placeholder chars to code ints; no prior replace-callback production modeled. 2 shapes verified (short + 40-char). -- unmodeled; all shapes node-verified (v24.20.0), one find_credential call per fresh process.
Filed 2026-10-10 05:02 UTC wave-394 (attack round 62, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1033-s0",
     'var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var RESULT="#####################".replace(/./g,function(m,i){return String.fromCharCode(codes[i]);});'),
    ("f1033-s1",
     'var codes=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50];var RESULT="########################################".replace(/./g,function(m,i){return String.fromCharCode(codes[i]);});'),
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
