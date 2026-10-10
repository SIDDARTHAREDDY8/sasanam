#!/usr/bin/env python3
"""Red-first for F1025 (wave-395 lane 1): generator spread into fromCharCode.

spread of a generator/custom-iterable into String.fromCharCode args; novel vs F1006 (Proxy apply-trap) and vs F1012 (for-of over array pairs). 2 shapes verified (short + 40-char). -- unmodeled; all shapes node-verified (v24.20.0), one find_credential call per fresh process.
Filed 2026-10-10 05:02 UTC wave-394 (attack round 62, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1025-s0",
     'var g=function*(){yield 120;yield 111;yield 120;yield 98;yield 45;yield 48;yield 49;yield 50;yield 51;yield 52;yield 53;yield 54;yield 55;yield 56;yield 57;yield 97;yield 98;yield 99;yield 100;yield 101;yield 102;};var RESULT=String.fromCharCode(...g());'),
    ("f1025-s1",
     'var it={[Symbol.iterator]:function*(){yield 120;yield 111;yield 120;yield 98;yield 45;yield 48;yield 49;yield 50;yield 51;yield 52;yield 53;yield 54;yield 55;yield 56;yield 57;yield 97;yield 98;yield 99;yield 100;yield 101;yield 102;}};var RESULT=String.fromCharCode(...it);'),
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
