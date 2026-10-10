#!/usr/bin/env python3
"""Red-first for F1040: spread of built-in collection iterators into fromCharCode (wave-396 lane 2).

String.fromCharCode(...m.values()) / (...arr.values()) over built-in
collection iterators assembles node-exactly; distinct production vs
F1025 (generator/custom-[Symbol.iterator] spread) -- no
built-in-iterator production modeled. Filed 2026-10-10 06:45 UTC
wave-395 (attack round 63, local node validation, $0.00 model spend
(0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1040-s0-mapvalues",
     'var m=new Map();[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102].forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());'),
    ("f1040-s1-mapvalues",
     'var m=new Map();[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50].forEach(function(c,i){m.set(i,c);});var RESULT=String.fromCharCode(...m.values());'),
    ("f1040-s2-arrvalues",
     'var RESULT=String.fromCharCode(...[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102].values());'),
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
