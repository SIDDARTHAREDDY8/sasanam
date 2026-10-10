#!/usr/bin/env python3
"""Red-first for F1063: WeakMap staged-array indexed reads (F1028 residual).

F1028 (CLOSED wave-395 lane 2) models a credential assembled from code ints
staged as a single string via wm.set(k,s) and read back via wm.get(k);
staging a fragment ARRAY and reading wm.get(k)[0]+wm.get(k)[1] assembles
node-exactly (v24.20.0) but misses the hook's grammar. AA control: the
filed F1028 shape blocks coded.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1063-s0",
     'var wm=new WeakMap();var k={};wm.set(k,["xoxb-01","23456789abcdef"]);var RESULT=wm.get(k)[0]+wm.get(k)[1];'),
    ("f1063-s1-40",
     'var wm=new WeakMap();var k={};wm.set(k,["xox","b-0123456789abcdef0123456789abcdef012"]);var RESULT=wm.get(k)[0]+wm.get(k)[1];'),
]

CONTROLS = [
    # AA: F1028's filed shape (single staged string) blocks coded.
    ("aa-f1028-filed-blocks",
     'var wm=new WeakMap();var k={};var parts=[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];var s="";for(var i=0;i<parts.length;i++){s+=String.fromCharCode(parts[i]);}wm.set(k,s);var RESULT=wm.get(k);', True),
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
