#!/usr/bin/env python3
"""Red-first for F1044: for-in enumeration code reads.

var o={0:code,...};for(var k in o){s+=String.fromCharCode(o[k]);} assembles node-exactly; no for-in enumeration production modeled.
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1044-s0",
     'var o={0:120,1:111,2:120,3:98,4:45,5:48,6:49,7:50,8:51,9:52,10:53,11:54,12:55,13:56,14:57,15:97,16:98,17:99,18:100,19:101,20:102};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;'),
    ("f1044-s1",
     'var o={0:120,1:111,2:120,3:98,4:45,5:48,6:49,7:50,8:51,9:52,10:53,11:54,12:55,13:56,14:57,15:97,16:98,17:99,18:100,19:101,20:102,21:48,22:49,23:50,24:51,25:52,26:53,27:54,28:55,29:56,30:57,31:97,32:98,33:99,34:100,35:101,36:102,37:48,38:49,39:50};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;'),
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
