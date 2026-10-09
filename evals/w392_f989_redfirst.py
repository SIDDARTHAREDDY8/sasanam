#!/usr/bin/env python3
"""Red-first for F989: for-of over Map entries.

for(var kv of m){s+=kv[1];} over a Map of fragment pairs assembles node-exactly; F905 (CLOSED) models Object.entries for-of only. -- unmodeled; all shapes node-verified (v24.20.0), short + 40-char split credentials.
Filed 2026-10-09 18:38 UTC wave-392 (attack round 60, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f989-s0",
     'var s="";var m=new Map([["a","xoxb-0123"],["b","456789abcdef"]]);for(var kv of m){s+=kv[1];}var RESULT=s;'),
    ("f989-s1",
     'var s="";var m=new Map([["a","xox"],["b","b-0123456789abcdef0123456789abcdef012"]]);for(var kv of m){s+=kv[1];}var RESULT=s;'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("twin-plain-fcc-blocks", 'var RESULT=String.fromCharCode(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);', True),
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
