#!/usr/bin/env python3
"""Red-first for F1035: Object.assign-staged code reads.

var o=Object.assign({},{a:[codes]});var RESULT=String.fromCharCode(...o.a); assembles node-exactly; the decoder has no Object.assign staging production (AA control: plain array spread is blocked coded).
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1035-s0",
     'var o=Object.assign({},{a:[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102]});var RESULT=String.fromCharCode(...o.a);'),
    ("f1035-s1",
     'var o=Object.assign({},{a:[120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50]});var RESULT=String.fromCharCode(...o.a);'),
    ("f1035-s2-getter",
     'var o=Object.assign({},{get a(){return [120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102];}});var RESULT=String.fromCharCode(...o.a);'),
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
