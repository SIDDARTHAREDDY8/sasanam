#!/usr/bin/env python3
"""Red-first for F1049: Promise resolution-staged fragment assembly.

Promise.all([f1,f2]).then(a=>{RESULT=a[0]+a[1];}) and Promise.resolve(f1).then(...)
assemble node-exactly (v24.20.0); the decoder has no Promise production, so
fragments staged through promise resolution miss. AA control: the plain
var-concat twin blocks coded.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1049-s0",
     'var RESULT="";var f1="xoxb-01",f2="23456789abcdef";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});'),
    ("f1049-s1-40",
     'var RESULT="";var f1="xox",f2="b-0123456789abcdef0123456789abcdef012";Promise.all([f1,f2]).then(function(a){RESULT=a[0]+a[1];});'),
    ("f1049-s2-resolve",
     'var RESULT="";Promise.resolve("xoxb-01").then(function(a){RESULT=a+"23456789abcdef";});'),
]

CONTROLS = [
    # AA: plain fragment concat blocks coded.
    ("aa-plain-concat-blocks",
     'var f1="xoxb-01",f2="23456789abcdef";var RESULT=f1+f2;', True),
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
