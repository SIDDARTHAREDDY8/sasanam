#!/usr/bin/env python3
"""Red-first for F1060: defineProperty getter-descriptor fragment reads (F970 residual).

F970 (CLOSED wave-392 lane 1) models defineProperty-installed VALUES and
explicitly fails closed on accessor descriptors; a getter descriptor returning
a fragment (Object.defineProperty(o,"a",{get:function(){return "frag";}})) read
via o.a+"frag" assembles node-exactly (v24.20.0) but misses. AA control: the
value-descriptor twin blocks coded.
Filed 2026-10-10 08:16 UTC wave-397 lane 3 (closure of wave-396 attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1060-s0",
     'var o={};Object.defineProperty(o,"a",{get:function(){return "xoxb-01";}});var RESULT=o.a+"23456789abcdef";'),
    ("f1060-s1-40",
     'var o={};Object.defineProperty(o,"a",{get:function(){return "xox";}});var RESULT=o.a+"b-0123456789abcdef0123456789abcdef012";'),
]

CONTROLS = [
    # AA: value-descriptor form is modeled by F970 -- blocks coded.
    ("aa-value-descriptor-blocks",
     'var o={};Object.defineProperty(o,"a",{value:"xoxb-01"});var RESULT=o.a+"23456789abcdef";', True),
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
