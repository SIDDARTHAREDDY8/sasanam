#!/usr/bin/env python3
"""Red-first for F1018: Object.setPrototypeOf read.

Object.setPrototypeOf(o,{p:"frag"}); o.p + frag assembles
node-exactly; no setPrototypeOf data-read production was modeled
(F925 installs method protos for calls only, with a bound-name
proto -- not inline-literal data reads in an additive). Short form
verified. -- unmodeled; all shapes node-verified (v24.20.0).
Filed 2026-10-10 04:11 UTC wave-393 (attack round 61, local node validation,
$0.00 model spend (0 paid calls)).
Prints HELD when a payload is BLOCKED (closed tree), FAIL when it MISSES.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1018-s0",
     'var o={};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o.p+"3456789abcdef";'),
    ("f1018-40char",
     'var o={};Object.setPrototypeOf(o,{p:"xox"});var RESULT=o.p+"b-0123456789abcdef0123456789abcdef012";'),
    ("f1018-ownfirst",
     'var o={a:"Q"};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o.a+o.p+"3456789abcdef";'),
    ("f1018-bracket",
     'var o={};Object.setPrototypeOf(o,{p:"xoxb-012"});var RESULT=o["p"]+"3456789abcdef";'),
    ("f1018-multiprop",
     'var o={};Object.setPrototypeOf(o,{x:"1",p:"xoxb-012"});var RESULT=o.p+"3456789abcdef";'),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    ("plain-twin-blocks", 'var RESULT="xoxb-012"+"3456789abcdef";', True),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD " if hit else "FAIL ") + name)
        if not hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
