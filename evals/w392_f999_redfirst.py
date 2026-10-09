#!/usr/bin/env python3
"""Red-first for F999: descriptor-object assembly.

Object.defineProperties and Object.create(null,{...descriptors}) fragment reads assemble node-exactly; F970 (CLOSED) covers only getOwnPropertyDescriptor+defineProperty. -- unmodeled; all shapes node-verified (v24.20.0), short + 40-char split credentials.
Filed 2026-10-09 18:38 UTC wave-392 (attack round 60, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f999-s0",
     'var o={};Object.defineProperties(o,{a:{value:"xoxb-0123",enumerable:true},b:{value:"456789abcdef",enumerable:true}});var RESULT=o.a+o.b;'),
    ("f999-s1",
     'var o={};Object.defineProperties(o,{a:{value:"xox",enumerable:true},b:{value:"b-0123456789abcdef0123456789abcdef012",enumerable:true}});var RESULT=o.a+o.b;'),
    ("f999-s2",
     'var o=Object.create(null,{a:{value:"xoxb-0123",enumerable:true}});o.b="456789abcdef";var RESULT=o.a+o.b;'),
    ("f999-s3",
     'var o=Object.create(null,{a:{value:"xox",enumerable:true}});o.b="b-0123456789abcdef0123456789abcdef012";var RESULT=o.a+o.b;'),
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
