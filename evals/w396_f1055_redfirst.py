#!/usr/bin/env python3
"""Red-first for F1055: JSON.parse reviver-staged fragment reads.

JSON.parse('{"a":"frag","b":"frag"}',(k,v)=>v) staged fragments read back via
o.a+o.b assemble node-exactly (v24.20.0); the decoder has no JSON.parse-reviver
production (distinct vs F1035 Object.assign staging).
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1055-s0",
     'var o=JSON.parse(\'{"a":"xoxb-01","b":"23456789abcdef"}\',(k,v)=>v);var RESULT=o.a+o.b;'),
    ("f1055-s1-40",
     'var o=JSON.parse(\'{"a":"xox","b":"b-0123456789abcdef0123456789abcdef012"}\',(k,v)=>v);var RESULT=o.a+o.b;'),
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
