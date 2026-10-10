#!/usr/bin/env python3
"""Red-first for F991: WeakRef deref reads.

new WeakRef({v:frag}).deref().v reads assemble node-exactly; F960 (CLOSED) covers WeakMap.get only. -- unmodeled; all shapes node-verified (v24.20.0), short + 40-char split credentials.
Red-first for F991 (filed 2026-10-09 18:38 UTC, wave-392 attack round 60; closure red-first by wave-393 lane 1), local node validation, $0.00 model spend (0 paid calls).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f991-s0",
     'var w=new WeakRef({v:"xoxb-0123"});var x=new WeakRef({v:"456789abcdef"});var RESULT=w.deref().v+x.deref().v;'),
    ("f991-s1",
     'var w=new WeakRef({v:"xox"});var x=new WeakRef({v:"b-0123456789abcdef0123456789abcdef012"});var RESULT=w.deref().v+x.deref().v;'),
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
