#!/usr/bin/env python3
"""Red-first for F1012: for-of over array pairs (wave-394 lane 2 closure).

for(var kv of [["a","frag"],["b","frag"]])r+=kv[1] assembles node-exactly;
F989 models for-of over Map entries only -- the array-pair for-of is a
distinct production, unmodeled on the open tree. Filed 2026-10-10 04:11 UTC
wave-393 (attack round 61, local node validation, $0.00 model spend
(0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Capture via Python subprocess only (wave-392 lesson).
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1012-s0",
     'var r="";for(var kv of [["a","xoxb-012"],["b","3456789abcdef"]])r+=kv[1];var RESULT=r;'),
    ("f1012-s1-braced",
     'var r="";for(var kv of [["a","xoxb-012"],["b","3456789abcdef"]]){r+=kv[1];}var RESULT=r;'),
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
