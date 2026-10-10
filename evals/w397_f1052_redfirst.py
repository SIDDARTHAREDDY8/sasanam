#!/usr/bin/env python3
"""Red-first for F1052 (wave-397 lane 2): Headers value reads.

Filed shapes from w396_f1052_redfirst.py (attack round 64, first-filing
2026-10-10 08:16 UTC). Prints BREAK when a payload MISSES (open tree),
HELD when blocked. Python-subprocess capture only (wave-392 lesson).
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1052-s0",
     'var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});var RESULT=h.get("X-A")+h.get("X-B");'),
    ("f1052-s1-40",
     'var h=new Headers({"X-A":"xox","X-B":"b-0123456789abcdef0123456789abcdef012"});var RESULT=h.get("X-A")+h.get("X-B");'),
    ("f1052-s2-foreach",
     'var h=new Headers({"X-A":"xoxb-01","X-B":"23456789abcdef"});var s="";h.forEach(function(v,k){s+=v;});var RESULT=s;'),
]

CONTROLS = [
    ("aa-plain-literal-blocks",
     'var RESULT="xoxb-0123456789abcdef";', True),
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
