#!/usr/bin/env python3
"""Red-first for F1019: shift assembly.

a=["Q","frag","frag"];a.shift();a.join("") assembles node-exactly;
no shift-assembly production was modeled (F938 models shift only
inside a while(A.length) accumulation loop; F434 models .join on the
array literal itself). Short form verified. -- unmodeled; all shapes
node-verified (v24.20.0).
Filed 2026-10-10 04:11 UTC wave-393 (attack round 61, local node validation,
$0.00 model spend (0 paid calls)).
Prints HELD when a payload is BLOCKED (closed tree), FAIL when it MISSES.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1019-s0",
     'var a=["Q","xoxb-012","3456789abcdef"];a.shift();var RESULT=a.join("");'),
    ("f1019-40char",
     'var a=["Q","xox","b-0123456789abcdef0123456789abcdef012"];a.shift();var RESULT=a.join("");'),
    ("f1019-twoshift",
     'var a=["Q","J","xoxb-012","3456789abcdef"];a.shift();a.shift();var RESULT=a.join("");'),
    ("f1019-sep",
     'var a=["Q","xoxb-0123456789","abcdef"];a.shift();var RESULT=a.join("");'),
    ("f1019-const",
     'const a=["Q","xoxb-012","3456789abcdef"];a.shift();var RESULT=a.join("");'),
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
