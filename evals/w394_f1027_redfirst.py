#!/usr/bin/env python3
"""Red-first for F1027: BigInt code ints.

code ints as BigInt literals coerced via Number(); distinct vs F996 (.map(Number) over string arrays) and F1007 (parseInt hex). 2 shapes verified (short + 40-char). -- unmodeled; all shapes node-verified (v24.20.0), one find_credential call per fresh process.
Filed 2026-10-10 05:02 UTC wave-394 (attack round 62, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1027-s0",
     'var s="";for(var b of [120n,111n,120n,98n,45n,48n,49n,50n,51n,52n,53n,54n,55n,56n,57n,97n,98n,99n,100n,101n,102n]){s+=String.fromCharCode(Number(b));}var RESULT=s;'),
    ("f1027-s1",
     'var s="";for(var b of [120n,111n,120n,98n,45n,48n,49n,50n,51n,52n,53n,54n,55n,56n,57n,97n,98n,99n,100n,101n,102n,48n,49n,50n,51n,52n,53n,54n,55n,56n,57n,97n,98n,99n,100n,101n,102n,48n,49n,50n]){s+=String.fromCharCode(Number(b));}var RESULT=s;'),
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
