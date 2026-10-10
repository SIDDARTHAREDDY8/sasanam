#!/usr/bin/env python3
"""Red-first for F1006: Proxy apply-trap on String.fromCharCode.

new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}}) called with code ints assembles node-exactly; F990 (OPEN) models the get trap only; the existing F542 apply-trap production does not cover this call form. 2 shapes verified (short + 40-char). -- unmodeled; all shapes node-verified (v24.20.0).
Filed 2026-10-10 04:09 UTC wave-393 (attack round 61, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1006-s0",
     'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);'),
    ("f1006-s1",
     'var f=new Proxy(String.fromCharCode,{apply:function(t,th,a){return t.apply(th,a)}});var RESULT=f(120,111,120,98,45,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102,48,49,50);'),
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
