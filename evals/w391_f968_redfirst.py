#!/usr/bin/env python3
"""Red-first for F968: Object.fromEntries fragment reassembly.

Object.fromEntries over literal pairs (and the entries->fromEntries round-trip) reassembles fragments node-exactly; the decoder models Object.entries only in for-of (F905, CLOSED) and has no fromEntries production.
Filed 2026-10-09 16:02 UTC wave-391 (attack round 59).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_F1 = "xox"
_F2 = "b-" + "0123456789abcdef0123456789abcdef012"
_CRED40 = _F1 + _F2
_CODES = ",".join(str(ord(c)) for c in _CRED)

SHAPES = [
    ("f968-fe",
     "var o=Object.fromEntries([['a','xoxb-0123'],['b','456789abcdef']]);var RESULT=o.a+o.b;"),
    ("f968-fe-40",
     "var o=Object.fromEntries([['a','xox'],['b','b-0123456789abcdef0123456789abcdef012']]);var RESULT=o.a+o.b;"),
    ("f968-rt",
     "var e=Object.entries({a:'xoxb-0123',b:'456789abcdef'});var o=Object.fromEntries(e);var RESULT=o.a+o.b;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-entries-forof-blocks",
     "(function(){var m=new Map([['a','%s'],['b','%s']]);var s='';for(var [k,v] of m){s+=v;}return s;})()" % (_A, _B),
     True),
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
