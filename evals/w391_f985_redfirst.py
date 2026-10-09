#!/usr/bin/env python3
"""Red-first for F985: charCodeAt inverse reassembly.

Reading char codes back out of a fragment literal via charCodeAt and rebuilding with fromCharCode inverts the modeled direction; unmodeled.
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
    ("f985-cca",
     "var t='xoxb-0123';var c=t.charCodeAt(0);var RESULT=String.fromCharCode(c)+'oxb-0123'+'456789abcdef';"),
    ("f985-cca-40",
     "var t1='xox',t2='b-0123456789abcdef0123456789abcdef012';var s='';for(var i=0;i<t1.length;i++){s+=String.fromCharCode(t1.charCodeAt(i));}for(var j=0;j<t2.length;j++){s+=String.fromCharCode(t2.charCodeAt(j));}var RESULT=s;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-fromcharcode-blocks",
     "String.fromCharCode(%s)" % _CODES,
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
