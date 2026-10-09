#!/usr/bin/env python3
"""Red-first for F975: class private-field / private-method reads.

Private fields (#x) and private methods (#g()) carrying fragments read node-exactly; the decoder's class productions (F904/F926, CLOSED) model only public members.
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
    ("f975-priv",
     "class C{#x='xoxb-0123';get s(){return this.#x+'456789abcdef';}}var RESULT=new C().s;"),
    ("f975-priv-40",
     "class C{#x='xox';get s(){return this.#x+'b-0123456789abcdef0123456789abcdef012';}}var RESULT=new C().s;"),
    ("f975-pmeth",
     "class C{#g(){return 'xoxb-0123';}get s(){return this.#g()+'456789abcdef';}}var RESULT=new C().s;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-public-field-blocks",
     "(function(){function C(x){this.x=x;}var o=new C('%s');return o.x+'%s';})()" % (_A, _B),
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
