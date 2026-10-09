#!/usr/bin/env python3
"""Red-first for F974: getter assembly (plain and symbol-keyed).

Object-literal getters (plain and Symbol-keyed) returning fragment concatenations evaluate node-exactly; F917 (CLOSED) covers only mixed literal+bound-identifier computed getter names.
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
    ("f974-plain",
     "var o={a:'xoxb-0123',b:'456789abcdef',get s(){return this.a+this.b;}};var RESULT=o.s;"),
    ("f974-plain-40",
     "var o={a:'xox',b:'b-0123456789abcdef0123456789abcdef012',get s(){return this.a+this.b;}};var RESULT=o.s;"),
    ("f974-sym",
     "var k=Symbol.for('a');var o={};o[k]='xoxb-0123';var r={get s(){return o[k]+'456789abcdef';}};var RESULT=r.s;"),
    ("f974-symnew",
     "var k=Symbol('a');var o={};o[k]='xoxb-0123';var RESULT=o[k]+'456789abcdef';"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-method-blocks",
     "(function(){var o={a:'%s',b:'%s'};return o.a+o.b;})()" % (_A, _B),
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
