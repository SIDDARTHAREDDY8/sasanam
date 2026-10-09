#!/usr/bin/env python3
"""Red-first for F974 (residual): symbol-keyed member reads.

The plain getter forms were closed incidentally at the wave-391 merge via
the F949 top-level rewrite + F947 prop-assembly composition. The OPEN
residual is symbol-keyed member reads: Symbol.for / Symbol() bound vars
used as computed keys (o[k] reads/writes, getters reading o[k]).
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

SHAPES = [
    ("f974-sym",
     "var k=Symbol.for('a');var o={};o[k]='%s';var r={get s(){return o[k]+'%s';}};var RESULT=r.s;" % (_A, _B)),
    ("f974-symnew",
     "var k=Symbol('a');var o={};o[k]='%s';var RESULT=o[k]+'%s';" % (_A, _B)),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-getter-blocks",
     "var o={a:'%s',b:'%s',get s(){return this.a+this.b;}};var RESULT=o.s;" % (_A, _B),
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
