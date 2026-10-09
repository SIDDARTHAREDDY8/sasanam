#!/usr/bin/env python3
"""Red-first for F970: property-descriptor assembly (getOwnPropertyDescriptor + defineProperty).

Object.getOwnPropertyDescriptor(o,k).value reads and Object.defineProperty-installed values assemble fragments node-exactly; the decoder has no descriptor production.
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
    ("f970-gopd",
     "var d=Object.getOwnPropertyDescriptor({a:'xoxb-0123'},'a');var RESULT=d.value+'456789abcdef';"),
    ("f970-gopd-40",
     "var d=Object.getOwnPropertyDescriptor({a:'xox'},'a');var RESULT=d.value+'b-0123456789abcdef0123456789abcdef012';"),
    ("f970-defp",
     "var o={};Object.defineProperty(o,'a',{value:'xoxb-0123',enumerable:true});var RESULT=o.a+'456789abcdef';"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-read-blocks",
     "(function(){var o={a:'%s'};return o.a+'%s';})()" % (_A, _B),
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
