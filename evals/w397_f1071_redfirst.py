#!/usr/bin/env python3
"""Red-first for F1071: Object.getOwnPropertyNames loop accumulation.

F1044 (CLOSED) models for-in enumeration over int object literals with
fromCharCode reads. Accumulating string fragments via
`for(var k of Object.getOwnPropertyNames(O))S+=O[k]` assembles node-exactly
(v24.20.0) but is a different production -- no getOwnPropertyNames hook
exists.
Filed 2026-10-10 09:55 UTC wave-397 (attack round 65, local node validation,
$0.00 model spend (0 paid calls)). Prints BREAK on the open tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _frags(s):
    return '"%s"' % s[:3], '"%s"' % s[3:]


SHAPES = [
    ("f1071-s-gopn",
     'var O={a:%s,b:%s};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];'
     "var RESULT=S;" % _frags(SECRET_S)),
    ("f1071-l-gopn",
     'var O={a:%s,b:%s};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];'
     "var RESULT=S;" % _frags(SECRET_L)),
]

CONTROLS = [
    ("junk-quiet",
     'var O={a:"ab",b:"cd"};var S="";for(var k of Object.getOwnPropertyNames(O))S+=O[k];'
     "var RESULT=S;", False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("FAIL " if hit else "BREAK ") + name)
        if hit:
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
