#!/usr/bin/env python3
"""Red-first for F1072: JSON.parse plain property reads (F1055-adjacent).

F1055 (OPEN) covers JSON.parse with a REVIVER staging fragments. Reading
plain properties off a reviver-less parse --
`JSON.parse('{"a":"f1","b":"f2"}').a+.b` -- assembles node-exactly (v24.20.0)
but is a distinct production (no reviver argument at all). Filed alongside
F1055; the F1055 closure lane should consider subsuming it.
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
    return s[:3], s[3:]


SHAPES = [
    ("f1072-s-plain",
     'var O=JSON.parse(\'{"a":"%s","b":"%s"}\');var RESULT=O.a+O.b;' % _frags(SECRET_S)),
    ("f1072-l-plain",
     'var O=JSON.parse(\'{"a":"%s","b":"%s"}\');var RESULT=O.a+O.b;' % _frags(SECRET_L)),
]

CONTROLS = [
    # The reviver form is F1055's OPEN pin -- it must still MISS here (open),
    # so we assert only junk-quiet as the control.
    ("junk-quiet",
     'var O=JSON.parse(\'{"a":"ab","b":"cd"}\');var RESULT=O.a+O.b;', False),
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
