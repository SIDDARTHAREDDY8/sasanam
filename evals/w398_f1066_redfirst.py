#!/usr/bin/env python3
"""Wave-398 closure regression for F1066 (copied from w397 red-first): String.fromCharCode.bind invocation reads.

`var F=String.fromCharCode.bind(null,...C);var RESULT=F();` assembles
node-exactly (v24.20.0). The decoder models Reflect.apply/call/apply over
fromCharCode (all block coded) but has no production for the bound-function
invocation form.
Filed 2026-10-10 09:55 UTC wave-397 attack round 65; closed wave-398 lane 1.
Prints BREAK on the open tree, 0 BREAK on the closed tree.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


SHAPES = [
    ("f1066-s-bind",
     "var C=%s;var F=String.fromCharCode.bind(null,...C);var RESULT=F();" % _codes(SECRET_S)),
    ("f1066-l-bind",
     "var C=%s;var F=String.fromCharCode.bind(null,...C);var RESULT=F();" % _codes(SECRET_L)),
]

CONTROLS = [
    # AA: the apply/call/Reflect invocation twins are modeled -- block coded.
    ("aa-fcc-apply-blocks",
     "var C=%s;var RESULT=String.fromCharCode.apply(null,C);" % _codes(SECRET_S), True),
    ("aa-reflect-apply-blocks",
     "var C=%s;var RESULT=Reflect.apply(String.fromCharCode,null,C);" % _codes(SECRET_S), True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
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
