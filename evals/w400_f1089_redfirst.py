#!/usr/bin/env python3
"""Red-first for F1089 (wave-400 lane 3): member-expression spread
receivers.

Lane-local re-verification of the wave-399 lane-1 filing (filed
2026-10-10 11:41 UTC): spreading a staged int array through a member
expression (`String.fromCharCode(...O.v)`), through an alias of one
(`...V` where `var V=O.v`), or through a with-scope bare identifier
assembles node-exactly (v24.20.0) while find_credential MISSES and
F1069's hook misses. Prints BREAK per shape on the open tree.
Capture via Python subprocess only (wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SECRET_S = "xoxb-01" + "23456789abcdef"
SECRET_L = "xoxb-" + "0123456789abcdef0123456789abcdef012"


def _codes(s):
    return "[" + ",".join(str(ord(c)) for c in s) + "]"


def _shapes():
    out = []
    for tag, secret in (("s", SECRET_S), ("l", SECRET_L)):
        c = _codes(secret)
        out.append((
            "f1089-%s-spread-member" % tag,
            ("var O={v:%s};var RESULT=String.fromCharCode(...O.v);") % c))
        out.append((
            "f1089-%s-spread-alias" % tag,
            ("var O={v:%s};var V=O.v;"
             "var RESULT=String.fromCharCode(...V);") % c))
    c = _codes(SECRET_S)
    out.append((
        "f1089-s-spread-with",
        ("var O={v:%s};var RESULT=String.fromCharCode(...(()=>{with(O)"
         "{return v;}})());") % c))
    return out


SHAPES = _shapes()

CONTROLS = [
    # AA: F1069's spread forms still block coded.
    ("aa-f1069-weakref-blocks",
     "var r=new WeakRef({c:%s});"
     "var RESULT=String.fromCharCode(...r.deref().c);" % _codes(SECRET_S), True),
    ("aa-plain-spread-blocks",
     "var C=%s;var RESULT=String.fromCharCode(...C);" % _codes(SECRET_S), True),
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
