#!/usr/bin/env python3
"""Red-first for F951: Reflect invocation of the String constructor.

Reflect.construct(String,[frag]) and Reflect.apply(String,null,[frag]) coerce node-exactly; F780 models Reflect.construct for this-binding constructors only, F943 models Reflect.apply for fromCharCode anchors only.
Filed 2026-10-09 13:58 UTC wave-390 (attack round 58).
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
_CODES40 = ",".join(str(ord(c)) for c in _CRED40)
_RCODES = ",".join(str(ord(c)) for c in _CRED[::-1])
_RCODES40 = ",".join(str(ord(c)) for c in _CRED40[::-1])
_C1 = ",".join(str(ord(c)) for c in _CRED[1:])

SHAPES = [
    ("construct-string",
     "var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_A, _B)),
    ("construct-string-40",
     "var RESULT=Reflect.construct(String,['%s'])+'%s';" % (_F1, _F2)),
    ("apply-string",
     "var RESULT=Reflect.apply(String,null,['%s'])+'%s';" % (_A, _B)),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()" % (),
     False),
    ("twin-ctor-this-blocks",
     "(function(){function C(x){this.x=x;}var o=Reflect.construct(C,['%s']);return o.x+'%s';})()" % (_A, _B),
     True),
    ("coded-literal-blocks",
     "'%s' + '%s'" % (_A, _B),
     True),]


def main():
    fails = 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD " if hit else "BREAK ") + name)
        if hit:
            fails += 1
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = (hit == expect_block)
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails += 1
    print("%d shapes, %d controls, %d failures" % (len(SHAPES), len(CONTROLS), fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
