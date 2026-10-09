#!/usr/bin/env python3
"""Red-first for F952 (wave-391 closure lane 1): postfix array transforms on fromCharCode argument arrays.

Unmodeled Array.prototype transforms (.toReversed/.toSorted/.with/.toSpliced)
applied to the code array before .apply defeat the F643/F500 argument grammar.
Filed 2026-10-09 13:58 UTC, wave-390 attack round 58. Prints BREAK when a
payload MISSES (open tree), HELD when blocked. (node v24.20.0 verified;
short + 40-char split credentials.)
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
_RCODES = ",".join(str(ord(c)) for c in _CRED[::-1])
_RCODES40 = ",".join(str(ord(c)) for c in _CRED40[::-1])
_C1 = ",".join(str(ord(c)) for c in _CRED[1:])

SHAPES = [
    ("toreversed",
     "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES,)),
    ("toreversed-40",
     "var RESULT=String.fromCharCode.apply(null,[%s].toReversed());" % (_RCODES40,)),
    ("tosorted-noop",
     "var RESULT=String.fromCharCode.apply(null,[%s].toSorted((a,b)=>0));" % (_CODES,)),
    ("with",
     "var RESULT=String.fromCharCode.apply(null,[0,%s].with(0,120));" % (_C1,)),
    ("tospliced",
     "var RESULT=String.fromCharCode.apply(null,[99,%s].toSpliced(0,1));" % (_CODES,)),]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-plain-apply-blocks",
     "var RESULT=String.fromCharCode.apply(null,[%s]);" % (_CODES,),
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
