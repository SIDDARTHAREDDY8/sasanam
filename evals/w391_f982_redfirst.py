#!/usr/bin/env python3
"""Red-first for F982: F937 loop-form residuals (comma-sequence do-while, for(;;)).

F937 (CLOSED) models for/while/for-of/do-while accumulation; a do-while with comma-sequence body (s+=frag,i++) and the for(;;){...;break;} infinite-loop form miss.
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
    ("f982-comma",
     "var s='',i=0;do{s+='xoxb-0123',i++;}while(i<1);s+='456789abcdef';var RESULT=s;"),
    ("f982-comma-40",
     "var s='',i=0;do{s+='xox',i++;}while(i<1);s+='b-0123456789abcdef0123456789abcdef012';var RESULT=s;"),
    ("f982-forever",
     "var s='';for(;;){s+='xoxb-0123';break;}s+='456789abcdef';var RESULT=s;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-dowhile-blocks",
     "(function(){var s='',i=0;do{s+='%s';i++;}while(i<1);s+='%s';return s;})()" % (_A, _B),
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
