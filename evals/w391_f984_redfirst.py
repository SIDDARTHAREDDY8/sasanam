#!/usr/bin/env python3
"""Red-first for F984: try/catch around statement-scope builtins (F949/F950 composition).

F949 (OPEN) models statement-scope builtins top-level and F950 (OPEN) try/catch value flow; wrapping a statement-scope builtin (structuredClone, generator drain) in try/catch misses -- the combination is unmodeled.
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
    ("f984-try",
     "var s='';try{var o=structuredClone({a:'xoxb-0123',b:'456789abcdef'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;"),
    ("f984-try-40",
     "var s='';try{var o=structuredClone({a:'xox',b:'b-0123456789abcdef0123456789abcdef012'});s=o.a+o.b;}catch(e){s='no';}var RESULT=s;"),
    ("f984-trygen",
     "var s='';try{function*g(){yield 'xoxb-0123';yield '456789abcdef';}for(var p of g()){s+=p;}}catch(e){s='no';}var RESULT=s;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-bare-blocks",
     "(function(){var o=structuredClone({a:'%s',b:'%s'});return o.a+o.b;})()" % (_A, _B),
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
