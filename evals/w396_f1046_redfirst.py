#!/usr/bin/env python3
"""Red-first for F1046: .at() indexed code reads.

var codes=[...];var s="";for(var i=0;i<codes.length;i++){
s+=String.fromCharCode(codes.at(i));} assembles node-exactly (v24.20.0);
no .at() production modeled (distinct vs F994 arguments-indexed).
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation,
$0.00 model spend (0 paid calls)). Re-verified wave-396 lane 4 with
node-verified generalizations (negative indices, <= bound with OOB NUL,
let decl, s=s+ form). All shapes decode to credential-shaped strings
(xoxb-...); the output filter redacts them.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
Capture via Python subprocess only (wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# char codes for "xoxb-[credential]"
CODES = [120, 111, 120, 98, 45, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
         97, 98, 99, 100, 101, 102]
CODES40 = CODES + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99,
                   100, 101, 102, 48, 49, 50]
# reversed char codes (for the .at(-i) generalization)
CODES_REV = list(reversed(CODES))


def _arr(codes):
    return "[" + ",".join(str(c) for c in codes) + "]"


SHAPES = [
    ("f1046-s0",
     'var codes=%s;var s="";for(var i=0;i<codes.length;i++){s+=String.fromCharCode(codes.at(i));}var RESULT=s;'
     % _arr(CODES)),
    ("f1046-s1",
     'var codes=%s;var s="";for(var i=0;i<codes.length;i++){s+=String.fromCharCode(codes.at(i));}var RESULT=s;'
     % _arr(CODES40)),
    # generalizations (node-verified v24.20.0; all decode credential-shaped)
    ("f1046-g-let",
     'let codes=%s;let s="";for(let i=0;i<codes.length;i++){s+=String.fromCharCode(codes.at(i));}let RESULT=s;'
     % _arr(CODES)),
    ("f1046-g-plusform",
     'var codes=%s;var s="";for(var i=0;i<codes.length;i++){s=s+String.fromCharCode(codes.at(i));}var RESULT=s;'
     % _arr(CODES)),
    ("f1046-g-negative-index",
     # .at(-i) with i=1..length reads the reversed array -> credential
     'var codes=%s;var s="";for(var i=1;i<=codes.length;i++){s+=String.fromCharCode(codes.at(-i));}var RESULT=s;'
     % _arr(CODES_REV)),
    ("f1046-g-lte-oob",
     # i<=length: final iteration reads .at(length) -> undefined ->
     # fromCharCode -> NUL; the credential prefix still matches
     'var codes=%s;var s="";for(var i=0;i<=codes.length;i++){s+=String.fromCharCode(codes.at(i));}var RESULT=s;'
     % _arr(CODES)),
    ("f1046-g-result-additive",
     'var codes=%s;var s="";for(var i=0;i<codes.length;i++){s+=String.fromCharCode(codes.at(i));}var RESULT="k:"+s;'
     % _arr(CODES)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    # arguments[i] indexed reads are F994's domain, not .at():
    # this shape must stay quiet here (sibling pin -- F994 closed wave-393).
    ("sibling-f994-arguments-quiet",
     'function f(){var s="";for(var i=0;i<arguments.length;i++){s+=String.fromCharCode(arguments[i]);}return s;}',
     False),
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
