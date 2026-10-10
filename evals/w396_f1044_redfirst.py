#!/usr/bin/env python3
"""Red-first for F1044: for-in enumeration code reads.

var o={0:code,...};for(var k in o){s+=String.fromCharCode(o[k]);} assembles
node-exactly (v24.20.0); no for-in enumeration production modeled.
Filed 2026-10-10 06:45 UTC wave-395 (attack round 63, local node validation,
$0.00 model spend (0 paid calls)). Re-verified wave-396 lane 4 with
node-verified generalizations (mixed int/string keys, let decls,
s=s+... form, RESULT additive). All shapes decode to credential-shaped
strings (xoxb-...); the output filter redacts them.
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


def _obj(codes):
    return "{" + ",".join("%d:%d" % (i, c) for i, c in enumerate(codes)) + "}"


SHAPES = [
    ("f1044-s0",
     'var o=%s;var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;' % _obj(CODES)),
    ("f1044-s1",
     'var o=%s;var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;'
     % _obj(CODES + [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99,
                     100, 101, 102, 48, 49, 50])),
    # generalizations (node-verified v24.20.0; all decode credential-shaped)
    ("f1044-g-let",
     'let o=%s;let s="";for(let k in o){s+=String.fromCharCode(o[k]);}let RESULT=s;' % _obj(CODES)),
    ("f1044-g-plusform",
     'var o=%s;var s="";for(var k in o){s=s+String.fromCharCode(o[k]);}var RESULT=s;' % _obj(CODES)),
    ("f1044-g-mixedkeys",
     # string key inserted FIRST still enumerates after integer-index keys:
     # {z:90,0:120,...} -> "xoxb-[credential]Z" (credential-shaped)
     'var o={z:90,%s};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;'
     % ",".join("%d:%d" % (i, c) for i, c in enumerate(CODES))),
    ("f1044-g-strkeys",
     # pure string keys enumerate in insertion order
     'var o={%s};var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT=s;'
     % ",".join('"k%d":%d' % (i, c) for i, c in enumerate(CODES))),
    ("f1044-g-result-additive",
     'var o=%s;var s="";for(var k in o){s+=String.fromCharCode(o[k]);}var RESULT="tok:"+s;' % _obj(CODES)),
]

CONTROLS = [
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
    # for-of over a Map is F989's domain (K[1] reads), not for-in:
    # this shape must stay quiet here (sibling pin -- F989 closed wave-393).
    ("sibling-f989-forof-quiet",
     'var m=new Map([[0,120]]);var s="";for(var v of m.values()){s+=String.fromCharCode(v);}var RESULT=s;',
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
