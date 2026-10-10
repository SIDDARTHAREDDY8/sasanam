#!/usr/bin/env python3
"""Red-first for F1050: URLSearchParams fragment reads.

new URLSearchParams({k1:"frag",k2:"frag"}) staged fragments read back via
.get("k1")+.get("k2") (object-init and query-string forms) and via entries()
iteration assemble node-exactly (v24.20.0); the decoder has no URLSearchParams
production. AA control: a single full-credential query value blocks coded.
Filed 2026-10-10 08:16 UTC wave-396 (attack round 64, local node validation, $0.00 model spend (0 paid calls)).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os, sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f1050-s0",
     'var u=new URLSearchParams({k1:"xoxb-01",k2:"23456789abcdef"});var RESULT=u.get("k1")+u.get("k2");'),
    ("f1050-s1-40",
     'var u=new URLSearchParams("k1=xox&k2=b-0123456789abcdef0123456789abcdef012");var RESULT=u.get("k1")+u.get("k2");'),
    ("f1050-s2-entries",
     'var u=new URLSearchParams({k1:"xoxb-01",k2:"23456789abcdef"});var s="";for(var p of u.entries()){s+=p[1];}var RESULT=s;'),
]

CONTROLS = [
    # AA: full credential as one query value blocks coded.
    ("aa-query-literal-blocks",
     'var q="k1=xoxb-0123456789abcdef&k2=z";', True),
    ("junk-quiet", "(function(){var s='ab';return s;})()", False),
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
