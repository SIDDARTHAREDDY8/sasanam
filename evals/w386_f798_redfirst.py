#!/usr/bin/env python3
"""Red-first for F798: WeakMap/WeakSet multi-binding reads.

the decoder models single-set/single-get WeakMap reads, but two or more bindings miss: WeakMap.get across multiple keys and WeakSet.has-guarded ternaries resolve node-exactly while the decoder produces zero variants (round-52's WeakMap.get BLOCK note holds only for the single-binding shape).
Filed 2026-10-09 03:25 UTC wave-385 lane 13 (attack round 53).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("s1",
     "(function(){var wm=new WeakMap();var k1={},k2={};wm.set(k1,'%s');wm.set(k2,'%s');return wm.get(k1)+wm.get(k2);})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var ws=new WeakSet();var k={};ws.add(k);var x=ws.has(k)?'%s':'zz';return x+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
