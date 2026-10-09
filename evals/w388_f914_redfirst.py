#!/usr/bin/env python3
"""Red-first for F914: FormData .getAll.

The F860 closure (CLOSED wave-387 lane 8) models .get only: `f.getAll('k')`
resolves node-exactly (array of values, insertion order) while the decoder
produces zero variants. Close-when: the decoder models .getAll node-exactly
(or refuses the laundering coded) such that find_credential flags them,
red-first verified, honest text unaffected; shapes:
(function(){var f=new FormData();f.append('k','f1');return
f.getAll('k').join('')+'f2';})()
Filed 2026-10-09 07:08 UTC wave-387 lane 8 (F860 closure residual).
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
     "(function(){var f=new FormData();f.append('k','%s');"
     "return f.getAll('k').join('')+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var f=new FormData();f.append('k','%s');f.append('k','zz');"
     "return f.getAll('k').join('-')+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("get-twin",
     "(function(){var f=new FormData();f.append('k','%s');"
     "return f.get('k')+'%s';})()" % (_A, _B),
     True),
    ("junk-quiet",
     "(function(){var f=new FormData();f.append('k','ab');"
     "return f.getAll('k').join('');})()",
     False),
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
