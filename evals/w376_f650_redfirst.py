#!/usr/bin/env python3
"""Red-first for F650: object-spread-assembled enumeration sources.

F510 (CLOSED) models inline plain-literal enumeration sources and F612
(CLOSED) var-bound plain-literal sources, but an object literal assembled
with SPREAD ({...{a:'f1'},...{b:'f2'}}) is a different source production with
no modeled path, inline or var-bound, for values/entries/keys reads.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("spread-varbound-values",
     "(function(){var o={...{a:'%s'},...{b:'%s%s'}};return Object.values(o).join('');})()" % (_F1, _F2, _F3), True),
    ("spread-inline-values",
     "(function(){return Object.values({...{a:'%s'},...{b:'%s%s'}}).join('');})()" % (_F1, _F2, _F3), True),
    ("spread-varbound-entries",
     "(function(){var o={...{a:'%s'},...{b:'%s%s'}};return Object.entries(o).map(function(e){return e[1];}).join('');})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f510-plain-inline-still-blocks",
     "(function(){return Object.values({a:'%s',b:'%s%s'}).join('');})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var o={...{a:'jx'}};return Object.values(o).join('');})()", False),
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
