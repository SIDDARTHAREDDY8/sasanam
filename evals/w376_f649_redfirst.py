#!/usr/bin/env python3
"""Red-first for F649: structuredClone-sourced enumeration and var-bound member reads.

F536 (CLOSED) models structuredClone deep-copies with INLINE direct member
reads (structuredClone({...}).c+'f2'). Two paths escape: member reads through
a VAR-BOUND intermediate (var o=structuredClone(...); o.a+o.b), and
Object.values()/entries() over structuredClone sources (inline or var-bound).
The F612 var-bound pattern repeats for this source builtin.
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
    ("sclone-varbound-members",
     "(function(){var o=structuredClone({a:'%s',b:'%s%s'});return o.a+o.b;})()" % (_F1, _F2, _F3), True),
    ("sclone-inline-values",
     "(function(){return Object.values(structuredClone({a:'%s',b:'%s%s'})).join('');})()" % (_F1, _F2, _F3), True),
    ("sclone-varbound-values",
     "(function(){var o=structuredClone({a:'%s',b:'%s%s'});return Object.values(o).join('');})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f536-inline-member-still-blocks",
     "(function(){return structuredClone({c:'%s'}).c+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var o=structuredClone({a:'jx'});return o.a;})()", False),
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
