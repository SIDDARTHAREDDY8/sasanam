#!/usr/bin/env python3
"""Red-first for F829: prototype method returning a this-bound member.

F823 (CLOSED wave-386 lane 14) models prototype methods with literal
returns, but a method whose body reads a constructor-bound member
(`C.prototype.m=function(){return this.x;}`) dispatches node-exactly
while the decoder produces zero variants.
Filed 2026-10-09 wave-386 lane 14 (local node validation, no model calls).
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
     "(function(){function C(x){this.x=x;}C.prototype.m=function()"
     "{return this.x;};return new C('%s').m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){function C(x){this.x=x;}C.prototype.m=function()"
     "{return this.x;};var o=new C('%s');return o['m']()+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    # literal-return hybrid blocks (F823 closed)
    ("f823-closed-blocks",
     "(function(){function C(x){this.x=x;}C.prototype.m=function()"
     "{return '%s';};return new C('%s').m()+'%s';})()" % (_A, _A, _B),
     True),
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
