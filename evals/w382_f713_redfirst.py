#!/usr/bin/env python3
"""Red-first for F713: F669 residual -- literal-constructed Map spread-join.

F669 (CLOSED, wave-379) models builtin-iterable spread consumption for
`new Map()`+`m.set(...)` tails (`[...m.values()].join('')`) and Set
spreads -- but a LITERAL-constructed Map's spread-join has no modeled
path (node v24.20.0): `(function(){var m=new Map([['k','f1']]);return
[...m.values()].join('')+'f2';})()` and the bare-spread twin
`(function(){var m=new Map([['k','f1']]);return [...m].join('')+'f2';})()`
both node-evaluate to a credential-containing string while the decoder
produces zero variants. Distinct from F669 (set-tail construction)
and F712 (indexed iteration reads, no join).
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

SHAPES = [
    ("values-join",
     "(function(){var m=new Map([['k','%s']]);return [...m.values()].join('')+'%s';})()" % (_A, _B), True),
    ("bare-join",
     "(function(){var m=new Map([['k','%s']]);return [...m].join('')+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("f669-still-blocks",
     "(function(){var m=new Map();m.set('a','%s');m.set('b','%s');return [...m.values()].join('');})()" % (_A, _B), True),
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
