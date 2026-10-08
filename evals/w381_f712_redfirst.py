#!/usr/bin/env python3
"""Red-first for F712: var-bound Map iteration reads.

F695 (CLOSED, wave-381 lane 2) models the INLINE bare-Map iteration
protocol (`[...new Map(...)]`, `Array.from(new Map(...))`), and
F589/F600 (CLOSED) model inline `.entries()`/`.keys()` iteration --
but a VAR-BOUND literal Map's iteration reads have no modeled path
(node v24.20.0): `[...m.entries()][0][1]`, `[...m.keys()][0]`,
`[...m.values()][0]`, `Array.from(m)[0][1]`, and
`Array.from(m.entries())[0][1]` over `var m=new Map([[...]])`
all node-evaluate to the exact credential while the decoder
produces zero variants. Distinct from F695 (inline sources),
F589 (inline entries), F600 (inline keys), F669 (var-bound
spread+join consumption).
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
    ("entries-spread-index",
     "(function(){var m=new Map([['k','%s']]);return [...m.entries()][0][1]+'%s';})()" % (_A, _B), True),
    ("keys-spread-index",
     "(function(){var m=new Map([['%s','v']]);return [...m.keys()][0]+'%s';})()" % (_A, _B), True),
    ("values-spread-index",
     "(function(){var m=new Map([['k','%s']]);return [...m.values()][0]+'%s';})()" % (_A, _B), True),
    ("arrayfrom-bare-index",
     "(function(){var m=new Map([['k','%s']]);return Array.from(m)[0][1]+'%s';})()" % (_A, _B), True),
    ("arrayfrom-entries-index",
     "(function(){var m=new Map([['k','%s']]);return Array.from(m.entries())[0][1]+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("array-join-still-blocks",
     "['%s','%s'].join('')" % (_A, _B), True),
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
