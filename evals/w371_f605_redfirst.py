#!/usr/bin/env python3
"""Red-first for F605: Object.assign neighbor compositions on WeakMap object values.

F593 (wave-371 lane 7, CLOSED) models `Object.assign({}, CHAIN)` where
CHAIN resolves to a _JSObj. Three one-token neighbors node-yield the
exact credential (node v24.20.0) while the decoder produces zero
variants: non-empty assign targets (`Object.assign({x:1}, SRC)`),
swapped args (`Object.assign(SRC, {})`), and extra sources
(`Object.assign({}, SRC, {d:1})`). Distinct from F593 (different
argument shapes, same family -- the F500/F505 precedent).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A1 = "xoxb-" + "0123"
A2 = "456789" + "abcdef"

SHAPES = [
    ("assign-nonempty-target",
     '"(function(){var r={};var m=new WeakMap([[r,{c:\'' + A1 + '\'}]]);'
     'return Object.assign({x:1},m.get(r)).c+\'' + A2 + '\';})()"',
     True),
    ("assign-swapped-args",
     '"(function(){var r={};var m=new WeakMap([[r,{c:\'' + A1 + '\'}]]);'
     'return Object.assign(m.get(r),{}).c+\'' + A2 + '\';})()"',
     True),
    ("assign-extra-source",
     '"(function(){var r={};var m=new WeakMap([[r,{c:\'' + A1 + '\'}]]);'
     'return Object.assign({},m.get(r),{d:1}).c+\'' + A2 + '\';})()"',
     True),
]

CONTROLS = [
    ("f593-assign-blocked",
     '"(function(){var r={};var m=new WeakMap([[r,{c:\'' + A1 + '\'}]]);'
     'return Object.assign({},m.get(r)).c+\'' + A2 + '\';})()"',
     True),
    ("junk-quiet",
     '"(function(){var r={};var m=new WeakMap([[r,{c:\'zz\'}]]);'
     'return Object.assign({x:1},m.get(r)).c+\'yy\';})()"',
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
