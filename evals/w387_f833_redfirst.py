#!/usr/bin/env python3
"""Red-first for F833: braced if(BOOL) consequents in labeled for-loop bodies.

F833 (LOW, filed 2026-10-09 05:26 UTC, wave-386 lane 16): F826 (CLOSED)
models braced consequents in labeled BLOCKS and F827 (CLOSED) models
for(;;), but a braced consequent `if(1){break outer;}` inside a labeled
FOR body (counted or for(;;)) resolves node-exactly while the decoder
produces zero variants.
Close-when: the decoder models braced consequents in for bodies
node-exactly (or refuses the laundering coded) such that
find_credential flags them.
Filed shapes verified node-exact on v24.20.0.
Closed 2026-10-09 wave-387 lane 2 (braced-consequent extension of the
F784 labeled-for hook).
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
    ("s1",
     "(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';"
     "if(1){break outer;}r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var r='';outer:for(;;){if(1){r+='%s';break outer;}"
     "r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("bare-twin-blocks",
     "(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';"
     "if(1)break outer;r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'",
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
