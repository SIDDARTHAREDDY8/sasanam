#!/usr/bin/env python3
"""Red-first for F833: braced if(BOOL) consequents in labeled for bodies.

F826 (CLOSED wave-386 lane 16) models braced consequents in labeled BLOCKS
and F827 (CLOSED wave-386 lane 16) models for(;;), but a braced consequent
`if(1){r+='f1';break outer;}` inside a labeled FOR body (counted or
for(;;)) resolves node-exactly (v24.20.0: "f1f2") while the decoder
produces zero variants -- the for-body op parser only accepts bare
`if(BOOL)break/continue` / `if(BOOL)ACCUM;`.
Filed 2026-10-09 05:26 UTC wave-386 lane 16 (shapes repaired 05:38 UTC
per spec review: original s1 was unsatisfiable, s2 hung node).
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
     "(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';if(1){break outer;}r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var r='';outer:for(;;){if(1){r+='%s';break outer;}r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("bare-twin-blocks",
     "(function(){var r='';outer:for(var i=0;i<1;i++){r+='%s';if(1)break outer;}return r+'%s';})()" % (_A, _B),
     True),
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
    for name, payload, recovers in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == recovers
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
