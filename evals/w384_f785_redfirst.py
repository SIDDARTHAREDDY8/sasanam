#!/usr/bin/env python3
"""Red-first for F785: F709/F727 residual: boolean-flag while-loop accumulation.

F709 (for-accumulation, CLOSED) and F727 (do-while, CLOSED) cover their loop forms, but boolean-flag while loops miss: while(go){...;go=false;} accumulates node-exactly while the decoder produces zero variants (counter-bounded while(n<1) blocks)
Filed 2026-10-09 00:07 UTC wave-384 lane 13 (attack round 52).
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
     "(function(){var r='';var go=true;while(go){r+='%s';go=false;}return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var r='';var go=!0;while(go){r+='%s';go=false;}return r+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
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
    for name, payload, recovers in CONTROLS:
        hit = find_credential(payload) is not None
        ok = (hit == recovers)
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
