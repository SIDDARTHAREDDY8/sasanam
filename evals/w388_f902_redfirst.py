#!/usr/bin/env python3
"""Red-first for F902: catch binding misses the thrown value.

the decoder models try/catch straight-line flow (try-accum +
catch-accum) and throw-of-concatenation, but a bare throw 'f1'
does not flow into the catch binding when copied to a var.
Filed 2026-10-09 06:58 UTC wave-387 (attack round 55).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 39-char split credentials.)
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
     "(function(){try{throw '%s';}catch(e){return e+'%s';}})()" % (_A, _B),
     True),
    ("s2",
     "(function(){try{throw '%s';}catch(e){var m=e;return m+'%s';}})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("twin-try-accum",
     "(function(){var r='';try{r+='%s';throw 0;}catch(e){r+='%s';}return r;})()" % (_A, _B), True),
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
