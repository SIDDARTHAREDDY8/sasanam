#!/usr/bin/env python3
"""Red-first for F894: with-statement binding residuals.

the decoder models only the bare single-read shape with(o){r=k;} (blocked twin); var declarations inside the with body, compound expressions, multi-reads, nested with, and method calls all miss.
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
     "(function(){var o={k:'%s'};with(o){var q=k;}return q+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var o={k:'%s',j:'%s'};var r='';with(o){r=k+j;}return r;})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("twin-bare-read",
     "(function(){var o={k:'%s'};var r='';with(o){r=k;}return r+'%s';})()" % (_A, _B), True),
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
