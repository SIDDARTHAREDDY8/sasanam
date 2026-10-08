#!/usr/bin/env python3
"""Red-first for F701: getter invocation on object spread: {...o} copies invoke lit

getter invocation on object spread: {...o} copies invoke literal getters node-exactly (v24.20.0); the decoder models spread-copy (F471) as a copy but does not model accessor invocation on spread. Distinct from F664 (descriptor .get() invocation) and F698 (defineProperty-installed accessor .get()).
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
    ("spread-getter",
     "(function(){var o={get x(){return '%s';}};return {...o}.x+'%s';})()" % (_A, _B), True),
    ("spread-two-getters",
     "(function(){var o={get x(){return '%s';},get y(){return '%s';}};var c={...o};return c.x+c.y;})()" % (_A, _B), True)
]

CONTROLS = [
    ("array-join-still-blocks",
     "['xoxb-0123','456789abcdef'].join('')", True),
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
