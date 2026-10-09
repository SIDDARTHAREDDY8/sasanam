#!/usr/bin/env python3
"""Red-first for F804: arguments indexed reads (wave-386 lane 5).

F524 (CLOSED) covers destructuring from arguments, but indexed
arguments[0]/arguments[1] reads inside a named function declaration
have no production: they resolve node-exactly while the decoder
produces zero variants (v24.20.0 verified).
Filed 2026-10-09 03:25 UTC wave-385 lane 13 (attack round 53).
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
     "(function(){function f(){return arguments[0]+arguments[1];}"
     "return f('%s','%s');})()" % (_A, _B),
     True),
    ("s2",
     "(function(){function f(){var x=arguments[1];return arguments[0]+x;}"
     "return f('%s','%s');})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("f509-anon-held",
     "(function(){return arguments[0]+arguments[1]})('%s','%s')" % (_A, _B),
     True),
    ("f524-anon-held",
     "(function(){const [a,b]=arguments;return a+b})('%s','%s')" % (_A, _B),
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
