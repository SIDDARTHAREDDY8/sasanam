#!/usr/bin/env python3
"""Red-first for F921: Function.prototype.bind partial application.

the decoder has no Function.prototype.bind production: partial application via bind (2-arg, 3-arg chained, and 40-char split forms) resolves node-exactly while the decoder produces zero variants. Same-class: bind with bound thisArg blocks coded (control).
Filed 2026-10-09 11:21 UTC wave-388 (attack round 56).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_L1 = "xox"
_L2 = "b-" + "0123456789abcdef0123456789abcdef012"

SHAPES = [
    ("s1",
     "(function(){function f(a,b){return a+b;}var g=f.bind(null,'%s');return g('%s');})()" % (_A, _B),
     True),
    ("s2-long",
     "(function(){function f(a,b){return a+b;}var g=f.bind(null,'%s');return g('%s');})()" % (_L1, _L2),
     True),
    ("s3-3arg",
     "(function(){function f(a,b,c){return a+b+c;}var g=f.bind(null,'%s','%s');return g('');})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\'ab\\';return s;})()'", False),
    ("twin-direct-call",
     "(function(){function f(a,b){return a+b;}return f('%s','%s');})()" % (_A, _B), True),
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
