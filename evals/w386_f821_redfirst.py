#!/usr/bin/env python3
"""Red-first for F821: arrow function default parameters.

The decoder models function-declaration defaults (F736), but
arrow-function defaults `(a='f1')=>a` have no production: they
resolve node-exactly while the decoder produces zero variants.

CORRECTION (2026-10-09, wave-386 lane 13): the attack lane's filed
s2 shape `(a,b='xoxb-0123')=>a+b` called as `f('456789abcdef')`
does NOT recover the credential at runtime -- node v24.20.0 yields
'456789abcdefxoxb-0123' (a='456789abcdef', b='xoxb-0123'), which
contains no contiguous credential. The default must sit on the
second param while the first takes the explicit fragment:
`(a,b='456789abcdef')=>a+b` called as `f('xoxb-0123')`. This
red-first uses the node-verified credential-recovering shape; the
F821 finding itself (no arrow-default production) is genuine.

Filed 2026-10-09 03:25 UTC wave-385 attack round 53; shape
corrected 2026-10-09 wave-386 lane 13 (node-verified).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified.)
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
    ("s1-single-default",
     "(function(){var f=(a='%s')=>a;return f()+'%s';})()" % (_A, _B),
     True),
    ("s2-second-param-default",
     "(function(){var f=(a,b='%s')=>a+b;return f('%s');})()" % (_B, _A),
     True),
]

CONTROLS = [
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
