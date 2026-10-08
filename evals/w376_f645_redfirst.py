#!/usr/bin/env python3
"""Red-first for F645: function default-parameter fragment assembly.

F612 (CLOSED) documents 'named functions/params' as a fail-closed residual
of its var-binding production, but default parameter values in a no-arg IIFE
are a distinct binding production with no modeled path: the defaults supply
the fragments and the call supplies no arguments.
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
_F1, _F2, _F3 = _A[:5], _A[5:][1:], _B

SHAPES = [
    ("default-params-noarg",
     "(function(s='%s',t='%s%s'){return s+t;})()" % (_F1, _F2, _F3), True),
    ("default-params-undefined",
     "(function(s='%s',t='%s%s'){return s+t;})(undefined,undefined)" % (_F1, _F2, _F3), True),
    ("default-params-destructured",
     "(function({a,b}={a:'%s',b:'%s%s'}){return a+b;})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f612-varbind-still-blocks",
     "(function(){var s='%s';return s+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(s='jx',t='jy'){return s+t;})()", False),
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
