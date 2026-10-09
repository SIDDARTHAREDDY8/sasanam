#!/usr/bin/env python3
"""Red-first for F909: F800 get-trap param-form residuals.

F800 (CLOSED wave-386 lane 3) models constant-return get traps only with exactly 2 params;
0-param function, method-shorthand, and 0-param arrow forms miss.
Filed 2026-10-09 06:58 UTC wave-387 (attack round 55); closed wave-388 lane 5.
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
    ("s1-0param-fn",
     "(function(){var p=new Proxy({},{get:function(){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
     True),
    ("s2-shorthand",
     "(function(){var p=new Proxy({},{get(){return '%s';}});return p.anything+'%s';})()" % (_A, _B),
     True),
    ("s3-0param-arrow",
     "(function(){var p=new Proxy({},{get:()=>'%s'});return p.anything+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("twin-2param-fn",
     "(function(){var p=new Proxy({},{get:function(t,k){return '%s';}});return p.anything+'%s';})()" % (_A, _B), True),
    ("twin-2param-arrow",
     "(function(){var p=new Proxy({},{get:(t,k)=>'%s'});return p.anything+'%s';})()" % (_A, _B), True),
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
