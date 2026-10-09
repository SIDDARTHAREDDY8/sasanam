#!/usr/bin/env python3
"""Red-first for F826: braced if(BOOL) consequents in labeled blocks.

F784 (CLOSED wave-385 lane 12) models `if(BOOL)break LBL;` with a bare
consequent, but a braced consequent `if(1){break lbl;}` resolves
node-exactly (v24.20.0) while the decoder produces zero variants.
Filed 2026-10-09 03:43 UTC wave-385 lane 12 (renumbered F795->F826 at the
wave-385 merge; wave-272 rule, attack round 53 filed F795 first 03:25 UTC).
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
     "(function(){var r='';lbl:{r+='%s';if(1){break lbl;}r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var r='';lbl:{r+='%s';if(0){break lbl;}r+='xx';}return r+'%s';})()" % (_A, _B),
     True),
    ("s3",
     "(function(){var r='';lbl:{if(1){r+='%s';}r+='%s';}return r;})()" % (_A, _B),
     True),
    ("s4",
     "(function(){var r='';lbl:{if(1){r+='%s';r+='%s';break lbl;}r+='xx';}return r;})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("bare-twin-blocks",
     "(function(){var r='';lbl:{r+='%s';if(1)break lbl;r+='xx';}return r+'%s';})()" % (_A, _B),
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
