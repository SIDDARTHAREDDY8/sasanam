#!/usr/bin/env python3
"""Red-first for F732: F675 residual: Proxy getPrototypeOf-trap write body

F675 (CLOSED wave-380 lane 3) models the getPrototypeOf trap for literal-object returns but not a target-write body: the trap writes the fragment to the target when fired, and the decoder produces zero variants. F675 stays CLOSED on its pins; only the write-body shape is filed.
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
    ("f732-s1",
     "(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(tr){tr.__g='%s';return Object.getPrototypeOf(tr);}});Object.getPrototypeOf(p);return t.__g+'%s';})()" % (_A, _B), True),
    ("f732-s2",
     "(function(){var t={};var p=new Proxy(t,{getPrototypeOf:function(x){x['h']='%s';return Object.getPrototypeOf(x);}});Object.getPrototypeOf(p);return t.h+'%s';})()" % (_A, _B), True),
]

CONTROLS = [
    ("plain-concat-still-blocks",
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
