#!/usr/bin/env python3
"""Red-first for F737: Proxy setPrototypeOf-trap fragment writes

The decoder models Proxy set/construct/deleteProperty/getPrototypeOf traps (F675) and ownKeys (F686) but not the setPrototypeOf trap: a trap body writing the fragment to the target, fired by Object.setPrototypeOf, leaves the fragment in the target while the decoder produces zero variants. Distinct from F675 (modeled traps).
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
    ("f713-s1",
     "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tr,pr){tr.__p='%s';return true;}});Object.setPrototypeOf(p,{});return t.__p+'%s';})()" % (_A, _B), True),
    ("f713-s2",
     "(function(){var t={};var p=new Proxy(t,{setPrototypeOf:function(tg,pt){tg['k']='%s';return true;}});Object.setPrototypeOf(p,[]);return t.k+'%s';})()" % (_A, _B), True),
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
