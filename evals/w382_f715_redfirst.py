#!/usr/bin/env python3
"""Red-first for F715: F675 residual: Proxy deleteProperty-trap `{return false;}` body

F675 (CLOSED wave-380 lane 3) models the deleteProperty trap for the no-op `{return true;}` body and the deleting body, but not a `{return false;}` body: the delete fails, the fragment stays in the target, and the decoder produces zero variants. F675 stays CLOSED on its pins; only this body shape is filed.
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
    ("f715-s1",
     "(function(){var t={x:'%s'};var p=new Proxy(t,{deleteProperty:function(tr,pr){return false;}});delete p.x;return t.x+'%s';})()" % (_A, _B), True),
    ("f715-s2",
     "(function(){var t={y:'%s'};var p=new Proxy(t,{deleteProperty:function(a,b){return false;}});delete p['y'];return t.y+'%s';})()" % (_A, _B), True),
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
