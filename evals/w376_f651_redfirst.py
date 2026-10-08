#!/usr/bin/env python3
"""Red-first for F651: Array.prototype.entries()/values()/keys() for-of fragment assembly.

F622 (CLOSED) models Object.keys enumeration and F632 (CLOSED) for-in, but
the Array iterator methods -- .entries()/.values()/.keys() consumed with
for-of -- are a different enumeration production with no modeled path.
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
    ("array-entries-forof",
     "(function(){var s='';for(var _e of ['%s','%s%s'].entries()){s+=_e[1];}return s;})()" % (_F1, _F2, _F3), True),
    ("array-values-forof",
     "(function(){var s='';for(var x of ['%s','%s%s'].values()){s+=x;}return s;})()" % (_F1, _F2, _F3), True),
    ("array-keys-index",
     "(function(){var fr=['%s','%s%s'];var s='';for(var i of fr.keys()){s+=fr[i];}return s;})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f622-objkeys-still-blocks",
     "(function(){var o={a:'%s',b:'%s%s'};var k=Object.keys(o);return o[k[0]]+o[k[1]];})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var s='';for(var x of ['jx','jy'].values()){s+=x;}return s;})()", False),
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
