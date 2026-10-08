#!/usr/bin/env python3
"""Red-first for F652: comma/sequence expressions in additive position.

The decoder models || and && in the additive grammar, but the comma
operator -- evaluating each operand left-to-right and taking the last -- has
no modeled path: (x='f1',x) evaluates to the bound fragment and the sequence
is invisible to the static parse.
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
    ("comma-assign-read",
     "(function(){var x;return (x='%s',x)+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("comma-multi",
     "(function(){var x,y;return (x='%s',y='%s%s',x+y);})()" % (_F1, _F2, _F3), True),
    ("comma-nested-additive",
     "(function(){var x,y;return ((x='%s',x)+(y='%s%s',y));})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("and-additive-still-blocks",
     "(function(){return ('%s'+'%s%s')&&('%s'+'%s%s');})()" % (_F1, _F2, _F3, _F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var x;return (x='jx',x)+'jy';})()", False),
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
