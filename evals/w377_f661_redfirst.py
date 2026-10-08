"""Red-first for F661: comma/sequence expressions in DECLARATION position.

F652 (CLOSED wave-377 lane 4) models comma/sequence expressions in the
additive grammar only. A sequence in a var/let/const initializer --
`var s=('jx','f1')` -- evaluates to the LAST operand node-exactly
(v24.20.0), and the bound variable then participates in additive
fragment assembly, but the declaration-position sequence has no modeled
path: the F652 parser only accepts sequences in additive (return/operand)
position.

Filed at the wave-377 merge (red-first closure audit): the F652 closure
is overstated for this shape -- re-filed as a new finding per the
standing rule, never quietly patched.
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
    ("decl-seq-var",
     "(function(){var s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("decl-seq-let",
     "(function(){let s=('jx','%s');return s+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("decl-seq-multi",
     "(function(){var s=('jx','%s'),t='%s%s';return s+t;})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("f652-additive-still-blocks",
     "(function(){var x;return (x='%s',x)+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){var s=('jx','jy');return s;})()", False),
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
        ok = (hit == want_hit)
        print("%s: %s" % (name, "HELD(control-ok)" if ok else "BREAK(control-bad)"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
