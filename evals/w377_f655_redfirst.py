#!/usr/bin/env python3
"""Red-first for F655: env-threaded tail reads after F647/F652 fragments.

Wave-377 lane 4 closed F647 (nullish RIGHT-pick) and F652 (comma-sequence) but
the new term parsers fall back to plain primaries that do not know the local
bindings (env for F652, the declared-uninitialized ident for F647). A fragment
whose assigned ident is read AGAIN in a later tail additive operand evaluates
in node to the credential while the decoder produces zero variants.

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
    # F652 family: sequence assigns x, then a plain-primary tail operand reads x.
    # node yields _F1 + _F2 + _F3 + _F1; decoder knows x only inside the sequence.
    ("f652-tail-read",
     "(function(){var x;return (x='%s',x)+'%s%s'+x;})()" % (_A, _F2, _F3),
     True),
    # F647 family: nullish-LEFT picks RIGHT, then a plain-primary tail reads z
    # (declared, uninitialized -> node yields "undefined" as a string here, so
    # the tail read assembles the credential with the undefined string).
    ("f647-tail-read",
     "(function(){var z;return (z??'%s')+'%s%s'+z;})()" % (_A, _F2, _F3),
     True),
]

CONTROLS = [
    # Closed F652 bare shape still blocks (F652 closure intact).
    ("f652-bare-still-blocks",
     "(function(){var x;return (x='%s',x)+'%s%s';})()" % (_A, _F2, _F3), True),
    # Closed F647 bare shape still blocks (F647 closure intact).
    ("f647-bare-still-blocks",
     "(function(){var z;return (z??'%s')+'%s%s';})()" % (_A, _F2, _F3), True),
    # junk-quiet: no credential material anywhere.
    ("junk-quiet",
     "(function(){var x;return (x='jx',x)+'jy'+x;})()", False),
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
