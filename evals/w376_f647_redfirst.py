#!/usr/bin/env python3
"""Red-first for F647: nullish-coalescing RIGHT-pick fragment assembly.

F490 (CLOSED) models (LEFT ?? RIGHT) only when LEFT is a method reference
(provably non-null, so ?? picks LEFT). The other branch -- LEFT nullish so ??
picks RIGHT -- has no modeled path: the credential splits across the ?? and
the literal scan cannot see it. (A whole credential in RIGHT still blocks via
the literal scan; the gap is specifically the split.)
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
    ("nullish-null-left",
     "(function(){return (null??'%s')+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("nullish-void-left",
     "(function(){return (void 0??'%s')+'%s%s';})()" % (_F1, _F2, _F3), True),
    ("nullish-undef-var",
     "(function(){var z;return (z??'%s')+'%s%s';})()" % (_F1, _F2, _F3), True),
]

CONTROLS = [
    ("whole-cred-in-right-blocks",
     "(function(){return (null??'%s%s%s');})()" % (_F1, _F2, _F3), True),
    ("junk-quiet",
     "(function(){return (null??'jx')+'jy';})()", False),
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
