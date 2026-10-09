#!/usr/bin/env python3
"""Red-first for F947: object-literal property char assembly.

Credential characters stored as individual object-literal properties and
concatenated via member reads resolve node-exactly while the decoder
produces zero variants. No filed finding covers member-read assembly from
object literals.
Filed 2026-10-09 12:34 UTC wave-389 (attack round 57).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_CRED = _A + _B
_CRED40 = "xox" + "b-" + "0123456789abcdef0123456789abcdef012"
_PROPS = ",".join("p%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED))
_PREAD = "+".join("o.p%d" % i for i in range(len(_CRED)))
_PROPS40 = ",".join("q%d:%s" % (i, repr(c)) for i, c in enumerate(_CRED40))
_PREAD40 = "+".join("o.q%d" % i for i in range(len(_CRED40)))

SHAPES = [
    ("s1-prop-asm",
     "(function(){var o={%s};return %s;})()" % (_PROPS, _PREAD)),
    ("s2-40char",
     "(function(){var o={%s};return %s;})()" % (_PROPS40, _PREAD40)),
    # generalization: bracket-string reads (node-identical)
    ("s3-bracket",
     "(function(){var o={%s};return %s;})()" % (
         _PROPS, "+".join("o['p%d']" % i for i in range(len(_CRED))))),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
    ("twin-object-values-blocks",
     "(function(){return Object.values({a:'" + _A + "',b:'" + _B + "'}).join('');})()",
     True),
    # __proto__ keys set the prototype (not an own property): must stay missed
    ("proto-key-misses",
     "(function(){var o={__proto__:'x',p0:'a'};return o.p0;})()",
     False),
]


def main():
    breaks, held = 0, 0
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        is_break = not hit
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
    print("shapes %d BREAK / %d HELD; controls tallied above" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
