#!/usr/bin/env python3
"""Red-first for F825: String.fromCharCode with numeric valueOf body.

F794 (CLOSED wave-385 lane 16) models `String.fromCharCode(o)` only
via an own [Symbol.toPrimitive] with a numeric/boolean literal body.
Node (v24.20.0) resolves fromCharCode's argument with ToNumber, whose
ToPrimitive uses hint "number": OrdinaryToPrimitive tries `valueOf`
first, then `toString` -- so `{valueOf:function(){return 120;}}`
node-evaluates to "x" while the decoder produces zero variants
(fail-closed miss). The F794 "hint-dependent" rationale does not apply:
fromCharCode is hint-number always.
Filed 2026-10-09 03:37:15 UTC, wave-385 lane 16 (spec-review residual
of the F794 closure); renumbered F796->F825 at the wave-385 merge
(wave-272 rule: attack round 53 filed F796 first).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
# fromCharCode(120) == 'x'; the tail completes the credential.
_TAIL = "oxb-" + "0123456789abcdef"

SHAPES = [
    ("s1-valueOf",
     "(function(){var o={valueOf:function(){return 120;}};"
     "return String.fromCharCode(o)+'%s';})()" % (_TAIL,),
     True),
    ("s2-toString",
     "(function(){var o={toString:function(){return 120;}};"
     "return String.fromCharCode(o)+'%s';})()" % (_TAIL,),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\\\\\'ab\\\\\\\\';return s;})()'", False),
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
