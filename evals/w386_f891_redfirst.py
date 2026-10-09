#!/usr/bin/env python3
"""Red-first for F891: Object.seal literals containing method values.

F812 (CLOSED, wave-386 lane 9) models Object.seal/preventExtensions as
identity builtins over F535 data literals -- but a sealed literal
CONTAINING a shorthand method has no production: the F539 literal
parse (_js_parse_f535_object) fails closed on methods, so even a pure
data read on the sealed object misses; and a method CALL on a sealed
object misses because the F812 sealed IIFE only models member reads.
Both resolve node-exactly (v24.20.0) while the decoder produces zero
variants.
Filed 2026-10-09 05:50:07 UTC by wave-386 lane 9 (spec-review residual
of the F812 closure).
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
    ("s1",
     "(function(){var o=Object.seal({k:'%s',m(){return 'z';}});return o.k+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var o=Object.seal({m(){return '%s';}});return o.m()+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    ("junk-quiet",
     "'(function(){var s=\\\\'ab\\\\';return s;})()'", False),
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
