#!/usr/bin/env python3
"""Red-first for F812: Object wrapper reads.

F539 (CLOSED) models Object.freeze/assign in VALUE position only, and
F548 models Object.create(PROTO[,PROPS]) in VALUE position only: a
var-bound Object.seal literal in an IIFE return additive, and a
var-bound Object.create(null) result mutated by a post-binding
assignment (o.k='lit'), both resolve node-exactly (v24.20.0) while the
decoder produced zero variants. Closed by wave-386 lane 9:
Object.seal/preventExtensions added to _js_parse_f539_object_identity
+ _js_parse_f812_sealed_iife + _js_parse_f812_create_assign_iife.
Filed 2026-10-09 03:25 UTC wave-385 lane 13 (attack round 53).
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
     "(function(){var o=Object.seal({k:'%s'});return o.k+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var o=Object.create(null);o.k='%s';return o.k+'%s';})()" % (_A, _B),
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
