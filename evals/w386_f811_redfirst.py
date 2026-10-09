#!/usr/bin/env python3
"""Red-first for F811: computed method names.

F755 (CLOSED, wave-384 lane 9) covers computed getters, but computed
method names {[k](){...}} / {['m'+'2'](){...}} had no production: they
resolve node-exactly (v24.20.0) while the decoder produced zero
variants. Closed by wave-386 lane 9: shorthand methods in
_js_parse_f67x_object (this_bodies-gated) + _js_parse_f811_computed_method_iife
(two-decl computed-key shape); the single-decl additive-key shape
routes via F674.
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
     "(function(){var k='m';var o={[k](){return '%s';}};return o.m()+'%s';})()" % (_A, _B),
     True),
    ("s2",
     "(function(){var o={['m'+'2'](){return '%s';}};return o.m2()+'%s';})()" % (_A, _B),
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
