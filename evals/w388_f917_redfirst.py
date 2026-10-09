#!/usr/bin/env python3
"""Red-first for F917: mixed literal+bound-identifier computed getter names.

F886 (CLOSED, wave-387 lane 15) covers `get [k]()` (identifier bound in
pre_env) and `get ['m'+'2']()` (pure additive fold), but a MIXED form
`get ['m'+k]()` with k bound to a string literal has no production:
_js_fold_key_expr folds literal-only operands, so the shape resolves
node-exactly while the decoder produces zero variants.
Filed wave-387 lane 15 (closure residual of the F886 work; node v24.20.0).
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
    ("mixed-lit-then-ident",
     "(function(){var k='2';var o={get ['m'+k](){return '%s';}};return o.m2+'%s';})()" % (_A, _B),
     True),
    ("mixed-ident-then-lit",
     "(function(){var k='m';var o={get [k+'2'](){return '%s';}};return o.m2+'%s';})()" % (_A, _B),
     True),
]

CONTROLS = [
    # bound-identifier twin blocks coded (F886)
    ("bound-ident-twin",
     "(function(){var k='m2';var o={get [k](){return '%s';}};return o.m2+'%s';})()" % (_A, _B),
     True),
    # pure-additive twin blocks coded (F886)
    ("pure-additive-twin",
     "(function(){var o={get ['m'+'2'](){return '%s';}};return o.m2+'%s';})()" % (_A, _B),
     True),
    # junk-quiet control: no credential at all
    ("junk-quiet",
     "(function(){var k='2';var o={get ['m'+k](){return 'ab';}};return o.m2+'cd';})()",
     False),
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
