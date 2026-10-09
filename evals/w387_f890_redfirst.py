#!/usr/bin/env python3
"""Red-first for F890: unparenthesized single-param arrow IIFE.

F890 (filed 2026-10-09 05:43:21 UTC, wave-386 lane 1 spec-axis review
residual of the F795 closure; renumbered from F829 at the wave-386
merge): the F795 arrow twin (_js_parse_f795_param_arrow_iife)
requires the parenthesized param list ((PARAMS)=>...), so
`(a=>a)('f1')` -- which node evaluates to 'f1' (v24.20.0) -- misses.

The credential is split across two literals so the raw-text strict
scan cannot fire; only a correct decode materializes the
credential-shaped concatenation. Prints BREAK when a payload MISSES
(open tree), HELD when blocked. The pure identity form
`(a=>a)(A)` is verified at the variant seam (a single literal can
never be credential-shaped without tripping the raw-text scan).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential, _decoded_variants  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"

SHAPES = [
    ("bare-arrow-add",
     "(a=>a+'%s')('%s')" % (_B, _A),
     True),
]

CONTROLS = [
    # parenthesized twin still blocks (F795 closed)
    ("paren-arrow-blocks",
     "((a)=>a+'%s')('%s')" % (_B, _A),
     True),
    # async bare arrow stays unmodeled -> must not decode (fail closed)
    ("async-bare-quiet",
     "(async a=>a)('%s')" % _A,
     False),
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
    # Pure identity form at the variant seam: the decode must
    # materialize the bound literal (open tree: zero variants).
    variants = list(_decoded_variants("(a=>a)('%s')" % _A))
    ident_ok = any(_A in v for v in variants)
    print("bare-arrow-ident: %s (%d variants)"
          % ("HELD(decodes)" if ident_ok else "BREAK(miss)", len(variants)))
    if ident_ok:
        held += 1
    else:
        breaks += 1
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
