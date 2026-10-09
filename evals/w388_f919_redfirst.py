#!/usr/bin/env python3
"""Red-first for F919: bare sort() statement form.

F872 (CLOSED wave-387 lane 11) models sort with a constant-zero comparator,
but `var a=['f1','f2'];a.sort();return a[0]+a[1];` resolves node-exactly
while the decoder produces zero variants (the expression-level bare sort()
is modeled; the statement-IIFE form is not).
Filed 2026-10-09 07:21 UTC, wave-387 lane 11 (F872 closure residual probe;
node v24.20.0).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.

Fragment note (s1): the filed s1 instantiates the standard split
fragments ('xoxb-0123'/'456789abcdef'). A bare sort() reorders by
UTF-16 code units, so '456789abcdef' sorts before 'xoxb-0123' and the
node-exact variant is "456789abcdefxoxb-0123" -- which carries no
regex-flaggable credential (the slack rule needs 10+ chars after
'xoxb-'). That arrangement is modeled exactly (see the MODEL checks
below) but cannot flag under any correct implementation. The
attack-relevant arrangement -- fragments ordered so the credential
reassembles post-sort -- is s1b: 'xoxb-0123' sorts before
'zzzzzzzzzzzz', so the variant "xoxb-0123zzzzzzzzzzzz" flags. Both
prove the same closure: the decoder models the bare-sort statement
node-exactly instead of producing zero variants.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential, _js_parse_f872_sortzero_iife  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
_A = "xoxb-" + "0123"
_B = "456789" + "abcdef"
_Z = "zzzzzzzzzzzz"

SHAPES = [
    # Filed s1 structure; fragments arranged so the credential
    # reassembles post-sort (see fragment note above).
    ("s1b-sort-survives",
     "(function(){var a=['%s','%s'];a.sort();return a[0]+a[1];})()" % (_A, _Z),
     True),
    # Filed s2: standard fragments reassemble post-sort.
    ("s2-filed",
     "(function(){var a=['%s','%s'];a.sort();return a[1]+a[0];})()" % (_B, _A),
     True),
]

# Model checks: the filed fragment arrangements are decoded
# node-exactly (no zero-variant gap), even where the resulting
# variant carries no flaggable credential.
MODEL = [
    ("s1-filed-fragments",
     "(function(){var a=['%s','%s'];a.sort();return a[0]+a[1];})()" % (_A, _B),
     "456789abcdefxoxb-0123"),
    ("s2-filed-fragments",
     "(function(){var a=['%s','%s'];a.sort();return a[1]+a[0];})()" % (_B, _A),
     "xoxb-0123456789abcdef"),
]

CONTROLS = [
    # junk-quiet control: no credential at all
    ("junk-quiet",
     "(function(){var a=['ab','cd'];a.sort();return a[0]+a[1];})()",
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
    for name, payload, want_variant in MODEL:
        r = _js_parse_f872_sortzero_iife(
            payload, 0, 0, {"parts": 0, "ops": 0})
        got = r[0] if r else None
        ok = got == want_variant
        print("%s: %s" % (name, "HELD(model-exact)" if ok else "BREAK(model-off)"))
        if ok:
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
