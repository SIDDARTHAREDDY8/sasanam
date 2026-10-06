#!/usr/bin/env python3
"""Red-first for F444: junk JS-expression prefixes starve the real
expression out of the decode budget.

gov/dlp.py `_decode_layer` enumerates JS-expression matches positionally
(`_JS_EXPR_START.finditer(text)[:_MAX_CANDIDATES]`, 8) and the whole
scan is bounded to 2 decode layers (`_decoded_variants(max_layers=2)`).
Each layer decodes the leftmost junk expressions first, so N attacker
junk JS-expressions ahead of the real one consume the budget: with 3
junk quoted-concat expressions the real `.reduce((a,b)=>a+b)` assembly
(a verified F437 shape) is never decoded in 2 layers, while a real JS
engine (eval: last statement wins) recovers the credential.

Prints BREAK when the real expression MISSES (open tree), HELD when
blocked. Controls pin the non-attack facts: the real reduce alone
blocks; order matters (real-first blocks).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-abc123"
B = "def" + "456"
CRED = A + B

REAL = "['" + A + "','" + B + "'].reduce((a,b)=>a+b)"
JUNK3 = "'j0'+'k0';'j1'+'k1';'j2'+'k2';"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("junk3-then-reduce", JUNK3 + REAL, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("real-reduce-alone", REAL, True),          # must block (F437 shape)
    ("junk3-alone", JUNK3, False),              # no credential: quiet
    ("real-first-then-junk3", REAL + ";" + JUNK3, True),  # order matters
    ("plain-credential", CRED, True),
]


def main():
    breaks, held = 0, 0
    for name, payload, recovers in SHAPES:
        hit = find_credential(payload) is not None
        # BREAK = genuine miss: real engine recovers, scanner misses.
        is_break = recovers and not hit
        print("%s: %s" % (name, "BREAK(miss)" if is_break else "HELD(blocks)"))
        if is_break:
            breaks += 1
        else:
            held += 1
    for name, payload, want_hit in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == want_hit
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
