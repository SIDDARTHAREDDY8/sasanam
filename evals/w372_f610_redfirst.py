#!/usr/bin/env python3
"""Red-first for F610: base64 runs decoding to credential FRAGMENTS escape
the F445 credential-shape gate.

F445 (CLOSED, wave-349) made the decoder attempt short base64 runs, but a variant is emitted ONLY when the decoded text is credential-shaped. A base64 run decoding to a credential FRAGMENT (e.g. "eG94Yi0wMTIz" -> "xoxb-0123", the first 9 of 25 chars) never becomes a variant, so fragment-then-concatenate assembly is invisible in atob() calls (bare,
var-bound, WeakMap-composed). All three shapes node-evaluate to the exact
credential (v24.20.0) while the decoder produces zero variants. Distinct
from F445 (full-credential base64 runs, CLOSED -- control blocks coded)
and from F500 (String.fromCharCode spread, OPEN -- a different decoding
primitive). Full-credential base64 blocks coded
(controls). Correction: the round-39 battery docstring listed "atob/base64 ... decoder HITS; dead". That note is wrong for fragment forms: re-verified on the wave-371 tree (601ef73f) that fragment base64 inside atob() misses in every probed form (bare call, var-bound, WeakMap-composed). The round-39 probe must have used a full-credential base64 (which does block); the fragment forms all miss.
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
# b64("xoxb-0123") = "eG94Yi0wMTIz" (fragment: first 9 of 25 cred chars).
# b64(full credential) = "eG94Yi0wMTIzNDU2Nzg5YWJjZGVm" -- blocks coded (F445).
A2 = "456789" + "abcdef"
B64_FRAG = "eG94Yi0wMTIz"
B64_FULL = "eG94Yi0wMTIzNDU2Nzg5YWJjZGVm"

SHAPES = [
    ('b64frag-atob',
     '"atob(\'%(B64)s\')+\'%(A2)s\'"'
     % {"B64": B64_FRAG, "A2": A2}, True),
    ('b64frag-atob-varbound',
     '"(function(){var b=atob(\'%(B64)s\');return b+\'%(A2)s\';})()"'
     % {"B64": B64_FRAG, "A2": A2}, True),
    ('b64frag-weakmap-compose',
     '"(function(){var m=new WeakMap();var k={};m.set(k,atob(\'%(B64)s\'));return m.get(k)+\'%(A2)s\';})()"'
     % {"B64": B64_FRAG, "A2": A2}, True),
]

CONTROLS = [
    ('b64full-literal-blocked',
     '"\'%(B64)s\'"'
     % {"B64": B64_FULL}, True),
    ('b64full-atob-blocked',
     '"atob(\'%(B64)s\')"'
     % {"B64": B64_FULL}, True),
    ('junk-quiet',
     '""(function(){var s=\'ab\';return s;})()""'
     % {"A2": A2}, False),
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
        print("%s(control): %s" % (name, "OK" if ok else "CONTROL-FAIL"))
        if ok:
            held += 1
        else:
            breaks += 1
    print("tally: %d BREAK / %d HELD" % (breaks, held))
    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
