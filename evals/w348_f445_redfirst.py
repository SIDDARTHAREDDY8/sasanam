#!/usr/bin/env python3
"""Red-first for F445: the base64 minimum-length gate lets base64 of
short credentials evade decode entirely.

gov/dlp.py `_B64_RUN` requires 24+ base64-alphabet chars and
`_try_b64_decode` refuses runs under 24 payload chars (an FP guard
against word-like runs). A credential under ~18 chars base64-encodes
to fewer than 24 payload chars, so its base64 form is never even
attempted -- while a real parser (base64.b64decode) recovers it
exactly. Same 24-char gate exists on `_B32_RUN` (same mechanism class,
not separately filed).

Prints BREAK when the base64 form MISSES (open tree), HELD when
blocked. Controls: plain short credential blocks; base64 of a LONG
credential blocks (the stack composes once the run is long enough);
base64 of junk text stays quiet (round-trip validation).
"""
import base64
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
A = "xox" + "b-abc123"
B = "def" + "456"
CRED = A + B  # 16 chars -> 24 b64 chars with pad, 23 payload chars < 24
B64_SHORT = base64.b64encode(CRED.encode()).decode()

LONG = "xoxb-" + "a" * 40
B64_LONG = base64.b64encode(LONG.encode()).decode()

SHAPES = [
    ("b64-short-credential", B64_SHORT, True),
]

CONTROLS = [
    ("plain-short-credential", CRED, True),
    ("b64-long-credential", B64_LONG, True),   # long run: decodes, blocks
    ("b64-junk-text", base64.b64encode(b"hello world junk").decode(), False),
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
