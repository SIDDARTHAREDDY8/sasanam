#!/usr/bin/env python3
"""Red-first for F449: base64 with embedded whitespace evades the
contiguous-run gate.

gov/dlp.py `_B64_RUN` requires 24 contiguous base64-alphabet chars
(`[A-Za-z0-9+/\\-_]{24,}={0,2}`). Python's `base64.b64decode` ignores
whitespace/newlines, so base64 of a (long, over-the-F445-length-gate)
credential with spaces/newlines inserted decodes exactly in a real
parser but matches no run in the static scanner.

Distinct from F445 (the minimum-length gate): this payload is over the
length gate and still misses, on contiguity alone.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: the same base64 without whitespace blocks (F439 stack);
whitespace-only junk is quiet (round-trip validation); the plain
credential blocks.
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
CRED = A + B
LONG = CRED + CRED  # over the 24-payload-char F445 gate either way

B64 = base64.b64encode(LONG.encode()).decode()
SPACED = B64[:16] + " " + B64[16:32] + "\n" + B64[32:]

# Real-parser ground truth: whitespace is ignored by base64.b64decode.
assert base64.b64decode(SPACED) == LONG.encode(), "test bug: spaced b64 must decode"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("b64-whitespace", SPACED, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("b64-contiguous", B64, True),  # same payload, no whitespace: blocks
    ("b64-whitespace-junk", base64.b64encode(b"junk junk junk").decode().replace("=", "")[:20] + " " + "aGVsbG8=", False),
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
