#!/usr/bin/env python3
"""Red-first for F450: the hex minimum-length gate lets hex of short
credentials evade decode entirely.

gov/dlp.py `_HEX_RUN` requires 16 byte-pairs (`(?:[0-9a-fA-F]{2}){16,}`,
32 hex chars) as an FP guard. A credential whose hex form is shorter
is never attempted, while `bytes.fromhex` recovers it exactly.

Same mechanism class as F445 (minimum-length FP guard on an encoded
run) but a different code path (`_HEX_RUN` + hex decode vs `_B64_RUN` +
`_try_b64_decode`): a base64-only F445 fix would not cover it, so it is
filed distinctly and cross-referenced.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: hex of a long credential blocks (the stack composes once the
run is long enough); hex of junk stays quiet (round-trip validation);
the plain credential blocks.
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

SHORT = "xox" + "b-abc12"  # 10 chars -> 20 hex chars, under the 32-char gate
HEX_SHORT = "".join("%02x" % c for c in SHORT.encode())
HEX_LONG = "".join("%02x" % c for c in (CRED + CRED).encode())

# Real-parser ground truth.
assert bytes.fromhex(HEX_SHORT) == SHORT.encode(), "test bug: hex must decode"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("hex-short-credential", HEX_SHORT, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("hex-long-credential", HEX_LONG, True),  # over the gate: blocks
    ("hex-junk", "".join("%02x" % c for c in b"junkjunkjunkjunk"), False),  # no credential: quiet
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
