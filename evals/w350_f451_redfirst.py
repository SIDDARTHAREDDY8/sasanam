#!/usr/bin/env python3
"""Red-first for F451: hex with embedded whitespace evades the
contiguous-run gate.

gov/dlp.py `_HEX_RUN` requires 16 contiguous byte-pairs (32 hex chars),
but `bytes.fromhex` ignores whitespace, so the hex of a (long,
over-the-F450-length-gate) credential with spaces/newlines inserted
decodes exactly in a real parser (verified: fromhex(spaced)==credential)
while the static scanner matches no run. Distinct from F450 (the
minimum-length gate): this payload is over the length gate and still
misses, on contiguity alone. Distinct from F449 (base64 whitespace): a
different code path (`_HEX_RUN` + `_try_hex_decode` vs `_B64_RUN` +
`_try_b64_decode`) -- a base64-only F449 fix would not cover it, so
filed distinctly and cross-referenced (same precedent as F450 vs F445).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: contiguous hex of the same credential blocks (F439 stack);
whitespace-bearing hex junk stays quiet (round-trip validation); plain
credential blocks coded.
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

# Constructed via concatenation: the write path redacts credential literals.
CRED = "xoxb-" + "0123456789abcdef"  # 21 chars -> 42 hex chars
HEX = CRED.encode().hex()
SPACED = HEX[:20] + " " + HEX[20:]
NEWLINED = HEX[:20] + "\n" + HEX[20:]

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("hex-spaced", SPACED, True),
    ("hex-newlined", NEWLINED, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("hex-contiguous", HEX, True),  # over the length gate: blocks
    ("hex-junk-spaced", "deadbeef cafef00d", False),  # no credential: quiet
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
