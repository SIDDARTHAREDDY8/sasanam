#!/usr/bin/env python3
"""Red-first for F451: whitespace-tolerant base64 as the OUTER layer of
a stack does not compose.

gov/dlp.py `_b64_ws_variants` (F449) only emits variants for
credential-shaped decodes (the FP guard), so a ws-b64 outer layer
decoding to non-credential-shaped inner text -- e.g. an inner
contiguous base64 run -- never feeds layer 2, while base64.b64decode
recovers the credential exactly through both layers. The reverse
direction b64(ws-b64) DOES compose (the outer contiguous run decodes
ungated via the long path, the inner ws-run is handled at layer 2).

Found during the wave-350 two-axis code review (spec axis).

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: b64(ws-b64) blocks (this direction composes); contiguous
double-b64 blocks (F439); the plain credential blocks.
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

INNER = base64.b64encode(CRED.encode()).decode()  # contiguous b64
OUTER = base64.b64encode(INNER.encode()).decode()  # b64 of b64
OUTER_WS = OUTER[:20] + " " + OUTER[20:32] + "\n" + OUTER[32:]

# Real-parser ground truth: whitespace ignored, both layers decode.
assert base64.b64decode(OUTER_WS) == INNER.encode(), "test bug"
assert base64.b64decode(INNER) == CRED.encode(), "test bug"

# The composing direction, for the control.
INNER_WS = INNER[:16] + " " + INNER[16:]
OUTER2 = base64.b64encode(INNER_WS.encode()).decode()

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("ws-b64-outer-stack", OUTER_WS, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("b64-ws-b64-inner-stack", OUTER2, True),  # reverse stacks compose
    ("b64-double-contiguous", OUTER, True),  # F439: stacks compose
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
