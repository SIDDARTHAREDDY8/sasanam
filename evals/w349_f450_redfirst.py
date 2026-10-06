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

AMENDMENT at closure (2026-10-06, wave-350 lane 3): the filed
minimized shape used a 10-char test string ("xoxb-abc12", 20 hex
chars). That string is NOT credential-shaped -- the shortest
credential rule needs 15 chars (xox[baprs]- + 10), and the plain
10-char form does not block on the base tree either (verified:
find_credential returns None). The genuine mechanism-class shape is a
15-char credential (30 hex chars, still under the 32-char gate,
credential-shaped, plain form blocks coded). The 10-char shape is kept
as a documented accepted residual: hex of sub-15-char text cannot be
blocked without dropping the credential-shape FP guard, and such text
is the F2 unknown-format residual class, not a bypass of a known
format. The FINDINGS.md F450 entry's close-when explicitly permits the
documented-residual path with the honest short-credential bound.

Prints BREAK when the payload MISSES (open tree), HELD when blocked.
Controls: hex of a long credential blocks (the stack composes once the
run is long enough); hex of junk stays quiet (round-trip validation);
the plain 15-char credential blocks; the 10-char sub-credential
residual stays quiet (documented, not a finding).
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

B15 = "xox" + "b-abc123def4"  # 15 chars: shortest the slack rule matches
assert len(B15) == 15
HEX15 = "".join("%02x" % c for c in B15.encode())
assert len(HEX15) == 30  # under the 32-char _HEX_RUN gate

SHORT10 = "xox" + "b-abc12"  # 10 chars: NOT credential-shaped (residual)
HEX10 = "".join("%02x" % c for c in SHORT10.encode())

HEX_LONG = "".join("%02x" % c for c in (CRED + CRED).encode())

# Real-parser ground truth.
assert bytes.fromhex(HEX15) == B15.encode(), "test bug: hex must decode"
assert bytes.fromhex(HEX10) == SHORT10.encode(), "test bug: hex must decode"

SHAPES = [
    # (name, payload, real-engine-recovers-credential)
    ("hex-short-credential", HEX15, True),
]

CONTROLS = [
    # (name, payload, want_hit)
    ("hex-long-credential", HEX_LONG, True),  # over the gate: blocks
    ("hex-junk", "".join("%02x" % c for c in b"junkjunkjunkjunk"), False),
    ("plain-credential", B15, True),
    # Documented accepted residual (see module docstring): sub-15-char
    # text is not credential-shaped under any deterministic form, so
    # the credential-shape gate keeps it out of the pipeline. Quiet.
    ("hex-subcredential-residual", HEX10, False),
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
