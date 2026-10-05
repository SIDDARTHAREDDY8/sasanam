#!/usr/bin/env python3
"""Red-first for F439 (LOW, OPEN): triple-base64 stack exceeds the depth-2
decode composition budget.

_decoded_variants composes decode layers at most 2 deep. A credential
wrapped in three base64 layers decodes only twice, leaving a 52-char
base64 run that no rule matches. A real chain (base64-decode x3)
recovers the credential; double-wrapped still blocks (control).

Prints BREAK on the open tree (verified MISS), HELD once closed.
"""
import base64
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential  # noqa: E402

# Test credential, concatenation-constructed -- never a literal.
_CRED = "xoxb-" + "a1b2c3d4e5f6" + "0718293a4b5c6d7e8f90"  # 37 chars


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def main():
    b1 = _b64(_CRED)          # 52 chars
    b2 = _b64(b1)             # 72 chars
    b3 = _b64(b2)             # 96 chars
    assert _CRED not in b3 and b1 not in b3
    # real-parser roundtrip: three base64 decodes recover the credential
    recovered = base64.b64decode(base64.b64decode(base64.b64decode(b3))).decode()
    roundtrip = (recovered == _CRED)
    miss = find_credential(b3) is None
    # control: double-wrapped still blocks (depth-2 budget covers it)
    double_hit = find_credential(b2) == "dlp-slack-token"
    plain_hit = find_credential(_CRED) == "dlp-slack-token"
    print("F439 triple-b64 miss (BREAK if True):", miss)
    print("real-parser roundtrip recovers credential:", roundtrip)
    print("control double-b64 blocks:", double_hit)
    print("control plain blocks:", plain_hit)
    if miss and roundtrip and double_hit and plain_hit:
        print("BREAK")
    else:
        print("HELD")


if __name__ == "__main__":
    main()
