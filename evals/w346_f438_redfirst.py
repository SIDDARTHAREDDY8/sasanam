#!/usr/bin/env python3
"""Red-first for F438 (LOW, OPEN): HTML-entity + UTF-16 NUL-interleave
composition defeats the decode layers.

Entities separated by NUL bytes each decode in their own single-entity
variant (per-run decode spreads the 8-candidate budget), so the
fully-decoded + NUL-stripped form is unreachable within the depth-2
composition budget. A real chain (html.unescape then NUL-strip) recovers
the credential.

Prints BREAK on the open tree (verified MISS), HELD once closed.
"""
import html
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
_CRED = "xoxb-" + "abc123" + "def456"


def main():
    payload = "".join("&#x%02x;\x00" % b for b in _CRED.encode())
    assert _CRED not in payload  # no plaintext credential
    # real-parser roundtrip: html.unescape decodes every entity at once,
    # then a control-strip recovers the credential
    recovered = html.unescape(payload).replace("\x00", "")
    roundtrip = (recovered == _CRED)
    miss = find_credential(payload) is None
    # control: the fully entity-decoded form blocks coded
    decoded = "".join(chr(b) + "\x00" for b in _CRED.encode())[:-1]
    plain_hit = find_credential(_CRED) == "dlp-slack-token"
    print("F438 entity+NUL-shape miss (BREAK if True):", miss)
    print("real-parser roundtrip recovers credential:", roundtrip)
    print("control plain blocks:", plain_hit)
    if miss and roundtrip and plain_hit:
        print("BREAK")
    else:
        print("HELD")


if __name__ == "__main__":
    main()
