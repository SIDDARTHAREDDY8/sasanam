#!/usr/bin/env python3
"""Red-first for F430: JS string-concatenation obfuscation bypasses DLP.

On the OPEN tree this prints BREAK: the text '"xoxb-abc123" + "def456"'
evaluates to the credential xoxb-abc123def456 in any JS engine, but
gov/dlp.py's decode layer (F2/F8 encodings + F428's alphabet-specific
JSFuck parser) matches no decode layer and find_credential misses it,
while the plain credential blocks coded dlp-slack-token (control).

When F430 closes (decode layer recognizes bounded static
string-concatenation, or refuses obfuscation-shaped runs coded), this
prints HELD.
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov import dlp  # noqa: E402

_CRED = "xoxb-abc123def456"

_CONCAT_SHAPES = [
    '"xoxb-abc123" + "def456"',
    "'xoxb-abc123' + 'def456'",
    '"xoxb-" + "abc123" + "def456"',
    '"xoxb-abc123"+"def456"',
]


def main():
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    control = blocked and rule == "dlp-slack-token"
    print("control plain credential blocks coded dlp-slack-token: %s" % control)
    misses = 0
    for shape in _CONCAT_SHAPES:
        hit = dlp.find_credential("token=" + shape) is not None
        print("concat shape %r -> %s" % (shape, "HIT" if hit else "MISS"))
        misses += 0 if hit else 1
    if control and misses == len(_CONCAT_SHAPES):
        print("BREAK")
        return 0
    print("HELD")
    return 0


if __name__ == "__main__":
    main()
