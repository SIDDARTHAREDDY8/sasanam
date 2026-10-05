#!/usr/bin/env python3
"""Red-first for F432/F433: F429-residual escape-transform bypasses.

On the OPEN tree this prints BREAK:

F432 -- sub-threshold single-escape transforms. The F429 decode layer
only attempts a decode when 2+ escapes run consecutively
(_ESC_RUN / _ENTITY_RUN ``{2,}``). A credential with exactly ONE escaped
character -- e.g. ``k=\\u0078oxb-abc123def456`` -- is decoded to the raw
credential by any real JSON/JS parser, but find_credential misses it
while the plain credential blocks coded dlp-slack-token (control).

F433 -- CSS escapes terminated by a non-hex character. Per CSS Syntax
Level 3, ``\\78`` followed by a non-hex char (``o``) decodes to 'x'
with NO trailing space required; the F429 run regex and decoder both
demand the mandatory space (``\\HHHHHH<space>``). So
``k=\\78\\6f\\78\\62-abc123def456`` (4 consecutive CSS escapes,
space-free) decodes to the credential in any CSS parser, but
find_credential misses it while the control blocks.

F432 CLOSED 2026-10-05 wave-345 lane 1 (decode layer widens the
escape gate from 2+ to 1+ escapes): the five F432 shapes now print HIT
and the script prints HELD. The two F433 shapes (space-free CSS
termination) still MISS -- F433 is a separate closure lane; this
script doubles as its red-first until it closes.
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

# (finding, shape, genuine-decode note)
_SHAPES = [
    # F432: single-escape transforms, one per escape class
    ("F432", "k=\\u0078oxb-abc123def456", "JSON \\uXXXX"),
    ("F432", "k=\\x78oxb-abc123def456", "JS \\xXX"),
    ("F432", "k=\\170oxb-abc123def456", "JS octal"),
    ("F432", "k=\\78 oxb-abc123def456", "CSS space-terminated"),
    ("F432", "k=&#x78;oxb-abc123def456", "HTML hex entity"),
    # F433: CSS escapes terminated by non-hex char (no space)
    ("F433", "k=\\78\\6f\\78\\62-abc123def456", "CSS xoxb"),
    ("F433", "k=\\78oxb-abc123def456", "CSS single"),
]


def main():
    blocked, rule = dlp.scan_value("token=" + _CRED)[:2]
    control = blocked and rule == "dlp-slack-token"
    print("control plain credential blocks coded dlp-slack-token: %s"
          % ("PASS" if control else "FAIL"))
    misses = 0
    for finding, shape, note in _SHAPES:
        hit = dlp.find_credential(shape) is not None
        print("%s %-34r (%s) -> %s"
              % (finding, shape, note, "HIT" if hit else "MISS"))
        misses += 0 if hit else 1
    if control and misses == len(_SHAPES):
        print("BREAK")
        return 0
    print("HELD")
    return 0


if __name__ == "__main__":
    main()
