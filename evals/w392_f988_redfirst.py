#!/usr/bin/env python3
"""Red-first for F988: property-copy re-add (F977 residual).

F977 (CLOSED) models delete/re-add and literal re-add; `o.b=o.a`
(fragment copy between props) followed by read assembles node-exactly
and misses.

Filed 2026-10-09 19:10 UTC wave-392 lane 3 (Spec-review follow-up).
Prints BREAK when a payload MISSES (open tree), HELD when blocked.
(node v24.20.0 verified; short + 40-char split credentials.)
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/..")

from gov.dlp import find_credential  # noqa: E402

SHAPES = [
    ("f988-copy",
     "var o={a:'xoxb-0123'};o.b=o.a;o.c='456789abcdef';var RESULT=o.b+o.c;"),
    ("f988-copy-40",
     "var o={a:'xox'};o.b=o.a;o.c='b-0123456789abcdef0123456789abcdef012';var RESULT=o.b+o.c;"),
]

CONTROLS = [
    ("junk-quiet",
     "(function(){var s='ab';return s;})()",
     False),
]


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        ok = not hit
        print(("BREAK " if ok else "FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append((name, hit))
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES), len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
