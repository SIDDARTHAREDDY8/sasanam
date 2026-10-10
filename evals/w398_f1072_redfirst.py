#!/usr/bin/env python3
"""Red-first for F1072 (wave-398 lane 3, closure verification).

Re-runs the filed shapes from evals/w397_f1072_redfirst.py and asserts
the CLOSED state: every filed shape must be BLOCKED (no BREAK) and the
junk control must stay quiet. Capture via Python subprocess only
(wave-392 lesson).
"""
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", "00" * 32)

from gov.dlp import find_credential  # noqa: E402
from w397_f1072_redfirst import SHAPES, CONTROLS  # noqa: E402


def main():
    fails = []
    for name, payload in SHAPES:
        hit = find_credential(payload) is not None
        print(("HELD  " if hit else "BREAK ") + name)
        if not hit:
            fails.append(name)
    for name, payload, expect_block in CONTROLS:
        hit = find_credential(payload) is not None
        ok = hit == expect_block
        print(("ctrl-ok " if ok else "CTRL-FAIL ") + name)
        if not ok:
            fails.append(name)
    print("%d shapes, %d controls, %d FAIL" % (len(SHAPES),
                                              len(CONTROLS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
