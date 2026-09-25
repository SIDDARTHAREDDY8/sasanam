#!/usr/bin/env python3
"""F171 (red-first): DLP PII scrub must be linear-time in input length.

The pii-email regex backtracks quadratically on long runs of word
characters with no '@' (e.g. a 60KB 'd'*n tool arg): 10KB -> ~0.2s,
60KB -> ~7s, 263KB -> minutes. scrub_pii runs inside executor.call()
BEFORE the F33 byte-cap check (executor.py:5061 scan vs 5282
projection), so an agent-controlled payload burns governor CPU before
the cap can deny it.

RED: test_linear_time_scrub fails on the unfixed scrub_pii
(ratio ~36x for a 6x size increase); passes after the fix.
GREEN also requires: redaction behavior unchanged
(test_redaction_behavior_unchanged).
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gov import dlp  # noqa: E402


def _time_scrub(n):
    text = "d" * n  # no '@': worst case for the email rule
    t = time.perf_counter()
    dlp.scrub_pii(text)
    return time.perf_counter() - t


class TestF171LinearScrub(unittest.TestCase):
    def test_linear_time_scrub(self):
        # warm up the regex machinery once
        _time_scrub(1000)
        small = _time_scrub(10000)
        big = _time_scrub(60000)
        # guard against a near-zero denominator on very fast machines
        small = max(small, 0.005)
        ratio = big / small
        print("\nscrub 10KB: %.3fs, 60KB: %.3fs, ratio: %.1fx" %
              (small, big, ratio))
        # linear scaling: 6x input -> ~6x time (allow 2x headroom).
        # Quadratic was ~36x.
        self.assertLess(ratio, 12.0,
                        "scrub_pii scales super-linearly (ratio %.1f)" %
                        ratio)

    def test_redaction_behavior_unchanged(self):
        cases = [
            ("ssn 123-45-6789 here", "pii-ssn", "123-45-6789"),
            ("mail me at bob@example.com ok", "pii-email",
             "bob@example.com"),
            ("call (415) 555-2671 now", "pii-phone", "(415) 555-2671"),
            ("card 4111111111111111 x", "pii-card", "4111111111111111"),
            ("nothing sensitive at all", None, None),
            ("d" * 60000, None, None),  # no PII, no '@', no digits
        ]
        for text, expect, secret in cases:
            redacted, hits = dlp.scrub_pii(text)
            if expect is None:
                self.assertEqual(hits, [], text[:40])
                self.assertEqual(redacted, text)
            else:
                self.assertIn(expect, hits, text[:40])
                self.assertNotIn(secret, redacted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
