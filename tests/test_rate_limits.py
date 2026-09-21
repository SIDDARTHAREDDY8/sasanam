"""Red-team tests: T9 (rate/loop abuse), R10 (rate/volume/loop guards).

Threat: no budgets on outbound sends, writes, or repeated identical calls
(worming, cascading runaway). OWASP LLM10, ASI08.

Every test here FAILS on the current code: each asserts a guard that does
not exist, demonstrating the vulnerability as an assertion failure.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)


class RateLimitBase(unittest.TestCase):
    def denied_count(self, run, tool, n, **kwargs):
        ident = run["identities"]["support"]
        denied = 0
        for i in range(n):
            kw = dict(kwargs)
            for k, v in kw.items():
                if isinstance(v, str) and "{i}" in v:
                    kw[k] = v.format(i=i)
            res = run["executor"].call(ident, tool, **kw)
            if res["status"] == "denied":
                denied += 1
        return denied


class TestOutboundSendCap(RateLimitBase):
    """T9/R10: per-run cap on outbound sends. 25 send_email calls in one
    run must trip the cap (deny, or at minimum queue-with-budget)."""

    def test_send_email_per_run_cap(self):
        run = make_run()
        denied = self.denied_count(run, "send_email", 25,
                                   to="u{i}@example.com", subject="s", body="b")
        self.assertGreater(
            denied, 0,
            "T9/R10: 25 outbound sends in one run, NONE denied "
            "(no per-run send budget)",
        )


class TestLoopGuard(RateLimitBase):
    """T9/R10: loop guard - the same tool with identical args N times
    must be denied (worming / runaway loop shape)."""

    def test_identical_api_call_loop_guard(self):
        run = make_run()
        denied = self.denied_count(run, "api_call", 15,
                                   endpoint="/v1/data", params={"q": "same"})
        self.assertGreater(
            denied, 0,
            "T9/R10: 15 identical api_call invocations, NONE denied "
            "(no loop guard)",
        )


class TestWriteVolumeGuard(RateLimitBase):
    """T9/R10: volume guard on writes. 30 rapid write_file calls in one
    run must engage a volume guard."""

    def test_write_volume_guard(self):
        run = make_run()
        denied = self.denied_count(run, "write_file", 30,
                                   path="f{i}.txt", content="x")
        self.assertGreater(
            denied, 0,
            "T9/R10: 30 rapid write_file calls in one run, NONE denied "
            "(no write volume guard)",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
