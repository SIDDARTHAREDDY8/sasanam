"""Unit tests for gov/human_approval_contract.py (wave-280 lane 5).

HumanLayer ADAPT (contract shapes only). Synthetic/local, deterministic.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import human_approval_contract as hlc  # noqa: E402


class StakesTests(unittest.TestCase):
    def test_four_tiers(self):
        self.assertEqual(tuple(hlc.STAKES_TIERS),
                         ("low", "medium", "high", "critical"))

    def test_unknown_tier_refused(self):
        with self.assertRaises(ValueError):
            hlc.validate_stakes("cosmic")

    def test_horizons_positive_and_rising(self):
        hs = [hlc.default_wait_horizon(t) for t in hlc.STAKES_TIERS]
        self.assertTrue(all(h > 0 for h in hs))
        self.assertLess(hs[0], hs[-1])

    def test_outcome_vocabulary(self):
        self.assertEqual(tuple(hlc.OUTCOMES),
                         ("approved", "denied", "edited", "timed_out"))

    def test_stakes_risk_bump_monotone(self):
        bumps = [hlc.STAKES_RISK_BUMP[t] for t in hlc.STAKES_TIERS]
        self.assertEqual(len(bumps), 4)
        self.assertTrue(all(b >= 0 for b in bumps),
                        "stakes bump is escalation-only, never negative")
        self.assertEqual(bumps, sorted(bumps))
        self.assertEqual(hlc.STAKES_RISK_BUMP[hlc.STAKES_LOW], 0)
        self.assertGreater(hlc.STAKES_RISK_BUMP[hlc.STAKES_CRITICAL],
                           hlc.STAKES_RISK_BUMP[hlc.STAKES_HIGH])


class NeedTests(unittest.TestCase):
    def test_need_defaults_to_tier_horizon(self):
        need = hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH)
        self.assertEqual(need.wait_timeout_s,
                         hlc.default_wait_horizon(hlc.STAKES_HIGH))
        self.assertEqual(need.channel, "console")

    def test_need_bad_tool_refused(self):
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed("", hlc.STAKES_LOW)
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed(None, hlc.STAKES_LOW)

    def test_need_bad_stakes_refused(self):
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed("x", "cosmic")

    def test_need_bad_channel_refused(self):
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed("x", hlc.STAKES_LOW, channel="")

    def test_need_bad_horizon_refused(self):
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed("x", hlc.STAKES_LOW, wait_timeout_s=-1)
        with self.assertRaises(ValueError):
            hlc.ApprovalNeed("x", hlc.STAKES_LOW,
                             wait_timeout_s=float("inf"))

    def test_human_decision_bad_outcome_refused(self):
        with self.assertRaises(ValueError):
            hlc.HumanDecision("maybe", "abc123")

    def test_check_poll_refuses_bad_values(self):
        for bad in (0, -1, float("nan"), float("inf"), True, "0.2", None):
            with self.assertRaises((TypeError, ValueError),
                                   msg="poll_s=%r" % (bad,)):
                hlc._check_poll(bad)
        self.assertEqual(hlc._check_poll(0.2), 0.2)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        hlc.reset_registry()

    def tearDown(self):
        hlc.reset_registry()

    def test_declare_and_lookup(self):
        need = hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH))
        self.assertIs(hlc.need_for("send_email"), need)
        self.assertTrue(hlc.requires_approval("send_email"))
        self.assertFalse(hlc.requires_approval("read_file"))

    def test_duplicate_refused(self):
        hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_LOW))
        with self.assertRaises(ValueError):
            hlc.declare(hlc.ApprovalNeed("send_email", hlc.STAKES_HIGH))

    def test_declare_wrong_type_refused(self):
        with self.assertRaises(TypeError):
            hlc.declare({"tool": "x"})


if __name__ == "__main__":
    unittest.main()
