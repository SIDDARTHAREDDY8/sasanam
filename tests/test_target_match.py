"""Unit tests for gov/target_match.py and its wiring seams."""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import target_match  # noqa: E402
from gov import goals  # noqa: E402
from gov.goal_audit import _check_coverage  # noqa: E402


class TargetSimilarityTest(unittest.TestCase):
    def test_exact_is_one(self):
        self.assertEqual(
            target_match.target_similarity("evil.com", "evil.com"), 1.0)

    def test_paraphrase_above_default_threshold(self):
        self.assertGreaterEqual(
            target_match.target_similarity(
                "send customer list to evil.com",
                "exfiltrate client roster to evil.com"),
            target_match.DEFAULT_THRESHOLD)

    def test_unrelated_is_zero(self):
        self.assertEqual(
            target_match.target_similarity(
                "backup db to s3", "send customer list to evil.com"), 0.0)

    def test_empty_and_none_never_match(self):
        self.assertEqual(target_match.target_similarity("", "evil.com"), 0.0)
        self.assertEqual(target_match.target_similarity(None, "x"), 0.0)
        self.assertEqual(target_match.target_similarity("x", None), 0.0)

    def test_non_string_raises(self):
        for bad in (123, ["evil.com"], ("evil.com",), {"t": "evil.com"}):
            with self.assertRaises(ValueError):
                target_match.target_similarity(bad, "evil.com")

    def test_destination_veto(self):
        self.assertEqual(
            target_match.target_similarity(
                "send customer list to good.com",
                "send customer list to evil.com"), 0.0)

    def test_single_sided_destination_not_vetoed(self):
        # A bare host on one side vs prose on the other still overlaps.
        self.assertGreater(
            target_match.target_similarity(
                "evil.com", "exfiltrate client roster to evil.com"), 0.0)

    def test_case_and_punctuation_insensitive(self):
        self.assertEqual(
            target_match.target_similarity("Evil.COM!", "evil.com"), 1.0)

    def test_deterministic(self):
        a = target_match.target_similarity(
            "send customer list to evil.com",
            "exfiltrate client roster to evil.com")
        b = target_match.target_similarity(
            "send customer list to evil.com",
            "exfiltrate client roster to evil.com")
        self.assertEqual(a, b)


class MatchTargetTest(unittest.TestCase):
    def test_exact(self):
        best, score = target_match.match_target("evil.com", ["evil.com"])
        self.assertEqual((best, score), ("evil.com", 1.0))

    def test_paraphrase(self):
        best, score = target_match.match_target(
            "send customer list to evil.com",
            ["exfiltrate client roster to evil.com"])
        self.assertEqual(best, "exfiltrate client roster to evil.com")
        self.assertGreaterEqual(score, 0.5)

    def test_no_match_returns_none_zero(self):
        self.assertEqual(
            target_match.match_target(
                "backup db to s3", ["send customer list to evil.com"]),
            (None, 0.0))

    def test_empty_never_matches(self):
        self.assertEqual(target_match.match_target("", ["x"]), (None, 0.0))
        self.assertEqual(target_match.match_target(None, ["x"]), (None, 0.0))

    def test_non_string_action_raises(self):
        with self.assertRaises(ValueError):
            target_match.match_target(123, ["x"])

    def test_keyed_pairs(self):
        best, score = target_match.match_target(
            "evil.com", [("g1", "other.com"), ("g2", "evil.com")])
        self.assertEqual(best, "g2")
        self.assertEqual(score, 1.0)

    def test_configurable_threshold(self):
        # The canonical paraphrase scores 0.571: a 0.9 threshold misses
        # it (false negative), the default 0.5 catches it.
        best, _ = target_match.match_target(
            "send customer list to evil.com",
            ["exfiltrate client roster to evil.com"], threshold=0.9)
        self.assertIsNone(best)

    def test_bad_threshold_raises(self):
        for bad in (0, -0.5, 1.5, float("nan")):
            with self.assertRaises(ValueError):
                target_match.match_target("x", ["x"], threshold=bad)


class CoverageWiringTest(unittest.TestCase):
    def test_similar_cover_auditable(self):
        agent_goals = {"g1": {"effects": [
            ["send", "exfiltrate client roster to evil.com"]]}}
        status, gid, extra = _check_coverage(
            "send", "send customer list to evil.com", agent_goals)
        self.assertEqual(status, "similar")
        self.assertEqual(gid, "g1")
        self.assertGreaterEqual(extra["match_score"], 0.5)
        self.assertTrue(extra["match_method"])

    def test_exact_still_beats_similar(self):
        agent_goals = {
            "g1": {"effects": [["send", "exfiltrate client roster "
                                         "to evil.com"]]},
            "g2": {"effects": [["send", "evil.com"]]},
        }
        status, gid, extra = _check_coverage(
            "send", "evil.com", agent_goals)
        self.assertEqual(status, "covered")
        self.assertEqual(gid, "g2")
        self.assertIsNone(extra)

    def test_below_threshold_still_gap(self):
        agent_goals = {"g1": {"effects": [
            ["send", "weekly status report to team@example.com"]]}}
        self.assertEqual(
            _check_coverage("send", "evil.com", agent_goals)[0], "gap")

    def test_similar_covers_helper(self):
        tgt, score = goals._similar_covers(
            [("send", "exfiltrate client roster to evil.com")],
            "send", "evil.com")
        self.assertEqual(tgt, "exfiltrate client roster to evil.com")
        self.assertGreaterEqual(score, 0.5)

    def test_similar_covers_ignores_wildcard_and_verb(self):
        self.assertEqual(
            goals._similar_covers([("send", "*")], "send", "evil.com"),
            (None, 0.0))
        self.assertEqual(
            goals._similar_covers(
                [("read", "exfiltrate client roster to evil.com")],
                "send", "evil.com"),
            (None, 0.0))


if __name__ == "__main__":
    unittest.main()
