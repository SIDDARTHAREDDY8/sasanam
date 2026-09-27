"""Unit tests for gov/target_match.py and its wiring seams."""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import target_match  # noqa: E402
from gov import goals  # noqa: E402
from gov.goal_audit import _check_coverage  # noqa: E402
from gov import approvals  # noqa: E402


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


class StructuralScopeMatchTest(unittest.TestCase):
    """Wave-149 (row-11): structural typed-scope match pins."""

    def test_paraphrase_pair_matches(self):
        self.assertTrue(target_match.structural_scope_match(
            "obliterate the quarterly filing", "delete the Q3 report"))

    def test_wrong_verb_class_vetoes(self):
        self.assertFalse(target_match.structural_scope_match(
            "obliterate the quarterly filing", "archive the Q3 report"))
        self.assertFalse(target_match.structural_scope_match(
            "send the report", "delete the report"))

    def test_noun_sets_must_agree(self):
        self.assertFalse(target_match.structural_scope_match(
            "delete the customer list", "delete the vendor list"))
        self.assertFalse(target_match.structural_scope_match(
            "obliterate everything", "delete the Q3 report"))

    def test_empty_noun_set_never_matches(self):
        self.assertFalse(target_match.structural_scope_match(
            "obliterate", "delete the Q3 report"))
        self.assertFalse(target_match.structural_scope_match(
            "the quarterly filing", "delete the Q3 report"))

    def test_destination_veto(self):
        self.assertFalse(target_match.structural_scope_match(
            "obliterate the report to evil.com",
            "delete the report to good.com"))

    def test_empty_and_none_never_match(self):
        self.assertFalse(target_match.structural_scope_match(
            "", "delete the Q3 report"))
        self.assertFalse(target_match.structural_scope_match(
            "obliterate the filing", ""))
        self.assertFalse(target_match.structural_scope_match(
            None, "delete the Q3 report"))
        self.assertFalse(target_match.structural_scope_match(
            "obliterate the filing", None))

    def test_non_string_raises(self):
        for bad in (123, ["x"], {"t": "x"}):
            with self.assertRaises(ValueError):
                target_match.structural_scope_match(bad, "delete the x")
            with self.assertRaises(ValueError):
                target_match.structural_scope_match("delete the x", bad)

    def test_deterministic(self):
        a = target_match.structural_scope_match(
            "obliterate the quarterly filing", "delete the Q3 report")
        b = target_match.structural_scope_match(
            "obliterate the quarterly filing", "delete the Q3 report")
        self.assertEqual(a, b)


class DiscriminatorVetoTest(unittest.TestCase):
    """Row-11 follow-up leg: scope-discriminator contradiction veto.

    The ceremony tiers (typed_scope_similarity, structural_scope_match)
    suppress matches when the typed text contradicts the reference on
    a scope discriminator -- specific quarters, 4-digit years, or
    typed-side widening quantifiers. Ceremony-only: the grant path
    (target_similarity) is untouched, pinned below.
    """

    def test_quarter_contradiction_suppresses_numeric(self):
        # Pre-seam this scored 0.800 >= 0.5 (the ceremony accepted a
        # different-quarter scope).
        self.assertEqual(
            target_match.typed_scope_similarity(
                "delete the Q4 report", "delete the Q3 report"), 0.0)

    def test_quarter_contradiction_suppresses_structural(self):
        self.assertFalse(target_match.structural_scope_match(
            "delete the Q4 report", "delete the Q3 report"))
        self.assertFalse(target_match.structural_scope_match(
            "delete the Q2 report", "delete the Q1 report"))

    def test_same_quarter_no_veto(self):
        self.assertTrue(target_match.structural_scope_match(
            "delete the Q3 report", "delete the Q3 report"))
        self.assertGreaterEqual(
            target_match.typed_scope_similarity(
                "delete the Q3 report", "delete the Q3 report"),
            target_match.DEFAULT_THRESHOLD)

    def test_quarterly_is_not_a_specific_quarter(self):
        # "quarterly" names no specific quarter: the wave-149
        # mandated accept must survive the veto.
        self.assertTrue(target_match.structural_scope_match(
            "obliterate the quarterly filing", "delete the Q3 report"))

    def test_one_sided_quarter_no_veto(self):
        # Contradiction-only: the wave-147 s1 accept (typed side
        # names no quarter) is pinned at 0.8889.
        self.assertAlmostEqual(
            target_match.typed_scope_similarity(
                "erase the report", "delete the Q3 report"),
            0.8889, places=3)

    def test_year_contradiction_vetoes(self):
        self.assertEqual(
            target_match.typed_scope_similarity(
                "delete the 2025 report", "delete the 2024 report"), 0.0)
        self.assertFalse(target_match.structural_scope_match(
            "delete the 2025 report", "delete the 2024 report"))

    def test_same_year_no_veto(self):
        self.assertGreaterEqual(
            target_match.typed_scope_similarity(
                "delete the 2024 report", "delete the 2024 report"),
            target_match.DEFAULT_THRESHOLD)

    def test_quantifier_widening_vetoes(self):
        # Pre-seam the synonym tier scored 0.500 and the structural
        # tier matched: the ceremony accepted "erase all filings".
        self.assertEqual(
            target_match.typed_scope_similarity(
                "erase all filings", "delete the Q3 report"), 0.0)
        self.assertFalse(target_match.structural_scope_match(
            "erase all filings", "delete the Q3 report"))

    def test_every_each_canonicalize_to_all(self):
        self.assertEqual(
            target_match.typed_scope_similarity(
                "delete every document", "delete the Q3 report"), 0.0)
        self.assertEqual(
            target_match.typed_scope_similarity(
                "remove each filing", "delete the Q3 report"), 0.0)
        self.assertEqual(
            target_match.typed_scope_similarity(
                "delete the entire report", "delete the Q3 report"), 0.0)

    def test_matching_quantifier_no_veto(self):
        # Both sides widen identically: no contradiction.
        self.assertGreaterEqual(
            target_match.typed_scope_similarity(
                "delete all reports", "erase all filings"),
            target_match.DEFAULT_THRESHOLD)

    def test_narrowing_no_veto(self):
        # Reference-side widening is the human narrowing: accepted.
        self.assertGreaterEqual(
            target_match.typed_scope_similarity(
                "delete the report", "delete all reports"),
            target_match.DEFAULT_THRESHOLD)

    def test_grant_path_untouched(self):
        # The row-11 paraphrase tier keeps raw token-tversky: no
        # discriminator veto on the grant path.
        self.assertAlmostEqual(
            target_match.target_similarity(
                "delete the Q4 report", "delete the Q3 report"),
            0.8, places=3)
        self.assertAlmostEqual(
            target_match.target_similarity(
                "erase all filings", "delete the Q3 report"),
            0.0, places=3)

    def test_discriminator_veto_composes_with_destination_veto(self):
        # Both vetoes are suppress-only and independent.
        self.assertEqual(
            target_match.typed_scope_similarity(
                "delete the Q4 report to evil.com",
                "delete the Q3 report to good.com"), 0.0)
        self.assertFalse(target_match.structural_scope_match(
            "delete the Q4 report to evil.com",
            "delete the Q3 report to good.com"))

    def test_deterministic(self):
        a = target_match.typed_scope_similarity(
            "delete the Q4 report", "delete the Q3 report")
        b = target_match.typed_scope_similarity(
            "delete the Q4 report", "delete the Q3 report")
        self.assertEqual(a, b)


class DiscriminatorEvasionTest(unittest.TestCase):
    """Break-round v2 closes: quarter-form expansion, Unicode
    normalization, whole->entire, and the nounless-typed rule
    (evals/ceremony_receipt_evasion_probes.py, e1-e15).

    Veto cases pin at the target_match seam (refused on every
    tier) AND at the ceremony seam; accept cases pin at the
    ceremony seam (approvals._type_to_confirm_ok), where the
    structural tier composes.
    """

    def _refused(self, typed, ref):
        self.assertEqual(
            target_match.typed_scope_similarity(typed, ref), 0.0)
        self.assertFalse(target_match.structural_scope_match(typed, ref))
        ok, _s, _d, _m = approvals._type_to_confirm_ok([ref], typed)
        self.assertFalse(ok)

    def _accepted(self, typed, ref):
        ok, _s, _d, _m = approvals._type_to_confirm_ok([ref], typed)
        self.assertTrue(ok)

    def test_whole_widening_vetoes(self):
        # "the whole archive" is the entire archive: widening.
        self._refused("remove the whole archive", "delete the Q3 report")

    def test_quarter_form_variants_veto(self):
        for typed in ("delete the 3rd quarter report",
                      "delete the third-quarter filing",
                      "erase the FY26Q3 document",
                      "obliterate the Sept quarter filing",
                      "delete the quarter ending September report",
                      "delete the QIII report"):
            with self.subTest(typed=typed):
                self._refused(typed, "delete the Q4 report")

    def test_fullwidth_quarter_vetoes(self):
        # U+FF31 U+FF14 fold to "q4" under NFKC.
        self._refused("delete the Ｑ４ report",
                      "delete the Q3 report")

    def test_zero_width_split_quarter_vetoes(self):
        # F183's class, new seam: the split token still names q4.
        self._refused("delete the Q" + chr(0x200b) + "4 report",
                      "delete the Q3 report")

    def test_nounless_typed_scope_vetoes(self):
        for typed in ("delete the thing", "remove it", "erase stuff",
                      "delete everything"):
            with self.subTest(typed=typed):
                self._refused(typed, "delete the Q3 report")

    def test_quarter_set_parser(self):
        self.assertEqual(
            target_match._quarter_set("delete the 3rd quarter report"),
            {"q3"})
        self.assertEqual(
            target_match._quarter_set("erase the FY26Q3 document"),
            {"q3"})
        self.assertEqual(
            target_match._quarter_set("obliterate the quarterly filing"),
            set())

    def test_same_quarter_variants_accepted(self):
        # No false refusals: same quarter, rephrased.
        for typed in ("delete the 3rd quarter report",
                      "erase the FY26Q3 document",
                      "delete the September report",
                      "delete the QIII filing"):
            with self.subTest(typed=typed):
                self._accepted(typed, "delete the Q3 report")

    def test_wave149_quarterly_accept_preserved(self):
        self._accepted("obliterate the quarterly filing",
                       "delete the Q3 report")

    def test_wave147_erase_the_report_accept_preserved(self):
        self._accepted("erase the report", "delete the Q3 report")

    def test_zero_width_same_quarter_accepted(self):
        self._accepted("delete the Q" + chr(0x200b) + "3 report",
                       "delete the Q3 report")

    def test_h2_residual_pinned_accepted(self):
        # A half is not a quarter: interval semantics outside the
        # quarter discriminator. Pinned EXPECTED in the evasion
        # battery until a wider time-interval rule exists.
        self._accepted("delete the H2 report", "delete the Q4 report")
