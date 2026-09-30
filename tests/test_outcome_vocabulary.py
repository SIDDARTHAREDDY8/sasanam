"""Unit tests for gov/outcome_vocabulary.py (wave-243, W243-4).

Four-term vocabulary: VERIFIED (crypto+structural measured true,
says nothing about trust) / ACCEPTED (VERIFIED + pinned trust
inputs matched) / SATISFIED (evidence requirements met, sufficiency
only, never authorization) / UNSATISFIED (everything else), plus
the evaluation-lineage profile and the three-outcome composition.
"""
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import outcome_vocabulary as ov
from gov import gate_outcomes as go
from gov import three_outcome_conformance as oc


def _verdict(outcome, reason=""):
    return go.Verdict(outcome, reason)


class TermsTest(unittest.TestCase):
    def test_terms_are_four_and_ordered(self):
        self.assertEqual(ov.TERMS,
                         ("VERIFIED", "ACCEPTED", "SATISFIED", "UNSATISFIED"))

    def test_grade_rejects_unknown_term(self):
        with self.assertRaises(ValueError):
            ov.Grade("AUTHORIZED")

    def test_grade_equality(self):
        self.assertEqual(ov.Grade(ov.VERIFIED),
                         ov.Grade(ov.VERIFIED, ""))
        self.assertNotEqual(ov.Grade(ov.VERIFIED),
                            ov.Grade(ov.ACCEPTED))


class ClassifyEvidenceTest(unittest.TestCase):
    def test_unmeasured_is_unsatisfied_incomplete(self):
        g = ov.classify_evidence({"crypto_ok": None,
                                   "structural_ok": True})
        self.assertEqual(g, ov.Grade(ov.UNSATISFIED, "evidence-incomplete"))

    def test_measured_false_is_unsatisfied(self):
        g = ov.classify_evidence({"crypto_ok": False,
                                   "structural_ok": True})
        self.assertEqual(g, ov.Grade(ov.UNSATISFIED, "evidence-false"))

    def test_crypto_only_is_verified(self):
        g = ov.classify_evidence({"crypto_ok": True,
                                   "structural_ok": True})
        self.assertEqual(g, ov.Grade(ov.VERIFIED, ""))

    def test_accepted_needs_pinned_trust(self):
        g = ov.classify_evidence(
            {"crypto_ok": True, "structural_ok": True,
             "trust_inputs_match": True},
            trust_inputs={"pinned_issuer": "x"})
        self.assertEqual(g, ov.Grade(ov.ACCEPTED, ""))

    def test_trust_mismatch_stays_verified(self):
        g = ov.classify_evidence(
            {"crypto_ok": True, "structural_ok": True,
             "trust_inputs_match": False},
            trust_inputs={"pinned_issuer": "x"})
        self.assertEqual(g, ov.Grade(ov.VERIFIED, "trust-inputs-unmet"))

    def test_satisfied_needs_requirements(self):
        g = ov.classify_evidence(
            {"crypto_ok": True, "structural_ok": True,
             "trust_inputs_match": True, "requirements_met": True},
            trust_inputs={"pinned_issuer": "x"},
            requirements={"min_checks": 2})
        self.assertEqual(g, ov.Grade(ov.SATISFIED, ""))
        g2 = ov.classify_evidence(
            {"crypto_ok": True, "structural_ok": True,
             "trust_inputs_match": True, "requirements_met": False},
            trust_inputs={"pinned_issuer": "x"},
            requirements={"min_checks": 2})
        self.assertEqual(g2.term, ov.ACCEPTED)
        self.assertEqual(g2.reason, "requirements-unmet")

    def test_non_mapping_is_programming_error(self):
        with self.assertRaises(ValueError):
            ov.classify_evidence("not-a-mapping")


class AcceptReportTest(unittest.TestCase):
    def test_verified_claim_authorized_refused(self):
        with self.assertRaises(ov.OutcomeVocabularyError) as ctx:
            ov.accept_report({
                "verdict": _verdict(go.PASS, ""),
                "evidence": {"crypto_ok": True, "structural_ok": True},
                "claim": "authorized",
            })
        self.assertEqual(ctx.exception.code, "satisfied-missing")

    def test_tamper_is_unsatisfied(self):
        g = ov.accept_report({
            "verdict": _verdict(go.TAMPER, ""),
            "evidence": {"crypto_ok": False, "structural_ok": True},
        })
        self.assertEqual(g, ov.Grade(ov.UNSATISFIED, "tamper-measured"))

    def test_undecidable_is_unsatisfied_with_cause(self):
        g = ov.accept_report({
            "verdict": _verdict(go.UNDECIDABLE, "trust-root-missing"),
            "evidence": {"crypto_ok": True, "structural_ok": True},
        })
        self.assertEqual(g.term, ov.UNSATISFIED)
        self.assertIn("trust-root-missing", g.reason)

    def test_satisfied_report_grades_satisfied(self):
        g = ov.accept_report({
            "verdict": _verdict(go.PASS, ""),
            "evidence": {"crypto_ok": True, "structural_ok": True,
                         "trust_inputs_match": True,
                         "requirements_met": True},
            "trust_inputs": {"pinned_issuer": "x"},
            "requirements": {"min_checks": 2},
            "claim": "satisfied",
        })
        self.assertEqual(g, ov.Grade(ov.SATISFIED, ""))

    def test_non_verdict_is_programming_error(self):
        with self.assertRaises(ValueError):
            ov.accept_report({"verdict": "pass"})


class LineageTest(unittest.TestCase):
    def test_happy_path_binds_terminal(self):
        chain = [
            {"id": "a", "predecessor": None, "challenge": "1"},
            {"id": "b", "predecessor": "a", "challenge": "2"},
        ]
        binding = ov.verify_lineage(chain)
        self.assertEqual(binding["terminal"], "b")
        self.assertEqual(len(binding["binding"]), 64)

    def test_skip_refused(self):
        chain = [
            {"id": "a", "predecessor": None, "challenge": "1"},
            {"id": "c", "predecessor": "b-missing", "challenge": "3"},
        ]
        with self.assertRaises(ov.OutcomeVocabularyError) as ctx:
            ov.verify_lineage(chain)
        self.assertEqual(ctx.exception.code, "lineage-gap")

    def test_genesis_anchor_binding(self):
        chain = [{"id": "a", "predecessor": "anchor", "challenge": "1"}]
        with self.assertRaises(ov.OutcomeVocabularyError) as ctx:
            ov.verify_lineage(chain, expected_predecessor="other-anchor")
        self.assertEqual(ctx.exception.code, "lineage-gap")
        ok = ov.verify_lineage(chain, expected_predecessor="anchor")
        self.assertEqual(ok["terminal"], "a")

    def test_empty_is_broken_not_shortened(self):
        with self.assertRaises(ov.OutcomeVocabularyError) as ctx:
            ov.verify_lineage([])
        self.assertEqual(ctx.exception.code, "lineage-gap")


class CompositionTest(unittest.TestCase):
    def test_valid_composes_to_at_most_verified(self):
        verdict, grade, rendered = ov.classify_receipt_terms(
            {"algorithm": "ed25519-rfc8032", "key_source": "trust-anchor",
             "signature_valid": True})
        self.assertEqual(rendered["outcome"], oc.OUTCOME_VALID)
        self.assertEqual(grade.term, ov.VERIFIED)

    def test_undecidable_composes_to_unsatisfied(self):
        verdict, grade, rendered = ov.classify_receipt_terms(
            {"algorithm": "nope", "key_source": "trust-anchor",
             "signature_valid": True})
        self.assertEqual(rendered["outcome"], oc.OUTCOME_UNDECIDABLE)
        self.assertEqual(grade.term, ov.UNSATISFIED)

    def test_outcome_to_term_map_total(self):
        self.assertEqual(set(ov.OUTCOME_TO_TERM),
                         {oc.OUTCOME_VALID, oc.OUTCOME_INVALID,
                          oc.OUTCOME_UNDECIDABLE})


if __name__ == "__main__":
    unittest.main()
