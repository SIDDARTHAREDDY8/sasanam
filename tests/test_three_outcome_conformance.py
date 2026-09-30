"""Unit tests for gov/three_outcome_conformance.py (wave-242, W242-6).

The conformance oracle for the staged ACTA -04 section 5.3 vocabulary:
valid / invalid / undecidable must be distinguishable in every
consumer-actionable output; undecidable is never reported as
invalid nor valid; causes are named from the closed
UNDECIDABLE_REASONS vocabulary.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import three_outcome_conformance as oc
from gov import gate_outcomes as go


def _receipt(alg="ed25519-rfc8032", key="trust-anchor", sig=True):
    return {"algorithm": alg, "key_source": key, "signature_valid": sig}


class ClassifyTest(unittest.TestCase):
    def test_unsupported_algorithm_undecidable(self):
        verdict = oc.classify_receipt(
            _receipt(alg="dilithium-9000"))
        self.assertEqual(verdict.outcome, go.UNDECIDABLE)
        self.assertEqual(verdict.reason, "algorithm-unknown")

    def test_embedded_key_undecidable_even_on_bad_signature(self):
        verdict = oc.classify_receipt(
            _receipt(key="embedded", sig=False))
        self.assertEqual(verdict.outcome, go.UNDECIDABLE)
        self.assertEqual(verdict.reason, "trust-root-missing")

    def test_tampered_signature_under_trust_anchor_invalid(self):
        verdict = oc.classify_receipt(_receipt(sig=False))
        self.assertEqual(verdict.outcome, go.TAMPER)

    def test_good_signature_under_trust_anchor_valid(self):
        verdict = oc.classify_receipt(_receipt(sig=True))
        self.assertEqual(verdict.outcome, go.PASS)

    def test_unmeasured_signature_undecidable(self):
        verdict = oc.classify_receipt(_receipt(sig=None))
        self.assertEqual(verdict.outcome, go.UNDECIDABLE)
        self.assertEqual(verdict.reason, "evidence-incomplete")

    def test_malformed_receipt_is_total_undecidable(self):
        # Missing algorithm -> unknown algorithm; the oracle is total
        # and never reports tamper or pass on unshaped input.
        verdict = oc.classify_receipt({"not": "a receipt"})
        self.assertEqual(verdict.outcome, go.UNDECIDABLE)
        self.assertIn(verdict.reason, go.UNDECIDABLE_REASONS)

    def test_non_mapping_is_programming_error(self):
        with self.assertRaises(oc.ThreeOutcomeError):
            oc.classify_receipt("receipt")

    def test_explicit_supported_set(self):
        verdict = oc.classify_receipt(
            _receipt(alg="custom-alg"),
            supported_algorithms={"custom-alg"})
        self.assertEqual(verdict.outcome, go.PASS)

    def test_undecidable_reasons_all_in_vocabulary(self):
        for receipt in (
                {"algorithm": "nope", "key_source": "trust-anchor",
                 "signature_valid": True},
                {"algorithm": "ed25519-rfc8032", "key_source": "weird",
                 "signature_valid": True},
                {"algorithm": "ed25519-rfc8032",
                 "key_source": "trust-anchor", "signature_valid": None}):
            verdict = oc.classify_receipt(receipt)
            self.assertIn(verdict.reason, go.UNDECIDABLE_REASONS)


class RenderTest(unittest.TestCase):
    def test_render_valid(self):
        r = oc.render_outcome(go.Verdict(go.PASS, ""))
        self.assertEqual((r["outcome"], r["exit_status"]),
                         (oc.OUTCOME_VALID, oc.EXIT_VALID))

    def test_render_invalid(self):
        r = oc.render_outcome(go.Verdict(go.TAMPER, "sig mismatch"))
        self.assertEqual((r["outcome"], r["exit_status"]),
                         (oc.OUTCOME_INVALID, oc.EXIT_INVALID))
        self.assertEqual(r["cause"], "sig mismatch")

    def test_render_undecidable(self):
        r = oc.render_outcome(
            go.Verdict(go.UNDECIDABLE, "algorithm-unknown"))
        self.assertEqual((r["outcome"], r["exit_status"]),
                         (oc.OUTCOME_UNDECIDABLE, oc.EXIT_UNDECIDABLE))
        self.assertEqual(r["cause"], "algorithm-unknown")

    def test_exit_statuses_distinct(self):
        exits = {oc.EXIT_VALID, oc.EXIT_INVALID, oc.EXIT_UNDECIDABLE}
        self.assertEqual(exits, {0, 2, 4})
        self.assertEqual(len(exits), 3)

    def test_non_verdict_is_programming_error(self):
        with self.assertRaises(ValueError):
            oc.render_outcome("undecidable")


class GateCompositionTest(unittest.TestCase):
    def test_oracle_verdicts_flow_through_gate(self):
        self.assertTrue(
            go.gate_decide(oc.classify_receipt(_receipt(sig=True))))
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(oc.classify_receipt(_receipt(sig=False)))
        self.assertEqual(ctx.exception.code, "gate-tampered")
        with self.assertRaises(go.GateOutcomeError) as ctx2:
            go.gate_decide(
                oc.classify_receipt(_receipt(alg="dilithium-9000")))
        self.assertEqual(ctx2.exception.code, "gate-undecidable")


if __name__ == "__main__":
    unittest.main()
