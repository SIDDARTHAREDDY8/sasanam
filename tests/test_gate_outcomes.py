#!/usr/bin/env python3
"""Unit tests for gov/gate_outcomes.py (wave-237 lane A).

Three-outcome gate rule: PASS allows, TAMPER refuses gate-tampered,
UNDECIDABLE refuses gate-undecidable (a failure to verify, never
"tampered"); unreasoned or off-vocabulary undecidable reasons refuse
gate-verdict-unreasoned; a gate that allows undecidable fails the
compliance self-check with gate-undecidable-allowed.
Stdlib + gov.gate_outcomes only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import gate_outcomes as go  # noqa: E402


class VerdictShapeTest(unittest.TestCase):
    def test_outcomes_are_the_three(self):
        self.assertEqual(set(go.OUTCOMES), {"pass", "tamper", "undecidable"})

    def test_malformed_outcome_is_programming_error(self):
        with self.assertRaises(ValueError):
            go.Verdict(outcome="maybe")

    def test_non_string_reason_is_programming_error(self):
        with self.assertRaises(ValueError):
            go.Verdict(outcome="undecidable", reason=None)

    def test_pass_reason_defaults_empty(self):
        v = go.Verdict(outcome="pass")
        self.assertEqual(v.reason, "")

    def test_non_verdict_to_gate_is_programming_error(self):
        with self.assertRaises(ValueError):
            go.gate_decide({"outcome": "pass"})


class GateDecideTest(unittest.TestCase):
    def test_pass_allows(self):
        self.assertTrue(go.gate_decide(go.Verdict(outcome="pass")))

    def test_tamper_refuses_tampered_code(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(go.Verdict(outcome="tamper",
                                      reason="digest-mismatch-observed"))
        self.assertEqual(ctx.exception.code, "gate-tampered")

    def test_undecidable_refuses_undecidable_code(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(go.Verdict(outcome="undecidable",
                                      reason="trust-root-missing"))
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_undecidable_detail_says_could_not_verify(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(go.Verdict(outcome="undecidable",
                                      reason="evidence-truncated"))
        detail = (ctx.exception.detail or "").lower()
        self.assertIn("could not verify", detail)

    def test_undecidable_detail_never_says_tampered(self):
        for reason in go.UNDECIDABLE_REASONS:
            with self.assertRaises(go.GateOutcomeError) as ctx:
                go.gate_decide(go.Verdict(outcome="undecidable",
                                          reason=reason))
            self.assertNotIn("tamper",
                             (ctx.exception.detail or "").lower(),
                             "reason %r leaked tamper language" % reason)

    def test_undecidable_codes_distinct_from_tamper(self):
        # Behaviour-based: the code refused for an undecidable verdict
        # differs from the code refused for a tampered one (this must
        # never be a literal-vs-literal comparison).
        with self.assertRaises(go.GateOutcomeError) as undecidable_ctx:
            go.gate_decide(go.Verdict(outcome="undecidable",
                                      reason="trust-root-missing"))
        with self.assertRaises(go.GateOutcomeError) as tamper_ctx:
            go.gate_decide(go.Verdict(outcome="tamper",
                                      reason="digest-mismatch-observed"))
        self.assertNotEqual(undecidable_ctx.exception.code,
                            tamper_ctx.exception.code)

    def test_all_vocabulary_reasons_refuse_undecidable(self):
        self.assertEqual(go.UNDECIDABLE_REASONS,
                         {"trust-root-missing", "algorithm-unknown",
                          "evidence-truncated", "evidence-incomplete",
                          # Wave-240 lane B (APS -04 axis/result model):
                          # "unsupported-profile" folds the per-axis
                          # UNSUPPORTED term into UNDECIDABLE; the
                          # verifier does not implement the receipt's
                          # profile -- could not verify, not tampered.
                          # "verifier-limit-reached" folds a
                          # ceiling-induced indeterminate (depth/wire/
                          # chain limits are verifier properties) into
                          # UNDECIDABLE. Additive only; all four
                          # wave-237 reasons keep their behavior.
                          "unsupported-profile",
                          "verifier-limit-reached"})
        for reason in go.UNDECIDABLE_REASONS:
            with self.assertRaises(go.GateOutcomeError) as ctx:
                go.gate_decide(go.Verdict(outcome="undecidable",
                                          reason=reason))
            self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_unreasoned_undecidable_refused(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(go.Verdict(outcome="undecidable", reason=""))
        self.assertEqual(ctx.exception.code, "gate-verdict-unreasoned")

    def test_off_vocabulary_reason_refused(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(go.Verdict(outcome="undecidable",
                                      reason="the-moon-was-in-retrograde"))
        self.assertEqual(ctx.exception.code, "gate-verdict-unreasoned")

    def test_error_carries_code_and_detail(self):
        err = go.GateOutcomeError("gate-tampered", "some detail")
        self.assertEqual(err.code, "gate-tampered")
        self.assertIn("gate-tampered", str(err))
        self.assertIn("some detail", str(err))


class GateSelfcheckTest(unittest.TestCase):
    def _strict(self, verdict):
        return go.gate_decide(verdict)

    def _lenient(self, verdict):
        if verdict.outcome == "undecidable":
            return True
        return go.gate_decide(verdict)

    def test_strict_gate_is_compliant(self):
        result = go.gate_selfcheck(self._strict)
        self.assertTrue(result.get("ok"))
        self.assertEqual(result.get("compliance"), "compliant")

    def test_lenient_gate_is_non_compliant(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_selfcheck(self._lenient)
        self.assertEqual(ctx.exception.code, "gate-undecidable-allowed")

    def test_crashing_gate_is_non_compliant(self):
        def _crashes(verdict):
            raise RuntimeError("boom")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_selfcheck(_crashes)
        self.assertEqual(ctx.exception.code, "gate-undecidable-allowed")


class TaxonomyPinTest(unittest.TestCase):
    def test_gate_codes_mapped(self):
        from gov import decision_codes as dc
        for code in ("gate-tampered", "gate-undecidable",
                     "gate-verdict-unreasoned", "gate-undecidable-allowed"):
            self.assertIn(code, dc.TAXONOMY, "%s not mapped" % code)
            entry = dc.TAXONOMY[code]
            self.assertEqual(entry["domain"], "gate")
            self.assertEqual(entry["code"], code)


if __name__ == "__main__":
    unittest.main()
