"""Unit tests for gov/axis_result_model.py (wave-240, APS -04 axis/result
model). Stdlib unittest. No network, no env reads, deterministic.
"""

import unittest

from gov import axis_result_model as ax
from gov import gate_outcomes as go


class TermAlgebraTests(unittest.TestCase):
    def test_four_terms_distinct(self):
        self.assertEqual(len(set(ax.TERMS)), 4)
        self.assertEqual(ax.TERMS, ("valid", "invalid", "indeterminate",
                                   "unsupported"))

    def test_verdict_requires_mandatory_reason(self):
        with self.assertRaises(ValueError):
            ax.AxisVerdict("a", ax.VALID, "")
        with self.assertRaises(ValueError):
            ax.AxisVerdict("a", ax.VALID, None)

    def test_verdict_rejects_unknown_term(self):
        with self.assertRaises(ValueError):
            ax.AxisVerdict("a", "pass", "ok")

    def test_verdict_rejects_empty_axis(self):
        with self.assertRaises(ValueError):
            ax.AxisVerdict("", ax.VALID, "ok")

    def test_malformed_construction_is_programming_error(self):
        # Programming errors raise ValueError, never a product refusal.
        with self.assertRaises(ValueError):
            ax.AxisVerdict("a", "bogus-term", "x")
        with self.assertRaises(ValueError):
            ax.aggregate([])
        with self.assertRaises(ValueError):
            ax.aggregate([object()])
        with self.assertRaises(ValueError):
            ax.to_gate_verdict(object())
        with self.assertRaises(ValueError):
            ax.require_valid(object())
        with self.assertRaises(ValueError):
            ax.ceiling("a", "")
        with self.assertRaises(ValueError):
            ax.check_revocation("bogus", "active")


class AggregationTests(unittest.TestCase):
    def _chain(self, terms):
        return ax.aggregate([
            ax.AxisVerdict("axis-%d" % i, term, "reason-%d" % i)
            for i, term in enumerate(terms)])

    def test_all_valid_aggregates_valid(self):
        chain = self._chain([ax.VALID, ax.VALID])
        self.assertEqual(chain.term, ax.VALID)
        ax.require_valid(chain)

    def test_invalid_beats_everything(self):
        chain = self._chain([ax.VALID, ax.UNSUPPORTED, ax.INDETERMINATE,
                             ax.INVALID])
        self.assertEqual(chain.term, ax.INVALID)

    def test_unsupported_beats_indeterminate_and_valid(self):
        chain = self._chain([ax.VALID, ax.INDETERMINATE, ax.UNSUPPORTED])
        self.assertEqual(chain.term, ax.UNSUPPORTED)

    def test_indeterminate_beats_valid(self):
        chain = self._chain([ax.VALID, ax.INDETERMINATE])
        self.assertEqual(chain.term, ax.INDETERMINATE)

    def test_unsupported_never_erased(self):
        # The unsupported verdict is carried in the chain result with
        # its reason code intact.
        v = ax.AxisVerdict("profile:x-v9", ax.UNSUPPORTED,
                           "unsupported-profile")
        chain = ax.aggregate([ax.AxisVerdict("other", ax.VALID, "ok"), v])
        self.assertEqual(chain.term, ax.UNSUPPORTED)
        carried = [x for x in chain.verdicts if x.term == ax.UNSUPPORTED]
        self.assertEqual(len(carried), 1)
        self.assertEqual(carried[0].reason, "unsupported-profile")


class CeilingRuleTests(unittest.TestCase):
    def test_ceiling_is_indeterminate_not_invalid(self):
        v = ax.ceiling("chain:delegation", "delegation-depth-64")
        self.assertEqual(v.term, ax.INDETERMINATE)
        self.assertIn("delegation-depth-64", v.reason)

    def test_ceiling_names_the_limit_in_reason(self):
        v = ax.ceiling("wire", "wire-size-1mib")
        chain = ax.aggregate([v])
        self.assertEqual(chain.term, ax.INDETERMINATE)
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.require_valid(chain)
        self.assertEqual(ctx.exception.code, ax.AXIS_CEILING_HIT)
        self.assertIn("wire-size-1mib", ctx.exception.detail)

    def test_syntax_violation_stays_invalid(self):
        # A real defect observed first is not softened by the ceiling
        # rule.
        chain = ax.aggregate([
            ax.AxisVerdict("record:syntax", ax.INVALID, "duplicate-member"),
            ax.ceiling("chain:delegation", "delegation-depth-64"),
        ])
        self.assertEqual(chain.term, ax.INVALID)
        gate = ax.to_gate_verdict(chain)
        self.assertEqual(gate.outcome, "tamper")


class UnestablishedTests(unittest.TestCase):
    def test_unestablished_never_contributes_to_valid(self):
        chain = ax.aggregate([
            ax.AxisVerdict("record:syntax", ax.VALID, "ok"),
            ax.mark_unestablished("approval-state"),
        ])
        self.assertNotEqual(chain.term, ax.VALID)
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.require_valid(chain)
        self.assertEqual(ctx.exception.code, ax.AXIS_UNESTABLISHED)

    def test_mark_unestablished_carries_reason(self):
        v = ax.mark_unestablished("approval-state", detail="no store")
        self.assertEqual(v.term, ax.UNSUPPORTED)
        self.assertEqual(v.reason, "axis-not-established")


class RequireValidTests(unittest.TestCase):
    def test_invalid_chain_refused(self):
        chain = ax.aggregate([
            ax.AxisVerdict("a", ax.INVALID, "digest-mismatch")])
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.require_valid(chain)
        self.assertEqual(ctx.exception.code, ax.AXIS_INVALID)

    def test_unsupported_chain_refused(self):
        chain = ax.aggregate([
            ax.AxisVerdict("a", ax.UNSUPPORTED, "unsupported-profile")])
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.require_valid(chain)
        self.assertEqual(ctx.exception.code, ax.AXIS_UNESTABLISHED)

    def test_plain_indeterminate_refused(self):
        chain = ax.aggregate([
            ax.AxisVerdict("a", ax.INDETERMINATE, "evidence-truncated-x")])
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.require_valid(chain)
        self.assertEqual(ctx.exception.code, ax.AXIS_INDETERMINATE)


class GateMappingTests(unittest.TestCase):
    def test_valid_maps_to_pass(self):
        chain = ax.aggregate([ax.AxisVerdict("a", ax.VALID, "ok")])
        gate = ax.to_gate_verdict(chain)
        self.assertEqual(gate.outcome, "pass")
        self.assertTrue(go.gate_decide(gate))

    def test_invalid_maps_to_tamper(self):
        chain = ax.aggregate([
            ax.AxisVerdict("a", ax.INVALID, "digest-mismatch")])
        gate = ax.to_gate_verdict(chain)
        self.assertEqual(gate.outcome, "tamper")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(gate)
        self.assertEqual(ctx.exception.code, "gate-tampered")

    def test_unsupported_maps_to_undecidable_with_dedicated_reason(self):
        chain = ax.aggregate([
            ax.AxisVerdict("profile:x-v9", ax.UNSUPPORTED,
                           "unsupported-profile")])
        gate = ax.to_gate_verdict(chain)
        self.assertEqual(gate.outcome, "undecidable")
        self.assertEqual(gate.reason, "unsupported-profile")
        # The dedicated reason is inside the gate vocabulary: the gate
        # refuses gate-undecidable, not gate-verdict-unreasoned.
        self.assertIn("unsupported-profile", go.UNDECIDABLE_REASONS)
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(gate)
        self.assertEqual(ctx.exception.code, "gate-undecidable")
        self.assertIn("could not verify",
                      (ctx.exception.detail or "").lower())
        self.assertNotIn("tamper", (ctx.exception.detail or "").lower())

    def test_ceiling_maps_to_undecidable_naming_limit(self):
        chain = ax.aggregate([ax.ceiling("wire", "wire-size-1mib")])
        gate = ax.to_gate_verdict(chain)
        self.assertEqual(gate.outcome, "undecidable")
        self.assertEqual(gate.reason, "verifier-limit-reached")
        self.assertIn("verifier-limit-reached", go.UNDECIDABLE_REASONS)
        with self.assertRaises(go.GateOutcomeError) as ctx:
            go.gate_decide(gate)
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_no_fourth_gate_outcome(self):
        # Every chain result maps onto one of the three wave-237 gate
        # outcomes. This test fails if a fourth gate term is invented.
        for chain in (
                ax.aggregate([ax.AxisVerdict("a", ax.VALID, "ok")]),
                ax.aggregate([ax.AxisVerdict("a", ax.INVALID, "x")]),
                ax.aggregate([ax.ceiling("a", "depth-1")]),
                ax.aggregate([ax.AxisVerdict("a", ax.UNSUPPORTED, "r")]),
        ):
            self.assertIn(ax.to_gate_verdict(chain).outcome,
                          go.OUTCOMES)

    def test_unsupported_reason_stays_in_vocabulary(self):
        # A dedicated unsupported reason outside the closed vocabulary
        # would be refused as unreasoned, not undecidable -- the fold
        # must stay explicit.
        self.assertIn(ax.GATE_REASON_UNSUPPORTED, go.UNDECIDABLE_REASONS)
        self.assertIn(ax.GATE_REASON_CEILING, go.UNDECIDABLE_REASONS)


class ArtifactVerdictTests(unittest.TestCase):
    def test_six_member_mapping(self):
        self.assertEqual(ax.artifact_verdict_to_term("valid"), ax.VALID)
        self.assertEqual(ax.artifact_verdict_to_term("invalid"), ax.INVALID)
        self.assertEqual(ax.artifact_verdict_to_term("not established"),
                         ax.UNSUPPORTED)
        self.assertEqual(ax.artifact_verdict_to_term("not yet effective"),
                         ax.INDETERMINATE)
        self.assertEqual(ax.artifact_verdict_to_term("suspended"),
                         ax.INDETERMINATE)
        self.assertEqual(ax.artifact_verdict_to_term("restricted"),
                         ax.INDETERMINATE)

    def test_unknown_artifact_verdict_is_programming_error(self):
        with self.assertRaises(ValueError):
            ax.artifact_verdict_to_term("bogus")

    def test_not_established_never_valid(self):
        chain = ax.aggregate([ax.AxisVerdict(
            "artifact", ax.artifact_verdict_to_term("not established"),
            "no-anchor-yet")])
        self.assertNotEqual(chain.term, ax.VALID)


class RevocationTests(unittest.TestCase):
    def test_unknown_state_not_active(self):
        outcome = ax.check_revocation(claimed="revoked",
                                      observed="unknown")
        self.assertFalse(outcome.is_active)
        self.assertEqual(outcome.code, ax.REVOCATION_STATE_UNKNOWN)

    def test_unknown_state_not_active_for_active_claim(self):
        outcome = ax.check_revocation(claimed="active", observed="unknown")
        self.assertFalse(outcome.is_active)

    def test_suspension_not_revocation(self):
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.check_revocation(claimed="revoked", observed="suspended")
        self.assertEqual(ctx.exception.code, ax.REVOCATION_CATEGORY_ERROR)

    def test_expiry_not_revocation(self):
        with self.assertRaises(ax.AxisModelError) as ctx:
            ax.check_revocation(claimed="revoked", observed="expired")
        self.assertEqual(ctx.exception.code, ax.REVOCATION_CATEGORY_ERROR)

    def test_revoked_revoked_not_active(self):
        outcome = ax.check_revocation(claimed="revoked",
                                      observed="revoked")
        self.assertFalse(outcome.is_active)

    def test_active_active_active(self):
        outcome = ax.check_revocation(claimed="active", observed="active")
        self.assertTrue(outcome.is_active)

    def test_suspended_suspended_not_active_no_category_error(self):
        # Suspension reported AS suspension is a clean
        # classification, not a category error.
        outcome = ax.check_revocation(claimed="suspended",
                                      observed="suspended")
        self.assertFalse(outcome.is_active)
        self.assertEqual(outcome.code, "")

    def test_malformed_states_programming_error(self):
        with self.assertRaises(ValueError):
            ax.check_revocation("bogus", "active")


if __name__ == "__main__":
    unittest.main()
