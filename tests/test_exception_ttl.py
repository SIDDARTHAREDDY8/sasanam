"""Unit tests for gov/exception_ttl.py (wave-242, W242-3).

An operational exception declaration MUST carry a mandatory
valid_until horizon. An expired exception refuses gate-undecidable
(the exception no longer shields); a malformed declaration refuses
gate-exception-malformed; a live exception never shields tamper.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import exception_ttl as et
from gov import gate_outcomes as go


class DeclareTest(unittest.TestCase):
    def test_declare_ok(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        self.assertEqual(exc["valid_until"], 1000)
        self.assertEqual(exc["type"], "gate-exception")

    def test_missing_valid_until_malformed(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.declare_exception(valid_until=None, reason="x",
                                 scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-exception-malformed")

    def test_bool_valid_until_is_malformed(self):
        # A bool is not a numeric horizon (True == 1 epoch trap).
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.declare_exception(valid_until=True, reason="x",
                                 scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-exception-malformed")

    def test_empty_reason_malformed(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.declare_exception(valid_until=1000, reason="",
                                 scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-exception-malformed")


class ConsumeTest(unittest.TestCase):
    def test_live_exception_consumes(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        receipt = et.consume_exception(exc, now=999, scope="egress-gate")
        self.assertTrue(receipt["consumed"])
        self.assertEqual(receipt["consumed_at"], 999)

    def test_expired_exception_refuses_gate_undecidable(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.consume_exception(exc, now=1001, scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_scope_mismatch_refuses_gate_undecidable(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.consume_exception(exc, now=999, scope="other-gate")
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_not_a_declaration_refuses_malformed(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.consume_exception({"type": "not-an-exception"}, now=1,
                                 scope="s")
        self.assertEqual(ctx.exception.code, "gate-exception-malformed")


class GateSeamTest(unittest.TestCase):
    def test_undecidable_with_live_exception_returns_receipt(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        receipt = et.gate_decide_with_exception(
            go.Verdict(go.UNDECIDABLE, "trust-root-missing"),
            exc, now=999, scope="egress-gate")
        self.assertTrue(receipt["consumed"])

    def test_undecidable_with_expired_exception_refuses(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.gate_decide_with_exception(
                go.Verdict(go.UNDECIDABLE, "trust-root-missing"),
                exc, now=1001, scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_tamper_with_live_exception_still_refused(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.gate_decide_with_exception(go.Verdict(go.TAMPER, ""),
                                          exc, now=999, scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-tampered")

    def test_pass_allows(self):
        exc = et.declare_exception(valid_until=1000, reason="migration",
                                   scope="egress-gate")
        self.assertTrue(et.gate_decide_with_exception(
            go.Verdict(go.PASS, ""), exc, now=999, scope="egress-gate"))

    def test_undecidable_without_exception_refuses(self):
        with self.assertRaises(go.GateOutcomeError) as ctx:
            et.gate_decide_with_exception(
                go.Verdict(go.UNDECIDABLE, "trust-root-missing"),
                None, now=999, scope="egress-gate")
        self.assertEqual(ctx.exception.code, "gate-undecidable")

    def test_exception_error_is_gate_outcome_error(self):
        self.assertIsInstance(et.ExceptionTTL("x"),
                              go.GateOutcomeError)


if __name__ == "__main__":
    unittest.main()
