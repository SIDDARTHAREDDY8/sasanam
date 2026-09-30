#!/usr/bin/env python3
"""Unit tests for gov/receipt_pairs.py.

Wave-227 lane B: recomputable decision<->execution receipt pairs.
Tests use independent spec-vector literals (not recomputed from the
implementation) so they can disagree with the code.
"""

import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import receipt_pairs as rp  # noqa: E402

ISSUED = 1700000000.0
EXECUTED = 1700000060.0


def _verdict_record():
    return {"attempt": {"action": "install_package",
                        "package": "nginx-1.29"},
            "effect": {"status": "admitted",
                       "evidence": "gate allowed: pinned package"}}


def _decision():
    return rp.issue_decision_receipt(_verdict_record(), ISSUED)


def _execution(decision):
    obs = {"outcome": "timed-out", "executor_may_have_accepted": False}
    return rp.issue_execution_receipt(_verdict_record(), obs, decision,
                                      EXECUTED)


class DecisionReceiptTests(unittest.TestCase):

    def test_shape_and_digest_fields(self):
        receipt = _decision()
        self.assertEqual(receipt["v"], 1)
        self.assertEqual(receipt["kind"], "decision-receipt")
        self.assertEqual(receipt["verdict"], "admitted")
        self.assertEqual(len(receipt["decision_digest"]), 64)
        self.assertEqual(len(receipt["verdict_record_digest"]), 64)
        self.assertEqual(receipt["issued_at"], ISSUED)

    def test_refused_verdict_label(self):
        vr = _verdict_record()
        vr["effect"] = {"status": "refused", "code": "capgate-refused",
                        "evidence": "unlisted package"}
        receipt = rp.issue_decision_receipt(vr, ISSUED)
        self.assertEqual(receipt["verdict"], "refused:capgate-refused")

    def test_authority_fields_refuse_at_issuance(self):
        vr = _verdict_record()
        vr["permit"] = "everything"
        with self.assertRaises(Exception) as ctx:
            rp.issue_decision_receipt(vr, ISSUED)
        self.assertEqual(ctx.exception.code, "capsule-not-authorization")

    def test_bad_timestamp_refuses(self):
        with self.assertRaises(Exception) as ctx:
            rp.issue_decision_receipt(_verdict_record(), True)
        self.assertEqual(ctx.exception.code, "receipt-pair-malformed")


class ExecutionReceiptTests(unittest.TestCase):

    def test_shape_and_backlink(self):
        decision = _decision()
        receipt = _execution(decision)
        self.assertEqual(receipt["kind"], "execution-receipt")
        self.assertEqual(receipt["decision_backlink"],
                         decision["decision_digest"])
        self.assertEqual(receipt["effect_status"], "timed-out-before-effect")
        self.assertEqual(receipt["executed_at"], EXECUTED)

    def test_ambiguous_observation_refuses(self):
        decision = _decision()
        obs = {"outcome": "unknown", "executor_may_have_accepted": True}
        with self.assertRaises(Exception) as ctx:
            rp.issue_execution_receipt(_verdict_record(), obs, decision,
                                       EXECUTED)
        self.assertEqual(ctx.exception.code, "effect-status-ambiguous-refused")

    def test_denied_effect_seals_refused(self):
        decision = rp.issue_decision_receipt(
            {"attempt": {"action": "x", "arg": "y"},
             "effect": {"status": "refused", "code": "capgate-refused",
                        "evidence": "no"}},
            ISSUED)
        vr = {"attempt": {"action": "x", "arg": "y"},
              "effect": {"status": "refused", "code": "capgate-refused",
                         "evidence": "no"}}
        receipt = rp.issue_execution_receipt(
            vr, {"outcome": "denied", "executor_may_have_accepted": False},
            decision, EXECUTED)
        self.assertEqual(receipt["effect_status"], "denied")


class BindTests(unittest.TestCase):

    def test_bind_ok(self):
        decision = _decision()
        pair = rp.bind(_execution(decision), decision)
        self.assertEqual(pair["pair_kind"], "decision-execution-pair")

    def test_backlink_mismatch_refuses(self):
        decision = _decision()
        execution = _execution(decision)
        execution = copy.deepcopy(execution)
        execution["decision_backlink"] = "00" * 32
        with self.assertRaises(Exception) as ctx:
            rp.bind(execution, decision)
        self.assertEqual(ctx.exception.code, "receipt-pair-decision-mismatch")

    def test_unknown_field_refuses(self):
        decision = _decision()
        execution = copy.deepcopy(_execution(decision))
        execution["scope"] = "admin"
        with self.assertRaises(Exception) as ctx:
            rp.bind(execution, decision)
        self.assertEqual(ctx.exception.code, "receipt-pair-unknown-field")


class RecomputeTests(unittest.TestCase):

    def test_recompute_summary_fields(self):
        decision = _decision()
        pair = rp.bind(_execution(decision), decision)
        summary = rp.recompute_pair(pair)
        self.assertTrue(summary["recomputed"])
        self.assertEqual(summary["decision_digest"],
                         decision["decision_digest"])
        self.assertEqual(summary["effect_status"], "timed-out-before-effect")
        self.assertEqual(summary["verdict"], "admitted")
        self.assertEqual(summary["issued_at"], ISSUED)
        self.assertEqual(summary["executed_at"], EXECUTED)
        chain = summary["chain"]
        self.assertEqual(len(chain["chain_digest"]), 64)
        self.assertEqual(chain["close_state"], "closed-acknowledged")
        self.assertEqual(chain["counts"]["verdicts"], 2)

    def test_decision_drift_refuses(self):
        decision = _decision()
        pair = rp.bind(_execution(decision), decision)
        tampered = copy.deepcopy(pair)
        tampered["decision_receipt"]["verdict_record"]["attempt"][
            "package"] = "evil-9.9"
        with self.assertRaises(Exception) as ctx:
            rp.recompute_pair(tampered)
        self.assertEqual(ctx.exception.code, "receipt-pair-decision-drift")

    def test_effect_drift_refuses(self):
        decision = _decision()
        pair = rp.bind(_execution(decision), decision)
        lied = copy.deepcopy(pair)
        lied["execution_receipt"]["effect_status"] = "completed"
        with self.assertRaises(Exception) as ctx:
            rp.recompute_pair(lied)
        self.assertEqual(ctx.exception.code, "receipt-pair-effect-drift")

    def test_time_inversion_refuses(self):
        decision = _decision()
        obs = {"outcome": "completed", "executor_may_have_accepted": False}
        execution = rp.issue_execution_receipt(
            _verdict_record(), obs, decision, ISSUED - 1.0)
        pair = rp.bind(execution, decision)
        with self.assertRaises(Exception) as ctx:
            rp.recompute_pair(pair)
        self.assertEqual(ctx.exception.code, "receipt-pair-time-inversion")


class AuthorityTests(unittest.TestCase):

    def test_deny_authority_use_decision(self):
        with self.assertRaises(Exception) as ctx:
            rp.deny_authority_use(_decision())
        self.assertEqual(ctx.exception.code, "receipt-pair-not-authorization")

    def test_deny_authority_use_execution(self):
        decision = _decision()
        with self.assertRaises(Exception) as ctx:
            rp.deny_authority_use(_execution(decision))
        self.assertEqual(ctx.exception.code, "receipt-pair-not-authorization")


if __name__ == "__main__":
    unittest.main()
