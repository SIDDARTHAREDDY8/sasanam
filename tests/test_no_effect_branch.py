#!/usr/bin/env python3
"""Unit tests for the no_effect accepted-and-ignored branch
(wave-242 lane A, W242-4, draft-saha-aadp-03 section 4.1).

A SIGNED no_effect refusal on a NON-failure outcome is accepted,
ignored, and recorded in the reconciliation record's ``detail`` as
asserted-and-ignored -- it is NOT a budget release. A signed
no_effect on failure still releases (pre-existing behavior). An
unsigned refusal still refuses permit-no-effect-unattested.

Deterministic; no network; stdlib only.
"""

import unittest

from gov import bound_permit as bp
from gov import consumption_ledger as cl


def _accept(record):
    return True


def _issue(reg, jti):
    return bp.issue_permit(
        {"action": "deploy", "target": "prod", "trust_tier": "high",
         "decision": "permit"},
        {"mandate": "ops-oncall", "scope": "prod-deploy"},
        {"policy_rev": "r42", "rules_digest": "ab" * 32},
        reg, iss="permit-authority", jti=jti,
        verify_decision=_accept, verify_mandate=_accept,
        verify_policy=_accept)


def _verifier(refusal):
    return refusal.get("sig") == "recipient-sig"


_sentinel = object()


def _do_reconcile(jti, refusal, verifier, refusal_outcome=None):
    reg = bp.PermitRegistry()
    ledger = cl.ConsumptionLedger()
    store = bp.InMemoryConsumeStore(ledger, durable=True)
    budget = bp.BudgetLedger()
    permit = _issue(reg, jti=jti)
    bp.consume_permit(permit, ledger, consume_store=store)
    record = bp.reconcile_unknown_outcome(
        permit, ledger, reg, budget=budget,
        no_effect_refusal=refusal,
        verify_refusal_signature=verifier,
        refusal_outcome=refusal_outcome)
    return record, budget.state("permit-authority", jti), reg


IGNORED = "no-effect-asserted-and-ignored"


class FailureBranchTest(unittest.TestCase):
    def test_signed_on_failure_releases(self):
        record, bstate, _ = _do_reconcile(
            "jti-f1", {"no_effect": True, "sig": "recipient-sig"},
            _verifier, "failure")
        self.assertEqual(record["state"], "not-executed")
        self.assertTrue(bstate["released"])

    def test_default_outcome_is_failure(self):
        # Backward compatibility: callers that do not name the
        # outcome keep the pre-W242 behavior (release).
        record, bstate, _ = _do_reconcile(
            "jti-f2", {"no_effect": True, "sig": "recipient-sig"},
            _verifier)
        self.assertEqual(record["state"], "not-executed")
        self.assertTrue(bstate["released"])


class IgnoredBranchTest(unittest.TestCase):
    def test_signed_on_success_ignored(self):
        record, bstate, _ = _do_reconcile(
            "jti-s1", {"no_effect": True, "sig": "recipient-sig"},
            _verifier, "success")
        self.assertEqual(record["state"], "unknown")
        self.assertEqual(record["detail"], IGNORED)
        self.assertTrue(bstate["committed"])
        self.assertFalse(bstate["released"])

    def test_signed_on_timeout_ignored(self):
        record, bstate, _ = _do_reconcile(
            "jti-t1", {"no_effect": True, "sig": "recipient-sig"},
            _verifier, "timeout")
        self.assertEqual(record["state"], "unknown")
        self.assertEqual(record["detail"], IGNORED)
        self.assertTrue(bstate["committed"])
        self.assertFalse(bstate["released"])

    def test_ignored_record_verifies(self):
        record, _, _ = _do_reconcile(
            "jti-s2", {"no_effect": True, "sig": "recipient-sig"},
            _verifier, "success")
        self.assertTrue(bp.verify_reconciliation(record))

    def test_invalid_outcome_malformed(self):
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _do_reconcile(
                "jti-x1", {"no_effect": True, "sig": "recipient-sig"},
                _verifier, "maybe")
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_outcome_mismatch_malformed(self):
        refusal = {"no_effect": True, "sig": "recipient-sig",
                   "outcome": "success"}
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _do_reconcile("jti-x2", refusal, _verifier, "failure")
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_unsigned_still_refused(self):
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _do_reconcile("jti-u1", {"no_effect": True}, None,
                          "success")
        self.assertEqual(ctx.exception.code,
                         "permit-no-effect-unattested")


if __name__ == "__main__":
    unittest.main()
