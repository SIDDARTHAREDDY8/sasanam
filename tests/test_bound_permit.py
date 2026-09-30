#!/usr/bin/env python3
"""Unit tests for gov/bound_permit.py (wave-235 lane B).

Bound-permit conjunction: permit = decision AND mandate AND local
policy, each leg verified independently; atomic (iss, jti) consumption
in the wave-234 consumption ledger; unknown outcomes reconcile via jti,
never re-mint. Deterministic; no network; stdlib only.
"""

import hashlib
import json
import unittest

from gov import bound_permit as bp
from gov import consumption_ledger as cl


def _accept(record):
    return True


class _LegRefused(Exception):
    def __init__(self, code, message="refused"):
        super().__init__(message)
        self.code = code


def _decision(trust_tier="high"):
    return {"action": "deploy", "target": "prod",
            "trust_tier": trust_tier, "decision": "permit"}


def _mandate():
    return {"mandate": "ops-oncall", "scope": "prod-deploy"}


def _policy():
    return {"policy_rev": "r42", "rules_digest": "ab" * 32}


_MISSING = object()


def _issue(reg, iss="permit-authority", jti="jti-1", decision=_MISSING,
           mandate="dflt", policy="dflt", **kw):
    return bp.issue_permit(
        _decision() if decision is _MISSING else decision,
        _mandate() if mandate == "dflt" else mandate,
        _policy() if policy == "dflt" else policy,
        reg, iss=iss, jti=jti,
        verify_decision=_accept, verify_mandate=_accept,
        verify_policy=_accept, **kw)


class IssueTest(unittest.TestCase):
    def test_happy_path(self):
        reg = bp.PermitRegistry()
        permit = _issue(reg)
        self.assertTrue(bp.verify_permit(permit))
        self.assertEqual(permit["iss"], "permit-authority")
        self.assertEqual(permit["jti"], "jti-1")
        self.assertEqual(permit["legs_verified"],
                         ["decision", "mandate", "policy"])
        self.assertEqual(permit["reconciliation_digest"], "")
        entry = reg.lookup("permit-authority", "jti-1")
        self.assertIsNotNone(entry["permit"])
        self.assertIsNone(entry["reconciliation"])

    def test_decision_absent(self):
        reg = bp.PermitRegistry()
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, decision=None)
        self.assertEqual(ctx.exception.code, "permit-decision-absent")

    def test_mandate_absent(self):
        reg = bp.PermitRegistry()
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, mandate=None)
        self.assertEqual(ctx.exception.code, "permit-mandate-absent")

    def test_policy_absent(self):
        reg = bp.PermitRegistry()
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, policy=None)
        self.assertEqual(ctx.exception.code, "permit-policy-absent")

    def test_non_dict_leg_malformed(self):
        reg = bp.PermitRegistry()
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, mandate=["not", "a", "dict"])
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_empty_iss_malformed(self):
        reg = bp.PermitRegistry()
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, iss="")
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_non_registry_malformed(self):
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.issue_permit(_decision(), _mandate(), _policy(), {},
                            iss="i", jti="j", verify_decision=_accept,
                            verify_mandate=_accept, verify_policy=_accept)
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_duplicate_jti_refused(self):
        reg = bp.PermitRegistry()
        _issue(reg, jti="jti-dup")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            _issue(reg, jti="jti-dup")
        self.assertEqual(ctx.exception.code, "permit-jti-duplicate")

    def test_registry_lookup_returns_copies(self):
        reg = bp.PermitRegistry()
        _issue(reg, jti="jti-copy")
        entry = reg.lookup("permit-authority", "jti-copy")
        entry["permit"]["jti"] = "mutated"
        self.assertEqual(reg.lookup("permit-authority",
                                    "jti-copy")["permit"]["jti"], "jti-copy")


class LegRefusalTest(unittest.TestCase):
    def _issue_refusing(self, reg, leg, code):
        def _refuse(record):
            raise _LegRefused(code)
        kwargs = {"verify_decision": _accept, "verify_mandate": _accept,
                  "verify_policy": _accept}
        kwargs["verify_" + leg] = _refuse
        return bp.issue_permit(_decision(), _mandate(), _policy(), reg,
                               iss="permit-authority", jti="jti-leg",
                               **kwargs)

    def test_each_leg_refusal_propagates_exact_code(self):
        for leg in ("decision", "mandate", "policy"):
            reg = bp.PermitRegistry()
            with self.assertRaises(bp.BoundPermitError) as ctx:
                self._issue_refusing(reg, leg,
                                     "evaluation-incomplete-details")
            self.assertEqual(ctx.exception.code,
                             "evaluation-incomplete-details")
            self.assertEqual(ctx.exception.leg, leg)
            # A refused issue claims nothing.
            self.assertIsNone(reg.lookup("permit-authority", "jti-leg"))

    def test_unnamed_refusal_unmapped(self):
        reg = bp.PermitRegistry()

        def _refuse_bare(record):
            raise ValueError("no code here")

        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.issue_permit(_decision(), _mandate(), _policy(), reg,
                            iss="permit-authority", jti="jti-unmapped",
                            verify_decision=_refuse_bare,
                            verify_mandate=_accept, verify_policy=_accept)
        self.assertEqual(ctx.exception.code,
                         "permit-leg-refusal-unmapped")


class ConsumeExecuteTest(unittest.TestCase):
    def test_consume_returns_receipt(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-consume")
        receipt = bp.consume_permit(permit, ledger)
        self.assertEqual(receipt["outcome"], "consumed")
        self.assertEqual(receipt["instance_digest"],
                         permit["instance_digest"])
        self.assertTrue(ledger.is_consumed(permit["instance_digest"]))

    def test_double_consume_named_outcome(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-double")
        first = bp.consume_permit(permit, ledger)
        with self.assertRaises(cl.ConsumptionError) as ctx:
            bp.consume_permit(permit, ledger)
        self.assertEqual(ctx.exception.code, "previously-consumed")
        self.assertEqual(ctx.exception.receipt["receipt_digest"],
                         first["receipt_digest"])

    def test_execute_exactly_once(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-exec")
        calls = []

        def _execute(p):
            calls.append(p["jti"])
            return {"executed": p["jti"]}

        receipt, out = bp.execute_permit(
            permit, ledger, execute=_execute)
        self.assertEqual(receipt["outcome"], "consumed")
        self.assertEqual(out, {"executed": "jti-exec"})
        with self.assertRaises(cl.ConsumptionError) as ctx:
            bp.execute_permit(permit, ledger, execute=_execute)
        self.assertEqual(ctx.exception.code, "previously-consumed")
        self.assertEqual(calls, ["jti-exec"])

    def test_tampered_permit_never_executes(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-tamp")
        tampered = dict(permit)
        tampered["mandate_digest"] = "00" * 32
        calls = []
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.execute_permit(tampered, ledger,
                              execute=lambda p: calls.append(p))
        self.assertEqual(ctx.exception.code, "permit-tampered")
        self.assertEqual(calls, [])
        self.assertFalse(ledger.is_consumed(permit["instance_digest"]))

    def test_non_callable_execute_malformed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-execbad")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.execute_permit(permit, ledger, execute="not-callable")
        self.assertEqual(ctx.exception.code, "permit-malformed")


class VerifyPermitTest(unittest.TestCase):
    def test_malformed_shape(self):
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.verify_permit({"version": 1})
        self.assertEqual(ctx.exception.code, "permit-malformed")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.verify_permit("not-a-dict")
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_tampered_instance_digest(self):
        reg = bp.PermitRegistry()
        permit = _issue(reg, jti="jti-vt")
        bad = dict(permit)
        bad["instance_digest"] = "ff" * 32
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.verify_permit(bad)
        self.assertEqual(ctx.exception.code, "permit-tampered")

    def test_tampered_jti_detected(self):
        # (iss, jti) bind into the instance digest: editing the jti
        # breaks the recomputation.
        reg = bp.PermitRegistry()
        permit = _issue(reg, jti="jti-vj")
        bad = dict(permit)
        bad["jti"] = "jti-other"
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.verify_permit(bad)
        self.assertEqual(ctx.exception.code, "permit-tampered")


class ReconcileTest(unittest.TestCase):
    def test_unknown_when_consumed_without_evidence(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-rec")
        bp.consume_permit(permit, ledger)
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        self.assertEqual(rec["state"], "unknown")
        self.assertEqual(rec["jti"], "jti-rec")
        self.assertEqual(rec["instance_digest"], permit["instance_digest"])
        self.assertTrue(bp.verify_reconciliation(rec))
        # Registered: the slot now carries the reconciliation.
        self.assertIsNotNone(
            reg.lookup("permit-authority", "jti-rec")["reconciliation"])

    def test_not_executed_when_never_consumed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-recn")
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        self.assertEqual(rec["state"], "not-executed")

    def test_completed_with_bound_evidence(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-recc")
        bp.consume_permit(permit, ledger)
        evidence = {"iss": "permit-authority", "jti": "jti-recc",
                    "executed_at": "2026-09-30T00:00:00+00:00"}
        rec = bp.reconcile_unknown_outcome(
            permit, ledger, reg, execution_evidence=evidence,
            verify_execution=_accept)
        self.assertEqual(rec["state"], "completed")
        self.assertEqual(len(rec["evidence_digest"]), 64)

    def test_evidence_for_other_jti_malformed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-rece")
        evidence = {"iss": "permit-authority", "jti": "jti-OTHER"}
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.reconcile_unknown_outcome(
                permit, ledger, reg, execution_evidence=evidence,
                verify_execution=_accept)
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_evidence_without_verifier_malformed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-recv")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.reconcile_unknown_outcome(
                permit, ledger, reg,
                execution_evidence={"iss": "permit-authority",
                                    "jti": "jti-recv"})
        self.assertEqual(ctx.exception.code, "permit-malformed")

    def test_reconcile_never_mints_permit(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-recm")
        bp.consume_permit(permit, ledger)
        before = json.dumps(reg.lookup("permit-authority", "jti-recm"),
                            sort_keys=True)
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        after = json.dumps(reg.lookup("permit-authority", "jti-recm"),
                           sort_keys=True)
        # The permit record is byte-identical: reconciliation only
        # ADDS the reconciliation record, never re-issues.
        self.assertEqual(json.loads(before)["permit"],
                         json.loads(after)["permit"])
        self.assertEqual(rec["state"], "unknown")

    def test_reissue_after_not_executed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-rei")
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        self.assertEqual(rec["state"], "not-executed")
        fresh = bp.issue_permit(
            _decision(), _mandate(), _policy(), reg,
            iss="permit-authority", jti="jti-rei",
            verify_decision=_accept, verify_mandate=_accept,
            verify_policy=_accept, reconciliation=rec)
        self.assertEqual(fresh["reconciliation_digest"],
                         rec["record_digest"])
        self.assertNotEqual(fresh["instance_digest"],
                            permit["instance_digest"])
        self.assertTrue(bp.verify_permit(fresh))
        receipt = bp.consume_permit(fresh, ledger)
        self.assertEqual(receipt["outcome"], "consumed")

    def test_reissue_after_completed_refused(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-reic")
        bp.consume_permit(permit, ledger)
        rec = bp.reconcile_unknown_outcome(
            permit, ledger, reg,
            execution_evidence={"iss": "permit-authority",
                                "jti": "jti-reic"},
            verify_execution=_accept)
        self.assertEqual(rec["state"], "completed")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.issue_permit(
                _decision(), _mandate(), _policy(), reg,
                iss="permit-authority", jti="jti-reic",
                verify_decision=_accept, verify_mandate=_accept,
                verify_policy=_accept, reconciliation=rec)
        self.assertEqual(ctx.exception.code, "permit-jti-duplicate")

    def test_reissue_with_foreign_reconciliation_malformed(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-reif")
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        other = dict(rec)
        other["jti"] = "jti-forged"
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.issue_permit(
                _decision(), _mandate(), _policy(), reg,
                iss="permit-authority", jti="jti-reif",
                verify_decision=_accept, verify_mandate=_accept,
                verify_policy=_accept, reconciliation=other)
        self.assertIn(ctx.exception.code,
                      ("permit-malformed", "permit-tampered"))

    def test_tampered_reconciliation_detected(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-rect")
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        bad = dict(rec)
        bad["state"] = "completed"
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.verify_reconciliation(bad)
        self.assertEqual(ctx.exception.code, "permit-tampered")


class TrustTierTest(unittest.TestCase):
    def test_trust_tier_binds_instance(self):
        reg = bp.PermitRegistry()
        high = _issue(reg, jti="jti-tier-h", decision=_decision("high"))
        low = _issue(reg, jti="jti-tier-l", decision=_decision("low"))
        self.assertNotEqual(high["instance_digest"],
                            low["instance_digest"])
        ledger = cl.ConsumptionLedger()
        bp.consume_permit(high, ledger)
        receipt = bp.consume_permit(low, ledger)
        self.assertEqual(receipt["outcome"], "consumed")


if __name__ == "__main__":
    unittest.main()
