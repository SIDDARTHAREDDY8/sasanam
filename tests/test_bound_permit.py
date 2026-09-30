#!/usr/bin/env python3
"""Unit tests for gov/bound_permit.py (wave-235 lane B).

Bound-permit conjunction: permit = decision AND mandate AND local
policy, each leg verified independently; atomic (iss, jti) consumption
in the wave-234 consumption ledger; unknown outcomes reconcile via jti,
never re-mint. Deterministic; no network; stdlib only.
"""

import copy
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


def _store(ledger, durable=True):
    # Wave-240: consumption runs through the recipient-side consume
    # store; the admission gate requires a durable store unless the
    # deployment explicitly opts into the single-node contract.
    return bp.InMemoryConsumeStore(ledger, durable=durable)


class ConsumeExecuteTest(unittest.TestCase):
    def test_consume_returns_receipt(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-consume")
        record = bp.consume_permit(permit, ledger, consume_store=store)
        self.assertEqual(record["outcome"], "consumed")
        self.assertEqual(record["step"], 13)
        self.assertIsNone(record["reason"])
        self.assertEqual(record["receipt"]["instance_digest"],
                         permit["instance_digest"])
        self.assertTrue(ledger.is_consumed(permit["instance_digest"]))

    def test_double_consume_replays_stored_receipt(self):
        # Wave-240 (saha S12): a replay returns the STORED receipt and
        # is recorded as a repeat -- never a second release. The old
        # "previously-consumed" raise is superseded at this seam (the
        # ledger still raises it underneath; the store translates).
        # Note: replay requires a recorded result; a re-present of a
        # claimed-but-incomplete permit is in-progress -> retryable
        # (see test_in_progress_is_retryable_not_replay).
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-double")
        first = bp.consume_permit(permit, ledger, consume_store=store)
        store.record_result("permit-authority", "jti-double",
                            {"executed": True})
        second = bp.consume_permit(permit, ledger, consume_store=store)
        self.assertEqual(second["outcome"], "replayed")
        self.assertTrue(second["repeat_recorded"])
        self.assertEqual(second["receipt"]["receipt_digest"],
                         first["receipt"]["receipt_digest"])

    def test_conflict_on_different_digest(self):
        # Wave-240 (saha S12, vector V08): same (iss, jti), different
        # content digest -> permit-idempotency-conflict, 409-style.
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-conflict")
        bp.consume_permit(permit, ledger, consume_store=store)
        forged = copy.deepcopy(permit)
        forged["decision_digest"] = "ab" * 32
        forged["instance_digest"] = bp._instance_digest(
            forged["iss"], forged["jti"], forged["decision_digest"],
            forged["mandate_digest"], forged["policy_digest"],
            forged["reconciliation_digest"])
        body = {k: forged[k] for k in bp._PERMIT_FIELDS}
        forged["permit_digest"] = bp._body_digest(body)
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.consume_permit(forged, ledger, consume_store=store)
        self.assertEqual(ctx.exception.code, "permit-idempotency-conflict")
        self.assertEqual(ctx.exception.verification_record["http_status"],
                         409)

    def test_execute_exactly_once(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-exec")
        calls = []

        def _execute(p):
            calls.append(p["jti"])
            return {"executed": p["jti"]}

        record, out = bp.execute_permit(
            permit, ledger, execute=_execute, consume_store=store)
        self.assertEqual(record["outcome"], "consumed")
        self.assertEqual(out, {"executed": "jti-exec"})
        # Replay: the STORED result returns, the executor is not
        # called again (wave-240 saha S12; supersedes the old
        # previously-consumed raise at this seam).
        record2, out2 = bp.execute_permit(
            permit, ledger, execute=_execute, consume_store=store)
        self.assertEqual(record2["outcome"], "replayed")
        self.assertTrue(record2["repeat_recorded"])
        self.assertEqual(out2, {"executed": "jti-exec"})
        self.assertEqual(calls, ["jti-exec"])

    def test_tampered_permit_never_executes(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-tamp")
        tampered = dict(permit)
        tampered["mandate_digest"] = "00" * 32
        calls = []
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.execute_permit(tampered, ledger, consume_store=store,
                              execute=lambda p: calls.append(p))
        self.assertEqual(ctx.exception.code, "permit-tampered")
        # The crypto step (6) fires before the state step (13).
        self.assertEqual(ctx.exception.verification_record["step"], 6)
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
        bp.consume_permit(permit, ledger, consume_store=_store(ledger))
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
        bp.consume_permit(permit, ledger, consume_store=_store(ledger))
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
        bp.consume_permit(permit, ledger, consume_store=_store(ledger))
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
        record = bp.consume_permit(fresh, ledger, consume_store=_store(ledger),
                                 registry=reg)
        self.assertEqual(record["outcome"], "consumed")

    def test_reissue_without_registry_could_not_check(self):
        # Wave-240 (saha S8.3): a re-issue binding that cannot be
        # checked fails closed -- never a partial record. The
        # permit-registry is the named dependency.
        reg = bp.PermitRegistry()
        permit = _issue(reg, jti="jti-rei-nr")
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        rec = bp.reconcile_unknown_outcome(permit, ledger, reg)
        fresh = bp.issue_permit(
            _decision(), _mandate(), _policy(), reg,
            iss="permit-authority", jti="jti-rei-nr",
            verify_decision=_accept, verify_mandate=_accept,
            verify_policy=_accept, reconciliation=rec)
        record = bp.verify_presentation(fresh, consume_store=store)
        self.assertEqual(record["outcome"], "could-not-check")
        self.assertEqual(record["step"], 8)
        self.assertEqual(record["reason"], "permit-registry-unavailable")
        self.assertEqual(record["dependency"], "permit-registry")
        self.assertEqual(record["http_status"], 503)
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.consume_permit(fresh, ledger, consume_store=_store(ledger))
        self.assertEqual(ctx.exception.code,
                         "permit-registry-unavailable")

    def test_reissue_after_completed_refused(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        permit = _issue(reg, jti="jti-reic")
        bp.consume_permit(permit, ledger, consume_store=_store(ledger))
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


class VerifyPresentationTest(unittest.TestCase):
    """Wave-240: the 13-step verification order and its record."""

    def test_record_never_partial(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-vp")
        record = bp.verify_presentation(permit, consume_store=store)
        self.assertEqual(
            (record["outcome"], record["step"], record["reason"]),
            ("verified", 13, None))
        self.assertIsNotNone(record["receipt"])
        self.assertEqual(record["iss"], "permit-authority")

    def test_absence_is_no_fallback(self):
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        record = bp.verify_presentation(None, consume_store=store)
        self.assertEqual(record["outcome"], "refused")
        self.assertEqual(record["step"], 1)
        self.assertEqual(record["reason"], "permit-no-fallback")

    def test_store_unavailable_could_not_check(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        dead = bp.InMemoryConsumeStore(ledger, durable=True,
                                       available=False)
        permit = _issue(reg, jti="jti-vc")
        record = bp.verify_presentation(permit, consume_store=dead)
        self.assertEqual(record["outcome"], "could-not-check")
        self.assertEqual(record["step"], 9)
        self.assertEqual(record["reason"],
                         "permit-consume-store-unavailable")
        self.assertEqual(record["dependency"], "consume-store")
        self.assertEqual(record["http_status"], 503)

    def test_admission_gate_refuses_non_durable(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        flimsy = bp.InMemoryConsumeStore(cl.ConsumptionLedger())
        permit = _issue(reg, jti="jti-vg")
        record = bp.verify_presentation(permit, consume_store=flimsy)
        self.assertEqual(record["outcome"], "refused")
        self.assertEqual(record["step"], 10)
        self.assertEqual(record["reason"],
                         "permit-consume-store-not-durable")
        # Explicit single-node opt-out documents the contract.
        ok = bp.verify_presentation(permit, consume_store=flimsy,
                                    require_durable_store=False)
        self.assertEqual(ok["outcome"], "verified")

    def test_local_policy_denial_never_consumes(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-vl")

        def _deny(record):
            raise _LegRefused("local-policy")

        record = bp.verify_presentation(permit, consume_store=store,
                                        local_policy_verifier=_deny)
        self.assertEqual(record["outcome"], "refused")
        self.assertEqual(record["step"], 11)
        self.assertEqual(record["reason"], "local-policy")
        self.assertIsNone(store.lookup("permit-authority", "jti-vl"))
        self.assertFalse(ledger.is_consumed(permit["instance_digest"]))

    def test_consume_permit_raises_typed_refusal(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        dead = bp.InMemoryConsumeStore(ledger, durable=True,
                                       available=False)
        permit = _issue(reg, jti="jti-vr")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.consume_permit(permit, ledger, consume_store=dead)
        self.assertEqual(ctx.exception.code,
                         "permit-consume-store-unavailable")
        self.assertEqual(
            ctx.exception.verification_record["outcome"],
            "could-not-check")

    def test_in_progress_is_retryable_not_replay(self):
        # Wave-240 (saha S12): same (iss, jti) + same digest while
        # the effect is in flight elsewhere -> retryable, never a
        # replay of a result that does not exist yet.
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        permit = _issue(reg, jti="jti-vp-ip")
        outcome, _slot = store.claim(permit)
        self.assertEqual(outcome, "claimed")
        record = bp.verify_presentation(permit, consume_store=store)
        self.assertEqual(record["outcome"], "retryable")
        self.assertEqual(record["step"], 13)
        self.assertEqual(record["reason"], "permit-in-progress")
        self.assertEqual(record["http_status"], 503)
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.consume_permit(permit, ledger, consume_store=store)
        self.assertEqual(ctx.exception.code, "permit-in-progress")
        self.assertEqual(
            ctx.exception.verification_record["outcome"], "retryable")
        # Once the first holder records its result, the same
        # presentation replays the stored result.
        store.record_result("permit-authority", "jti-vp-ip",
                            {"done": True})
        record2, out2 = bp.execute_permit(
            permit, ledger, execute=lambda p: {"nope": True},
            consume_store=store)
        self.assertEqual(record2["outcome"], "replayed")
        self.assertEqual(out2, {"done": True})


class BudgetLedgerTest(unittest.TestCase):
    """Wave-240: outcome-tied budget accounting (saha S13)."""

    def test_commit_on_success(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bs")
        bp.execute_permit(permit, ledger, execute=lambda p: "ok",
                          consume_store=store, budget=budget)
        state = budget.state("permit-authority", "jti-bs")
        self.assertEqual(state,
                         {"kind": "spend", "committed": True,
                          "released": False})

    def test_commit_on_timeout(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bt")

        def _execute(p):
            raise TimeoutError("timed out")

        with self.assertRaises(TimeoutError):
            bp.execute_permit(permit, ledger, execute=_execute,
                              consume_store=store, budget=budget)
        state = budget.state("permit-authority", "jti-bt")
        self.assertTrue(state["committed"])
        self.assertFalse(state["released"])

    def test_commit_on_any_execute_exception(self):
        # Wave-240: the attempt consumed budget for ANY execute
        # exception, not only timeout. saha S13's release causes
        # (not_attempted, signed no_effect) do not cover a failed
        # attempt, so the budget stays committed.
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bg")

        def _execute(p):
            raise ValueError("deterministic business failure")

        with self.assertRaises(ValueError):
            bp.execute_permit(permit, ledger, execute=_execute,
                              consume_store=store, budget=budget)
        state = budget.state("permit-authority", "jti-bg")
        self.assertTrue(state["committed"])
        self.assertFalse(state["released"])

    def test_release_on_not_attempted(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bn")
        record = bp.reconcile_unknown_outcome(permit, ledger, reg,
                                              budget=budget)
        self.assertEqual(record["state"], "not-executed")
        self.assertTrue(
            budget.state("permit-authority", "jti-bn")["released"])

    def test_unsigned_no_effect_refused(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bu")
        bp.consume_permit(permit, ledger, consume_store=store)
        with self.assertRaises(bp.BoundPermitError) as ctx:
            bp.reconcile_unknown_outcome(
                permit, ledger, reg, budget=budget,
                no_effect_refusal={"no_effect": True},
                verify_refusal_signature=None)
        self.assertEqual(ctx.exception.code, "permit-no-effect-unattested")
        state = budget.state("permit-authority", "jti-bu")
        self.assertFalse(state["released"])

    def test_signed_no_effect_releases(self):
        reg = bp.PermitRegistry()
        ledger = cl.ConsumptionLedger()
        store = _store(ledger)
        budget = bp.BudgetLedger()
        permit = _issue(reg, jti="jti-bsg")
        bp.consume_permit(permit, ledger, consume_store=store)
        refusal = {"no_effect": True, "sig": "recipient-sig"}
        record = bp.reconcile_unknown_outcome(
            permit, ledger, reg, budget=budget,
            no_effect_refusal=refusal,
            verify_refusal_signature=lambda r: r.get("sig") ==
            "recipient-sig")
        self.assertEqual(record["state"], "not-executed")
        self.assertTrue(
            budget.state("permit-authority", "jti-bsg")["released"])

    def test_rate_budget_never_released(self):
        budget = bp.BudgetLedger()
        budget.commit("permit-authority", "jti-br", kind="rate")
        with self.assertRaises(bp.BoundPermitError) as ctx:
            budget.release("permit-authority", "jti-br",
                           on="not_attempted")
        self.assertEqual(ctx.exception.code,
                         "permit-rate-budget-unreleasable")
        self.assertFalse(
            budget.state("permit-authority", "jti-br")["released"])


class TrustTierTest(unittest.TestCase):
    def test_trust_tier_binds_instance(self):
        reg = bp.PermitRegistry()
        high = _issue(reg, jti="jti-tier-h", decision=_decision("high"))
        low = _issue(reg, jti="jti-tier-l", decision=_decision("low"))
        self.assertNotEqual(high["instance_digest"],
                            low["instance_digest"])
        ledger = cl.ConsumptionLedger()
        bp.consume_permit(high, ledger, consume_store=_store(ledger))
        record = bp.consume_permit(low, ledger, consume_store=_store(ledger))
        self.assertEqual(record["outcome"], "consumed")


if __name__ == "__main__":
    unittest.main()
