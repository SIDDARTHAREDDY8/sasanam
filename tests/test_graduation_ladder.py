#!/usr/bin/env python3
"""Unit tests for wave-198: Gatekeeper graduation ladder.

Public seams only:
  - gov.mode_ledger: ModeLedger (register/observe/review/heartbeat/
    graduation/demotion/emergency/quorum/chain) and
    WarnDigestAggregator.
  - gov.policy.PolicyEngine: mode/pinned load validation, decide()
    two-phase routing, ladder convenience methods.
  - gov.decision_contract: Decision/Diagnostics/RuleHit additive
    ladder fields and their serialization.
  - gov.decision_bom: the optional inputs.ladder section.
  - gov.executor.ToolExecutor._surface_warn_digest /
    flush_warn_digests (warn telemetry aggregation, verdict untouched).

Stdlib only. $0 spend. Deterministic (injectable clocks; no wall-clock
dependence in ledger tests).
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import mode_ledger as ml  # noqa: E402
from gov.decision_contract import (  # noqa: E402
    Decision,
    Diagnostics,
    Request,
    RuleHit,
)
from gov.policy import PolicyEngine  # noqa: E402
from gov import decision_bom  # noqa: E402
from gov import policy_export  # noqa: E402


class _Clock:
    def __init__(self, start=1_000_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, secs):
        self.now += secs


def _engine(policy_text):
    return PolicyEngine.from_text(policy_text)


def _req(tool):
    return Request.from_action({"tool": tool, "args": {}})


LADDER_POL = """\
version: 1
approvals:
  quorum:
    min_approvals: 2
    eligible_principals: [op1, op2]
policies:
  - id: pinned-exfil
    effect: deny
    pinned: true
    match:
      tool: api_call
    reason: pinned exfil forbid
  - id: obs-rule
    effect: deny
    mode: observe
    match:
      tool: write_file
    reason: observing
  - id: warn-rule
    effect: deny
    mode: warn
    match:
      tool: delete_file
    reason: warning
  - id: plain-allow
    effect: allow
    match:
      tool: read_file
    reason: reads ok
"""


# ---------------------------------------------------------------- ledger

class TestModeLedgerBasics(unittest.TestCase):
    def test_register_rejects_unknown_mode(self):
        ledger = ml.ModeLedger()
        with self.assertRaises(ml.ModeLedgerError):
            ledger.register_rule("r", mode="bogus")

    def test_register_rejects_pinned_non_deny(self):
        ledger = ml.ModeLedger()
        with self.assertRaises(ml.ModeLedgerError):
            ledger.register_rule("r", mode="observe", pinned=True)

    def test_register_rejects_non_bool_pinned(self):
        ledger = ml.ModeLedger()
        with self.assertRaises(ml.ModeLedgerError):
            ledger.register_rule("r", pinned="yes")

    def test_observe_records_violations_for_ladder_modes_only(self):
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("o", mode="observe")
        ledger.register_rule("w", mode="warn")
        ledger.register_rule("d", mode="deny")
        ledger.observe("o", mode="observe", matched=True,
                       nominal_effect="deny")
        ledger.observe("w", mode="warn", matched=True,
                       nominal_effect="deny")
        ledger.observe("d", mode="deny", matched=True,
                       nominal_effect="deny")
        self.assertEqual(ledger.stats("o")["violations"], 1)
        self.assertEqual(ledger.stats("w")["violations"], 1)
        self.assertEqual(ledger.stats("d")["violations"], 0)
        # ... but every evaluation is counted.
        self.assertEqual(ledger.stats("d")["evaluated"], 1)

    def test_chain_verifies_and_detects_tamper(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("o", mode="observe")
        ledger.observe("o", mode="observe", matched=True,
                       nominal_effect="deny")
        ledger.record_review("o", correct=True, reviewer="op1")
        ok, _ = ledger.verify_chain()
        self.assertTrue(ok)
        ledger._chain[0]["rule_id"] = "tampered"
        ok, reason = ledger.verify_chain()
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    def test_per_rule_chain_verifies_independently(self):
        # Wave-198 §3.2: each rule's records form their own hash
        # chain, verifiable without the global interleave.
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("a", mode="observe")
        ledger.register_rule("b", mode="warn")
        for _ in range(3):
            ledger.observe("a", mode="observe", matched=True,
                           nominal_effect="deny")
        for _ in range(2):
            ledger.observe("b", mode="warn", matched=True,
                           nominal_effect="deny")
        ok, reason = ledger.verify_rule_chain("a")
        self.assertTrue(ok, reason)
        ok, reason = ledger.verify_rule_chain("b")
        self.assertTrue(ok, reason)
        # rule_seq is per-rule: both start at 1 despite the global
        # interleave.
        a_seqs = [r["rule_seq"] for r in ledger._chain
                  if r["rule_id"] == "a"]
        self.assertEqual(a_seqs, [1, 2, 3])
        ok, reason = ledger.verify_rule_chain("nope")
        self.assertFalse(ok)

    def test_per_rule_chain_detects_tamper_and_isolation(self):
        # Tampering with rule A's record breaks A's chain but not
        # B's: per-rule isolation holds.
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("a", mode="observe")
        ledger.register_rule("b", mode="observe")
        ledger.observe("a", mode="observe", matched=True,
                       nominal_effect="deny")
        ledger.observe("b", mode="observe", matched=True,
                       nominal_effect="deny")
        target = next(r for r in ledger._chain
                      if r["rule_id"] == "a")
        target["rule_prev"] = "forged"
        ok, reason = ledger.verify_rule_chain("a")
        self.assertFalse(ok)
        self.assertIn("rule_prev", reason)
        ok, reason = ledger.verify_rule_chain("b")
        self.assertTrue(ok, reason)
        # The global chain also breaks (the digest covers rule_prev).
        ok, _ = ledger.verify_chain()
        self.assertFalse(ok)

    def test_review_requires_attested_reviewer(self):
        ledger = ml.ModeLedger()
        with self.assertRaises(ml.ModeLedgerError):
            ledger.record_review("r", correct=True, reviewer="  ")
        with self.assertRaises(ml.ModeLedgerError):
            ledger.record_review("r", correct=True, reviewer="")

    def test_fp_rate_none_without_reviews(self):
        ledger = ml.ModeLedger()
        ledger.register_rule("r", mode="observe")
        self.assertIsNone(ledger.stats("r")["fp_rate"])


class TestQuorum(unittest.TestCase):
    def _q(self, approvers, cfg=None):
        return ml.ModeLedger._check_quorum(approvers, cfg)

    def test_two_distinct_humans_meet_default(self):
        ok, _ = self._q(["op1", "op2"])
        self.assertTrue(ok)

    def test_single_approver_refused(self):
        ok, reason = self._q(["op1"])
        self.assertFalse(ok)
        self.assertIn("quorum", reason)

    def test_duplicate_approver_refused(self):
        ok, reason = self._q(["op1", "op1"])
        self.assertFalse(ok)
        self.assertIn("duplicate", reason)

    def test_deny_veto_blocks(self):
        ok, reason = self._q([("op1", True), ("op2", False)])
        self.assertFalse(ok)
        self.assertIn("veto", reason)

    def test_ineligible_principal_refused(self):
        cfg = {"eligible_principals": ("op1", "op2"),
               "min_approvals": 2}
        ok, reason = self._q(["agent:x", "op1"], cfg)
        self.assertFalse(ok)
        self.assertIn("eligible", reason)

    def test_config_min_raises_bar(self):
        cfg = {"eligible_principals": ("op1", "op2", "op3"),
               "min_approvals": 3}
        ok, _ = self._q(["op1", "op2"], cfg)
        self.assertFalse(ok)
        ok, _ = self._q(["op1", "op2", "op3"], cfg)
        self.assertTrue(ok)

    def test_malformed_approver_entry_refused(self):
        ok, _ = self._q([{"principal": "op1"}])
        self.assertFalse(ok)
        ok, _ = self._q([])
        self.assertFalse(ok)


def _evidence(ledger, rule_id, *, evaluated=100, violations=10,
              reviews_correct=25, reviews_wrong=0, acks=6):
    for i in range(evaluated):
        ledger.observe(rule_id,
                       mode=ledger.stats(rule_id)["mode"],
                       matched=(i < violations),
                       nominal_effect="deny")
    for _ in range(reviews_correct):
        ledger.record_review(rule_id, correct=True, reviewer="op1")
    for _ in range(reviews_wrong):
        ledger.record_review(rule_id, correct=False, reviewer="op2")
    for _ in range(acks):
        ledger.record_warning_ack(rule_id, operator="op1")


class TestGraduation(unittest.TestCase):
    def test_observe_to_warn_happy_path(self):
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r")
        ok, _ = ledger.apply_graduation("r", "warn",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        self.assertEqual(ledger.stats("r")["mode"], "warn")
        hist = ledger.mode_history("r")
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["old_mode"], "observe")
        self.assertEqual(hist[0]["new_mode"], "warn")
        self.assertEqual(hist[0]["approvers"], ["op1", "op2"])
        self.assertEqual(hist[0]["kind"], "graduation")

    def test_zero_violations_never_graduate(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        for _ in range(200):
            ledger.observe("r", mode="observe", matched=False)
        for _ in range(25):
            ledger.record_review("r", correct=True, reviewer="op1")
        ok, reasons = ledger.evaluate_graduation(
            "r", "warn", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("zero violations" in r for r in reasons))

    def test_insufficient_evaluations_refused(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r", evaluated=50)
        ok, reasons = ledger.evaluate_graduation(
            "r", "warn", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("evaluated" in r for r in reasons))

    def test_high_fp_refused_despite_quorum(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r", reviews_correct=13, reviews_wrong=7)
        ok, reasons = ledger.evaluate_graduation(
            "r", "warn",
            approvers=["op1", "op2", "op3", "op4", "op5"])
        self.assertFalse(ok)
        self.assertTrue(any("FP" in r for r in reasons))

    def test_fp_at_boundary_refused(self):
        # Exactly 5% is not < 5%.
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r", reviews_correct=19, reviews_wrong=1)
        ok, _ = ledger.evaluate_graduation(
            "r", "warn", approvers=["op1", "op2"])
        self.assertFalse(ok)

    def test_skip_rung_refused(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r")
        ok, reasons = ledger.evaluate_graduation(
            "r", "deny", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("one rung" in r for r in reasons))

    def test_pinned_never_graduates(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="deny", pinned=True)
        ok, reasons = ledger.evaluate_graduation(
            "r", "warn", approvers=["op1", "op2", "op3"])
        self.assertFalse(ok)
        self.assertTrue(any("pinned" in r for r in reasons))

    def test_warn_to_deny_needs_acks_and_tight_fp(self):
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="observe")
        # §3.4 "longer window": warn->deny needs 200 evaluated / 20
        # violations (2x the observe->warn bar).
        _evidence(ledger, "r", acks=0, evaluated=200, violations=20)
        ok, _ = ledger.apply_graduation("r", "warn",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        # No acks yet -> refused.
        ok, reasons = ledger.evaluate_graduation(
            "r", "deny", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("acknowledged" in r for r in reasons))
        for _ in range(6):
            ledger.record_warning_ack("r", operator="op2")
        ok, _ = ledger.apply_graduation("r", "deny",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        self.assertEqual(ledger.stats("r")["mode"], "deny")

    def test_warn_stale_blocks_graduation(self):
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r")
        ok, _ = ledger.apply_graduation("r", "warn",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        clock.advance(ml.WARN_MAX_DWELL_SECS + 1)
        self.assertEqual(ledger.warn_stale_rules(), ("r",))
        for _ in range(6):
            ledger.record_warning_ack("r", operator="op2")
        ok, reasons = ledger.evaluate_graduation(
            "r", "deny", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("warn-stale" in r for r in reasons))

    def test_heartbeat_recorded(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="observe")
        ledger.heartbeat("r", exercised=False, detail="no traffic")
        ledger.heartbeat("r", exercised=True, detail="canary matched")
        self.assertEqual(ledger.stats("r")["heartbeats"], 2)
        ok, _ = ledger.verify_chain()
        self.assertTrue(ok)


class TestDemotion(unittest.TestCase):
    def _deny_ledger(self):
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="observe")
        # §3.4 "longer window" for warn->deny.
        _evidence(ledger, "r", evaluated=200, violations=20)
        ok, _ = ledger.apply_graduation("r", "warn",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        for _ in range(6):
            ledger.record_warning_ack("r", operator="op1")
        ok, _ = ledger.apply_graduation("r", "deny",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        return ledger, clock

    def test_normal_demotion_needs_quorum(self):
        ledger, _ = self._deny_ledger()
        pid = ledger.propose_demotion("r", "warn", reason="FP spike",
                                      requested_by="op1")
        ok, _ = ledger.approve_demotion(pid, approvers=["op1"])
        self.assertFalse(ok)
        self.assertEqual(ledger.stats("r")["mode"], "deny")
        ok, _ = ledger.approve_demotion(pid, approvers=["op1", "op2"])
        self.assertTrue(ok)
        self.assertEqual(ledger.stats("r")["mode"], "warn")

    def test_demotion_never_automatic(self):
        ledger, _ = self._deny_ledger()
        # An FP spike creates a proposal; nothing applies itself.
        pid = ledger.propose_demotion("r", "warn", reason="FP spike",
                                      requested_by="op1")
        self.assertEqual(ledger.stats("r")["mode"], "deny")
        self.assertEqual(ledger._proposals[pid]["status"], "open")

    def test_pinned_demotion_refused(self):
        ledger = ml.ModeLedger(clock=_Clock())
        ledger.register_rule("r", mode="deny", pinned=True)
        with self.assertRaises(ml.ModeLedgerError):
            ledger.propose_demotion("r", "warn", reason="x",
                                    requested_by="op1")
        with self.assertRaises(ml.ModeLedgerError):
            ledger.emergency_demote("r", "warn", operator="op1",
                                    reason="x")

    def test_emergency_demote_mandates_review(self):
        ledger, clock = self._deny_ledger()
        rec = ledger.emergency_demote("r", "warn", operator="op1",
                                      reason="blocking prod")
        self.assertEqual(ledger.stats("r")["mode"], "warn")
        pending = ledger.stats("r")["pending_emergency_review"]
        self.assertIsNotNone(pending)
        self.assertEqual(pending["operator"], "op1")
        # Before the deadline: nothing overdue.
        self.assertEqual(ledger.check_emergency_reviews(), ())
        # After: re-escalation surfaces.
        clock.advance(ml.EMERGENCY_REVIEW_SECS + 1)
        overdue = ledger.check_emergency_reviews()
        self.assertEqual(len(overdue), 1)
        # Post-hoc quorum resolves it.
        ok, _ = ledger.resolve_emergency_review(
            "r", approvers=["op1", "op2"])
        self.assertTrue(ok)
        self.assertIsNone(
            ledger.stats("r")["pending_emergency_review"])
        self.assertEqual(ledger.check_emergency_reviews(), ())

    def test_proposal_replay_refused(self):
        ledger, _ = self._deny_ledger()
        pid = ledger.propose_demotion("r", "warn", reason="x",
                                      requested_by="op1")
        ok, _ = ledger.approve_demotion(pid, approvers=["op1", "op2"])
        self.assertTrue(ok)
        ok, reasons = ledger.approve_demotion(pid,
                                              approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("not open" in r for r in reasons))

    def test_mode_change_record_carries_fp_stats_snapshot(self):
        # Wave-198 §3.5: every mode-change record carries rule id,
        # old->new, approvers, AND the FP stats snapshot the quorum
        # acted on.
        ledger, _ = self._deny_ledger()
        hist = ledger.mode_history("r")
        self.assertEqual([h["new_mode"] for h in hist], ["warn", "deny"])
        for h in hist:
            snap = h.get("stats")
            self.assertIsInstance(snap, dict)
            self.assertGreaterEqual(snap["evaluated"], 200)
            self.assertGreaterEqual(snap["violations"], 20)
            self.assertEqual(snap["reviewed"],
                             snap["reviewed_correct"]
                             + snap["reviewed_wrong"])
            self.assertIsNotNone(snap["fp_rate"])
            self.assertLess(snap["fp_rate"], 0.05)

    def test_warn_to_deny_longer_window_refused(self):
        # Wave-198 §3.4: the warn->deny window is LONGER than the
        # observe->warn window. 150 evaluated / 15 violations clears
        # the observe bar but not warn->deny (200/20).
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="observe")
        _evidence(ledger, "r", evaluated=150, violations=15)
        ok, _ = ledger.apply_graduation("r", "warn",
                                        approvers=["op1", "op2"])
        self.assertTrue(ok)
        for _ in range(6):
            ledger.record_warning_ack("r", operator="op1")
        ok, reasons = ledger.evaluate_graduation(
            "r", "deny", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("longer window" in r for r in reasons))

    def test_stale_escalation_pops_once_per_episode(self):
        # Wave-198 §3.4: warn-stale is an operational escalation, not
        # a query. pop_stale_escalations returns newly-stale rules
        # once per warn episode; a mode change resets the episode.
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="warn")
        ledger._stats("r")["warn_since"] = (
            clock() - ml.WARN_MAX_DWELL_SECS - 1)
        self.assertEqual(ledger.pop_stale_escalations(), ("r",))
        self.assertEqual(ledger.pop_stale_escalations(), ())
        # A mode change starts a fresh episode.
        pid = ledger.propose_demotion("r", "observe",
                                      reason="x", requested_by="op1")
        ok, _ = ledger.approve_demotion(pid, approvers=["op1", "op2"])
        self.assertTrue(ok)
        ledger.register_rule("r", mode="warn")
        ledger._stats("r")["warn_since"] = (
            clock() - ml.WARN_MAX_DWELL_SECS - 1)
        self.assertEqual(ledger.pop_stale_escalations(), ("r",))

    def test_overdue_escalation_pops_once_per_demotion(self):
        # Wave-198 §3.5: an overdue post-hoc review re-escalates
        # exactly once per demotion; resolving clears the mark.
        clock = _Clock()
        ledger = ml.ModeLedger(clock=clock)
        ledger.register_rule("r", mode="deny")
        ledger.emergency_demote("r", "warn", operator="op1",
                                reason="blocking prod")
        clock.advance(ml.EMERGENCY_REVIEW_SECS + 1)
        popped = ledger.pop_overdue_emergency_reviews()
        self.assertEqual(len(popped), 1)
        self.assertEqual(popped[0]["rule_id"], "r")
        self.assertEqual(ledger.pop_overdue_emergency_reviews(), ())
        # A second emergency demotion re-escalates (fresh episode).
        ledger.emergency_demote("r", "observe", operator="op1",
                                reason="again")
        clock.advance(ml.EMERGENCY_REVIEW_SECS + 1)
        self.assertEqual(
            len(ledger.pop_overdue_emergency_reviews()), 1)


class TestEngineQuorumAttestation(unittest.TestCase):
    """Wave-198 §3.4: the engine fails closed without approvals.quorum.

    Without the eligible-principals set, "two distinct human
    approvers" is unattested -- any two strings would pass. The
    product boundary refuses; direct ledger use stays the caller's
    attestation.
    """

    _NO_QUORUM = ("version: 1\npolicies:\n"
                  "  - id: cand\n"
                  "    effect: deny\n"
                  "    mode: observe\n"
                  "    match:\n"
                  "      tool: http_post\n"
                  "    reason: cand\n")

    def _evidenced(self):
        eng = _engine(self._NO_QUORUM)
        for i in range(100):
            eng.decide(_req("http_post" if i % 10 == 0 else "read_file"))
        for _ in range(25):
            eng.mode_ledger.record_review("cand", correct=True,
                                          reviewer="op1")
        return eng

    def test_graduation_refused_without_quorum(self):
        eng = self._evidenced()
        ok, reasons = eng.apply_graduation("cand", "warn",
                                           approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("quorum" in r for r in reasons))
        self.assertEqual(eng.mode_ledger.stats("cand")["mode"],
                         "observe")

    def test_evaluate_graduation_refused_without_quorum(self):
        eng = self._evidenced()
        ok, reasons = eng.evaluate_graduation("cand", "warn",
                                              approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("quorum" in r for r in reasons))

    def test_demotion_approval_refused_without_quorum(self):
        eng = _engine("version: 1\npolicies:\n"
                      "  - id: wr\n"
                      "    effect: deny\n"
                      "    mode: warn\n"
                      "    match:\n"
                      "      tool: delete_file\n"
                      "    reason: wr\n")
        pid = eng.propose_demotion("wr", "observe", reason="x",
                                   requested_by="op1")
        ok, reasons = eng.approve_demotion(pid, approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("quorum" in r for r in reasons))

    def test_emergency_demote_refused_without_quorum(self):
        from gov.policy import ModeLedgerError
        eng = self._evidenced()
        with self.assertRaises(ModeLedgerError) as ctx:
            eng.emergency_demote("cand", "warn", operator="op1",
                                 reason="x")
        self.assertIn("quorum", str(ctx.exception).lower())

    def test_resolve_emergency_review_refused_without_quorum(self):
        eng = self._evidenced()
        ok, reasons = eng.resolve_emergency_review(
            "cand", approvers=["op1", "op2"])
        self.assertFalse(ok)
        self.assertTrue(any("quorum" in r for r in reasons))

    def test_graduation_allowed_with_quorum(self):
        # The LADDER_POL fixture configures approvals.quorum.
        eng = _engine(LADDER_POL)
        for i in range(100):
            eng.decide(_req("write_file" if i % 10 == 0 else "read_file"))
        for _ in range(25):
            eng.mode_ledger.record_review("obs-rule", correct=True,
                                          reviewer="op1")
        ok, reasons = eng.apply_graduation("obs-rule", "warn",
                                           approvers=["op1", "op2"])
        self.assertTrue(ok, reasons)


class TestPolicyDecisionObserveRefused(unittest.TestCase):
    def test_policy_decision_rejects_observe(self):
        from gov.policy import PolicyDecision
        with self.assertRaises(ValueError) as ctx:
            PolicyDecision("allow", "x", mode="observe")
        self.assertIn("observe", str(ctx.exception).lower())

    def test_ledger_posture_durable_via_policy_telemetry_not(self):
        # Wave-198 durability boundary: rule posture (mode/pinned)
        # re-registers identically from the policy file on every load
        # (durable); runtime telemetry and graduation history are
        # in-memory and reset on restart (honest v1 boundary).
        eng1 = _engine(LADDER_POL)
        for _ in range(10):
            eng1.decide(_req("delete_file"))
        self.assertEqual(
            eng1.mode_ledger.stats("warn-rule")["violations"], 10)
        eng2 = _engine(LADDER_POL)  # "restart": fresh engine, same file
        st = eng2.mode_ledger.stats("warn-rule")
        self.assertEqual(st["mode"], "warn")      # posture durable
        self.assertEqual(st["violations"], 0)     # telemetry reset
        self.assertEqual(st["evaluated"], 0)
        self.assertTrue(eng2.mode_ledger.stats("pinned-exfil")["pinned"])

    def test_policy_decision_accepts_warn_and_deny(self):
        from gov.policy import PolicyDecision
        for mode in ("warn", "deny"):
            pd = PolicyDecision("allow", "x", mode=mode)
            self.assertEqual(pd.mode, mode)


class TestWarnDigestAggregator(unittest.TestCase):
    def test_single_digest_per_window(self):
        clock = _Clock()
        agg = ml.WarnDigestAggregator(window_secs=300, clock=clock)
        for _ in range(1000):
            due = agg.record(rule_id="r", nominal_effect="deny",
                             warning="w")
            self.assertEqual(due, [])
        digests = agg.flush_all()
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests[0]["count"], 1000)
        self.assertEqual(digests[0]["rule_id"], "r")
        self.assertLessEqual(len(digests[0]["samples"]), 3)

    def test_window_roll_flushes_previous(self):
        clock = _Clock()
        agg = ml.WarnDigestAggregator(window_secs=300, clock=clock)
        agg.record(rule_id="r", nominal_effect="deny", warning="w1")
        clock.advance(301)
        due = agg.record(rule_id="r", nominal_effect="deny",
                         warning="w2")
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["count"], 1)
        self.assertEqual(due[0]["samples"], ["w1"])

    def test_rules_aggregated_independently(self):
        agg = ml.WarnDigestAggregator(window_secs=300, clock=_Clock())
        agg.record(rule_id="a", nominal_effect="deny", warning="w")
        agg.record(rule_id="b", nominal_effect="deny", warning="w")
        digests = agg.flush_all()
        self.assertEqual({d["rule_id"] for d in digests}, {"a", "b"})


# ---------------------------------------------------------------- engine

class TestPolicyLoadValidation(unittest.TestCase):
    def test_unknown_mode_refused_loudly(self):
        with self.assertRaises(ValueError) as cm:
            _engine(LADDER_POL.replace("mode: observe", "mode: bogus"))
        self.assertIn("unknown mode", str(cm.exception))

    def test_pinned_non_deny_refused(self):
        with self.assertRaises(ValueError) as cm:
            _engine(LADDER_POL.replace(
                "mode: observe", "mode: observe\n    pinned: true"))
        self.assertIn("pinned", str(cm.exception).lower())

    def test_non_bool_pinned_refused(self):
        with self.assertRaises(ValueError):
            _engine(LADDER_POL.replace("pinned: true",
                                      "pinned: yes-please"))

    def test_pinned_deny_loads(self):
        eng = _engine(LADDER_POL)
        st = eng.mode_ledger.stats("pinned-exfil")
        self.assertTrue(st["pinned"])
        self.assertEqual(st["mode"], "deny")

    def test_mode_absent_defaults_deny(self):
        eng = _engine(LADDER_POL)
        self.assertEqual(eng.mode_ledger.stats("plain-allow")["mode"],
                         "deny")


class TestDecideRouting(unittest.TestCase):
    def test_observe_hit_has_no_authority(self):
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("write_file"))
        self.assertEqual(d.effect, "deny")
        self.assertFalse(d.allowed)
        self.assertIsNone(d.policy_id)  # implicit default deny
        self.assertEqual(d.mode, "deny")
        self.assertEqual(d.nominal_effect, "deny")
        self.assertEqual(d.warnings, ())
        observed = [h.rule_id for h in d.diagnostics.observed_hits]
        self.assertEqual(observed, ["obs-rule"])
        self.assertIsNone(d.diagnostics.deciding_rule)

    def test_observe_does_not_displace_legacy_deny(self):
        eng = _engine(
            "version: 1\npolicies:\n"
            "  - id: legacy\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: write_file\n"
            "    reason: legacy\n"
            "  - id: obs\n"
            "    effect: deny\n"
            "    mode: observe\n"
            "    match:\n"
            "      tool: write_file\n"
            "    reason: obs\n")
        d = eng.decide(_req("write_file"))
        self.assertEqual(d.policy_id, "legacy")
        self.assertEqual(d.effect, "deny")

    def test_warn_deny_demoted_to_allow(self):
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("delete_file"))
        self.assertEqual(d.effect, "allow")
        self.assertTrue(d.allowed)
        self.assertEqual(d.nominal_effect, "deny")
        self.assertEqual(d.mode, "warn")
        self.assertEqual(len(d.warnings), 1)
        self.assertIn("warn-rule", d.warnings[0])

    def test_warn_mode_never_weakens_deny_mode_deny(self):
        # Wave-198 (review catch): a warn-mode deny rule declared
        # BEFORE a deny-mode deny rule must not demote the verdict to
        # allow. Dryrun never weakens the rest of the policy set
        # (Gatekeeper discipline, SPIKE §1).
        eng = _engine(
            "version: 1\n"
            "policies:\n"
            "  - id: warn-first\n"
            "    effect: deny\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: warn candidate\n"
            "  - id: deny-second\n"
            "    effect: deny\n"
            "    mode: deny\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: real deny\n")
        d = eng.decide(_req("delete_file"))
        self.assertEqual(d.effect, "deny")
        self.assertEqual(d.policy_id, "deny-second")
        self.assertEqual(d.mode, "deny")
        self.assertEqual(d.warnings, ())

    def test_warn_mode_never_weakens_deny_mode_approval(self):
        # Same across buckets: a warn-mode forbid must not override a
        # deny-mode require_approval (which would otherwise queue).
        eng = _engine(
            "version: 1\n"
            "policies:\n"
            "  - id: warn-forbid\n"
            "    effect: deny\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: send_email\n"
            "    reason: warn candidate\n"
            "  - id: deny-approval\n"
            "    effect: require_approval\n"
            "    mode: deny\n"
            "    match:\n"
            "      tool: send_email\n"
            "    reason: needs human\n")
        d = eng.decide(_req("send_email"))
        self.assertEqual(d.effect, "require_approval")
        self.assertEqual(d.policy_id, "deny-approval")

    def test_warn_decider_only_when_no_deny_mode_match(self):
        # A lone warn-mode rule still decides with nominal preserved
        # and enforced allow (the R1 contract is intact).
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("delete_file"))
        self.assertEqual((d.effect, d.nominal_effect, d.mode),
                         ("allow", "deny", "warn"))
        self.assertEqual(d.policy_id, "warn-rule")
        self.assertTrue(d.warnings)
        self.assertEqual(d.policy_id, "warn-rule")

    def test_warn_allow_stays_allow_but_warned(self):
        eng = _engine(
            "version: 1\npolicies:\n"
            "  - id: w\n"
            "    effect: allow\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: read_file\n"
            "    reason: warn allow\n")
        d = eng.decide(_req("read_file"))
        self.assertEqual((d.effect, d.nominal_effect, d.mode),
                         ("allow", "allow", "warn"))
        self.assertEqual(len(d.warnings), 1)

    def test_warn_require_approval_demoted(self):
        eng = _engine(
            "version: 1\npolicies:\n"
            "  - id: w\n"
            "    effect: require_approval\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: read_file\n"
            "    reason: warn approval\n")
        d = eng.decide(_req("read_file"))
        self.assertEqual(d.effect, "allow")
        self.assertEqual(d.nominal_effect, "require_approval")

    def test_deny_mode_unchanged(self):
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("api_call"))
        self.assertEqual((d.effect, d.policy_id, d.mode,
                          d.nominal_effect, d.warnings),
                         ("deny", "pinned-exfil", "deny", "deny", ()))

    def test_ledger_telemetry_fed_by_decide(self):
        eng = _engine(LADDER_POL)
        eng.decide(_req("write_file"))
        eng.decide(_req("write_file"))
        eng.decide(_req("read_file"))
        st = eng.mode_ledger.stats("obs-rule")
        self.assertEqual(st["evaluated"], 3)
        self.assertEqual(st["violations"], 2)
        ok, _ = eng.mode_ledger.verify_chain()
        self.assertTrue(ok)

    def test_synthetic_evaluation_never_feeds_ledger(self):
        # Wave-198: mint probes and what-if simulators ask
        # hypothetical questions; their matches must not become
        # violation telemetry (graduation evidence).
        eng = _engine(LADDER_POL)
        for _ in range(5):
            eng.evaluate({"tool": "delete_file", "args": {}},
                         record_telemetry=False)
        self.assertEqual(eng.mode_ledger.stats("warn-rule")["evaluated"], 0)
        self.assertEqual(eng.mode_ledger.stats("warn-rule")["violations"], 0)
        # The verdict is unchanged by the flag -- only the ledger
        # write is skipped.
        d = eng.evaluate({"tool": "delete_file", "args": {}})
        self.assertEqual((d.effect, d.nominal_effect, d.mode),
                         ("allow", "deny", "warn"))
        self.assertEqual(eng.mode_ledger.stats("warn-rule")["evaluated"], 1)
        self.assertEqual(eng.mode_ledger.stats("warn-rule")["violations"], 1)

    def test_engine_convenience_methods(self):
        eng = _engine(
            "version: 1\n"
            "approvals:\n"
            "  quorum:\n"
            "    min_approvals: 2\n"
            "    eligible_principals: [op1, op2]\n"
            "policies:\n"
            "  - id: cand\n"
            "    effect: deny\n"
            "    mode: observe\n"
            "    match:\n"
            "      tool: http_post\n"
            "    reason: cand\n")
        for i in range(100):
            eng.decide(_req("http_post" if i % 10 == 0 else "read_file"))
        for _ in range(25):
            eng.mode_ledger.record_review("cand", correct=True,
                                          reviewer="op1")
        ok, _ = eng.apply_graduation("cand", "warn",
                                     approvers=["op1", "op2"])
        self.assertTrue(ok)
        d = eng.decide(_req("http_post"))
        self.assertEqual(d.mode, "warn")
        self.assertEqual(d.effect, "allow")


class TestContractSerialization(unittest.TestCase):
    def _decision(self):
        eng = _engine(LADDER_POL)
        return eng.decide(_req("send_email"))

    def test_mode_absent_serialization_unchanged(self):
        eng = _engine(
            "version: 1\npolicies:\n"
            "  - id: r\n"
            "    effect: deny\n"
            "    match:\n"
            "      tool: send_email\n"
            "    reason: x\n")
        d = eng.decide(_req("send_email"))
        ser = d.to_dict()
        self.assertEqual(
            sorted(ser.keys()),
            ["allowed", "diagnostics", "effect", "flag", "policy_id",
             "reason", "request"])
        self.assertNotIn("observed_hits", ser["diagnostics"])
        pd = d.to_policy_decision().to_dict()
        self.assertEqual(
            sorted(pd.keys()),
            ["diagnostics", "effect", "flag", "matched_rules",
             "policy_id", "reason"])

    def test_warn_decision_serializes_ladder(self):
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("delete_file"))
        ser = d.to_dict()
        self.assertEqual(ser["mode"], "warn")
        self.assertEqual(ser["nominal_effect"], "deny")
        self.assertEqual(len(ser["warnings"]), 1)
        hit = ser["diagnostics"]["deciding_rule"]
        self.assertEqual(hit["mode"], "warn")

    def test_observe_hit_serializes_mode(self):
        eng = _engine(LADDER_POL)
        d = eng.decide(_req("write_file"))
        dser = d.diagnostics.to_dict()
        self.assertEqual(len(dser["observed_hits"]), 1)
        self.assertEqual(dser["observed_hits"][0]["mode"], "observe")

    def test_decision_rejects_observe_mode(self):
        eng = _engine(LADDER_POL)
        req = _req("read_file")
        diag = Diagnostics(deciding_rule=None)
        with self.assertRaises(Exception):
            Decision(effect="deny", allowed=False, reason="x",
                     policy_id=None, flag=None, diagnostics=diag,
                     request=req, mode="observe")

    def test_rulehit_rejects_bad_mode(self):
        with self.assertRaises(Exception):
            RuleHit(rule_id="r", effect="deny", reason="x", flag=None,
                    declaration_index=0, mode="bogus")

    def test_nominal_defaults_to_effect(self):
        eng = _engine(LADDER_POL)
        req = _req("read_file")
        diag = Diagnostics(deciding_rule=None)
        d = Decision(effect="allow", allowed=True, reason="x",
                     policy_id="r", flag=None, diagnostics=diag,
                     request=req)
        self.assertEqual(d.nominal_effect, "allow")
        self.assertEqual(d.mode, "deny")
        self.assertEqual(d.warnings, ())

    def test_decision_rejects_empty_warning(self):
        # Wave-198: an empty warning string passes nothing downstream
        # (build_bom rejects it) -- refuse it at the contract.
        req = _req("read_file")
        diag = Diagnostics(deciding_rule=None)
        with self.assertRaises(Exception):
            Decision(effect="allow", allowed=True, reason="x",
                     policy_id="r", flag=None, diagnostics=diag,
                     request=req, warnings=[""])


# ---------------------------------------------------------------- BOM

_HEX = "ab" * 32


class TestBomLadder(unittest.TestCase):
    def _base_kwargs(self):
        return dict(policy_id="p", policy_version="1",
                    policy_digest=_HEX, evidence_head_digest="head",
                    principal={"agent_id": "a"})

    def test_absent_ladder_byte_identical(self):
        b1 = decision_bom.build_bom(**self._base_kwargs())
        self.assertNotIn("ladder", b1["inputs"])
        ok, _ = decision_bom.check_bom_shape(b1)
        self.assertTrue(ok)

    def test_ladder_section_present_and_shaped(self):
        bom = decision_bom.build_bom(
            **self._base_kwargs(),
            decision_mode="warn", nominal_effect="deny",
            decision_warnings=["w1"],
            rule_mode_history=[{"old_mode": "observe",
                                "new_mode": "warn", "at": 1.0,
                                "approvers": ["op1", "op2"]}])
        ladder = bom["inputs"]["ladder"]
        self.assertEqual(ladder["mode"], "warn")
        self.assertEqual(ladder["nominal_effect"], "deny")
        self.assertEqual(ladder["warnings"], ["w1"])
        self.assertEqual(len(ladder["rule_mode_history"]), 1)
        ok, reason = decision_bom.check_bom_shape(bom)
        self.assertTrue(ok, reason)

    def test_ladder_validation_loud(self):
        kw = self._base_kwargs()
        with self.assertRaises(decision_bom.BomError):
            decision_bom.build_bom(decision_mode="bogus",
                                   nominal_effect="deny",
                                   decision_warnings=[],
                                   rule_mode_history=[], **kw)
        with self.assertRaises(decision_bom.BomError):
            decision_bom.build_bom(decision_mode="warn",
                                   nominal_effect="maybe",
                                   decision_warnings=[],
                                   rule_mode_history=[], **kw)
        with self.assertRaises(decision_bom.BomError):
            decision_bom.build_bom(
                decision_mode="warn", nominal_effect="deny",
                decision_warnings=[],
                rule_mode_history=[{"old_mode": "deny"}], **kw)

    def test_shape_checker_rejects_malformed_ladder(self):
        bom = decision_bom.build_bom(**self._base_kwargs())
        bom["inputs"]["ladder"] = {"mode": "bogus"}
        ok, reason = decision_bom.check_bom_shape(bom)
        self.assertFalse(ok)
        self.assertIn("ladder", reason)


# ---------------------------------------------------------------- export

_EXPORT_POL = """\
version: 2
policies:
  - id: r-warn
    effect: deny
    mode: warn
    match:
      tool: read_file
    reason: x
  - id: r-pinned
    effect: deny
    pinned: true
    match:
      tool: send_email
    reason: y
  - id: r-plain
    effect: allow
    match:
      tool: read_file
    reason: z
"""


class TestExportLadder(unittest.TestCase):
    def test_ladder_modes_annotated_not_dropped(self):
        # Wave-198: mode/pinned have no Cedar equivalent, but the
        # export must not silently claim a stronger posture than the
        # engine enforces -- they are emitted as // ladder annotations.
        out = policy_export.translate_text(_EXPORT_POL)
        self.assertIn("// ladder: mode=warn", out)
        self.assertIn("// ladder: mode=deny, pinned", out)
        self.assertEqual(out.count("// ladder"), 2)

    def test_export_refuses_bad_ladder_fields_loudly(self):
        with self.assertRaises(Exception):
            policy_export.translate_text(
                _EXPORT_POL.replace("mode: warn", "mode: bogus"))
        with self.assertRaises(Exception):
            policy_export.translate_text(
                _EXPORT_POL.replace("mode: warn",
                                    "mode: warn\n    pinned: true"))


# ---------------------------------------------------------------- executor

class TestExecutorWarnDigest(unittest.TestCase):
    def _executor(self, engine):
        import tempfile
        from gov.executor import ToolExecutor
        from gov.log import ActionLog, read_entries
        run_dir = tempfile.mkdtemp(prefix="gov-grad-ut-")
        log_path = os.path.join(run_dir, "actions.jsonl")
        log = ActionLog(log_path)
        from gov.approvals import ApprovalQueue
        queue = ApprovalQueue(run_dir, log)
        # Wave-246 merge: isolate the egress ledger to this test's run_dir.
        # The default (run_dir.parent / "egress_ledger.jsonl") shares the
        # TMPDIR root across tests; a prior test's ledger key causes
        # LedgerUnverifiableError here in the full canonical.
        ex = ToolExecutor(run_dir, engine, log, queue,
                          ledger_path=os.path.join(run_dir, "egress_ledger.jsonl"),
                          ungoverned_ack=("synthetic wave-198 unit test: "
                                          "raw pipeline by design"))
        return ex, lambda: read_entries(log_path)

    def test_warn_digest_aggregated_not_interrupting(self):
        eng = _engine(LADDER_POL)
        ex, read_log = self._executor(eng)
        for _ in range(50):
            d = eng.decide(_req("delete_file")).to_policy_decision()
            self.assertEqual(d.effect, "allow")  # agent sees allow
            ex._surface_warn_digest(d)
        digests = ex.flush_warn_digests()
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests[0]["count"], 50)
        chained = [e for e in read_log()
                   if e.get("event") == "warn_digest"]
        self.assertEqual(len(chained), 1)
        self.assertEqual(chained[0]["warn_count"], 50)

    def test_no_warnings_no_digest(self):
        eng = _engine(LADDER_POL)
        ex, _ = self._executor(eng)
        d = eng.decide(_req("read_file")).to_policy_decision()
        ex._surface_warn_digest(d)
        self.assertEqual(ex.flush_warn_digests(), [])

    def test_telemetry_failure_never_breaks_verdict(self):
        eng = _engine(LADDER_POL)
        ex, _ = self._executor(eng)
        d = eng.decide(_req("delete_file")).to_policy_decision()
        ex._warn_digest_agg = None  # sabotage the aggregator
        ex._surface_warn_digest(d)  # must not raise
        self.assertEqual(d.effect, "allow")

    def test_graduated_deny_bom_carries_mode_history(self):
        # Wave-198: a rule that graduated observe->warn->deny and now
        # denies must carry its (non-empty) mode history in the
        # executor-produced decision BOM -- the deny was earned, not
        # just declared. Mode-absent rules stay ladder-free (P8).
        #
        # Wave-245 triage: this test MUST be hermetic. It previously used
        # os.environ.setdefault() without cleanup, which (a) left
        # GOV_DECISION_PACKET_KEY set for all subsequent tests in the
        # suite, enabling decision packets where other tests expected
        # them disabled (broke test_secret_path_read_is_denied,
        # test_tail_truncation_detected, test_wrong_key_fails_verification
        # in the full canonical run), and (b) inherited a polluted value
        # when a prior test had already set the key. Explicit set +
        # try/finally restore fixes both directions.
        import secrets
        _old_env = {k: os.environ.get(k) for k in (
            "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_DECISION_PACKET_KEY")}
        os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
        os.environ["GOV_LOG_KEY_EPOCH"] = "grad-ladder-ut"
        os.environ["GOV_DECISION_PACKET_KEY"] = secrets.token_hex(32)
        try:
            self._graduated_deny_bom_body()
        finally:
            for _k, _v in _old_env.items():
                if _v is None:
                    os.environ.pop(_k, None)
                else:
                    os.environ[_k] = _v

    def _graduated_deny_bom_body(self):
        eng = _engine(
            "version: 1\n"
            "approvals:\n"
            "  quorum:\n"
            "    min_approvals: 2\n"
            "    eligible_principals: [op1, op2]\n"
            "policies:\n"
            "  - id: cand\n"
            "    effect: deny\n"
            "    mode: observe\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: candidate\n")
        for i in range(100):
            eng.decide(_req("delete_file" if i % 10 == 0 else "read_file"))
        for _ in range(25):
            eng.mode_ledger.record_review("cand", correct=True,
                                          reviewer="op1")
        ok, reasons = eng.apply_graduation("cand", "warn",
                                           approvers=["op1", "op2"])
        self.assertTrue(ok, reasons)
        for _ in range(100):
            eng.decide(_req("delete_file"))
        for _ in range(6):
            eng.mode_ledger.record_warning_ack("cand", operator="op1")
        ok, reasons = eng.apply_graduation("cand", "deny",
                                           approvers=["op1", "op2"])
        self.assertTrue(ok, reasons)
        ex, read_log = self._executor(eng)
        ident = ex.mint_identity("a1", "coder", "u1")
        try:
            ex.call(ident, "delete_file", path="z.txt")
        except Exception:
            pass  # the denial itself may raise; the packet is chained
        packets = [e for e in read_log()
                   if e.get("event") == "decision_packet"]
        self.assertTrue(packets, "no decision packet chained")
        ladder = (packets[0]["packet"]["bill_of_materials"]["value"]
                  ["inputs"].get("ladder"))
        self.assertIsNotNone(ladder,
                             "graduated deny BOM missing ladder section")
        hist = ladder["rule_mode_history"]
        self.assertEqual([h["new_mode"] for h in hist], ["warn", "deny"])
        # Every history entry carries the §3.5 FP stats snapshot.
        for h in hist:
            self.assertIn("stats", h)
            self.assertGreaterEqual(h["stats"]["evaluated"], 100)

    def test_public_ack_seam_feeds_graduation_bar(self):
        # Wave-198 (review catch): record_warning_ack must be reachable
        # through a public operator seam -- otherwise the warn->deny
        # acknowledgement bar is unreachable except by poking the
        # in-memory ledger directly.
        eng = _engine(LADDER_POL)
        ex, read_log = self._executor(eng)
        ex.record_warning_ack("warn-rule", operator="op1")
        st = eng.mode_ledger.stats("warn-rule")
        self.assertEqual(st["warnings_acknowledged"], 1)
        acks = [e for e in read_log() if e.get("event") == "warning_ack"]
        self.assertEqual(len(acks), 1)
        self.assertEqual(acks[0]["operator"], "op1")

    def test_warn_digest_flush_feeds_warning_count_stat(self):
        # Wave-198 (SPIKE §3.3): the per-mode warning count accrues in
        # the ledger when a digest window rolls.
        eng = _engine(LADDER_POL)
        ex, _ = self._executor(eng)
        for _ in range(3):
            ex.call(ex.mint_identity("a1", "coder", "u1"),
                    "delete_file", path="x.txt")
        ex.flush_warn_digests()
        st = eng.mode_ledger.stats("warn-rule")
        self.assertEqual(st.get("warnings_surfaced"), 3)

    def test_violation_record_carries_request_digest(self):
        # Wave-198 (SPIKE §3.3): every observe/warn violation record
        # carries the digest of the exact request that triggered it.
        eng = _engine(LADDER_POL)
        eng.decide(_req("delete_file"))
        recs = [r for r in eng.mode_ledger._chain
                if r["kind"] == "violation"]
        self.assertTrue(recs)
        for r in recs:
            self.assertIn("request_digest", r)
            self.assertEqual(len(r["request_digest"]), 64)

    def test_public_call_path_chains_warn_digest(self):
        # Wave-198: the REAL executor action path (not the helper) --
        # a warn-mode hit admits the action AND aggregates operator
        # telemetry into a chained warn_digest. The agent's verdict
        # is untouched: status executed, no warning surfaced.
        import secrets
        os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
        os.environ.setdefault("GOV_LOG_KEY_EPOCH", "grad-ladder-ut")
        eng = _engine(
            "version: 1\npolicies:\n"
            "  - id: warn-del\n"
            "    effect: deny\n"
            "    mode: warn\n"
            "    match:\n"
            "      tool: delete_file\n"
            "    reason: warn delete\n")
        ex, read_log = self._executor(eng)
        ident = ex.mint_identity("a1", "coder", "u1")
        for _ in range(5):
            r = ex.call(ident, "delete_file", path="z.txt")
            self.assertEqual(r.get("status"), "executed")
        ex.flush_warn_digests()
        chained = [e for e in read_log()
                   if e.get("event") == "warn_digest"]
        self.assertEqual(len(chained), 1)
        self.assertEqual(chained[0]["warn_count"], 5)
        self.assertEqual(chained[0]["policy_id"], "warn-del")
        self.assertEqual(chained[0]["nominal_effect"], "deny")


if __name__ == "__main__":
    unittest.main()
