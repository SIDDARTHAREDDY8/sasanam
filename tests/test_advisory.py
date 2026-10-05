"""Monotonic advisory layer + Decision BOM (adapted from
microsoft/agent-governance-toolkit, MIT -- concept adapted, not cloned).

Regression tests for gov/advisory.py and the ToolExecutor opt-in
wiring. The break-first battery is
evals/adversarial_advisory_monotonic.py (13/13 HELD); these tests pin
the contract at the unit seam.
"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
# GOV_DEPLOYMENT_MODE=staging. No module-level env manipulation here.

from gov.advisory import (
    EFFECT_RANK,
    AdvisoryContext,
    AdvisoryComposer,
    Advisor,
    AdvisorVerdict,
    DecisionBOM,
)
from gov.executor import ToolExecutor
from gov.policy import PolicyEngine
from gov.log import ActionLog, read_entries
from gov.approvals import ApprovalQueue


def _ctx(deterministic_effect="allow", tool="write_file"):
    return AdvisoryContext(
        tool=tool,
        args_digest=hashlib.sha256(b'{"path":"x"}').hexdigest(),
        agent_id="a1", role="coder", principal="u1", run_id="r1",
        deterministic_effect=deterministic_effect,
        policy_version="v1", policy_digest="pd",
        content_signals={"carries_read_content": False})


class _Deny(Advisor):
    def advise(self, ctx):
        return AdvisorVerdict(floor="deny", flags=("j",), reason="r")


class _Whitelist(Advisor):
    def advise(self, ctx):
        return AdvisorVerdict(floor="allow", flags=("rogue_flag",),
                              reason="rogue")


class _Noop(Advisor):
    pass


class _Crash(Advisor):
    def advise(self, ctx):
        raise RuntimeError("boom")


class _Garbage(Advisor):
    def advise(self, ctx):
        return AdvisorVerdict(floor="maybe")


class _NotAVerdict(Advisor):
    def advise(self, ctx):
        return {"floor": "deny"}


class TestLattice(unittest.TestCase):
    def test_rank_order(self):
        self.assertLess(EFFECT_RANK["allow"], EFFECT_RANK["require_approval"])
        self.assertLess(EFFECT_RANK["require_approval"], EFFECT_RANK["deny"])

    def test_context_rejects_unknown_effect(self):
        with self.assertRaises(ValueError):
            _ctx(deterministic_effect="maybe")

    def test_verdict_rejects_unknown_floor(self):
        with self.assertRaises(ValueError):
            AdvisorVerdict(floor="maybe")


class TestMonotonicity(unittest.TestCase):
    def test_whitelist_after_deny_is_violation_loud(self):
        events = []
        out = AdvisoryComposer([_Whitelist()],
                               audit=events.append).compose(_ctx("deny"))
        self.assertEqual(out.final_effect, "deny")
        self.assertEqual(len(out.violations), 1)
        self.assertTrue(any(
            e.get("event") == "advisory_monotonicity_violation"
            for e in events))

    def test_violating_advisor_output_fully_discarded(self):
        # Full discard: not just the floor, the violator's flags must
        # not leak into the composed result either.
        out = AdvisoryComposer([_Whitelist()]).compose(_ctx("deny"))
        self.assertNotIn("rogue_flag", out.flags)
        rec = out.records[0]
        self.assertFalse(rec.accepted)
        self.assertEqual(rec.flags_added, ())
        self.assertEqual(rec.note, "monotonicity-violation")

    def test_tighten_then_loosen_order_independent(self):
        outs = []
        for order in ([_Deny(), _Whitelist()], [_Whitelist(), _Deny()]):
            outs.append(AdvisoryComposer(order).compose(_ctx("allow")))
        self.assertEqual(outs[0].final_effect, "deny")
        self.assertEqual(outs[1].final_effect, "deny")

    def test_later_advisor_cannot_drop_earlier_tightening(self):
        out = AdvisoryComposer([_Deny(), _Noop()]).compose(_ctx("allow"))
        self.assertEqual(out.final_effect, "deny")
        self.assertIn("j", out.flags)

    def test_approval_cannot_be_loosened_to_allow(self):
        events = []
        out = AdvisoryComposer([_Whitelist()],
                               audit=events.append).compose(
                                   _ctx("require_approval"))
        self.assertEqual(out.final_effect, "require_approval")
        self.assertEqual(len(out.violations), 1)

    def test_genuine_tightening_accepted(self):
        out = AdvisoryComposer([_Deny()]).compose(_ctx("allow"))
        self.assertTrue(out.tightened())
        self.assertEqual(out.final_effect, "deny")
        self.assertEqual(out.records[0].note, "tightened")

    def test_noop_advisors_change_nothing(self):
        out = AdvisoryComposer([_Noop(), _Noop()]).compose(_ctx("allow"))
        self.assertFalse(out.tightened())
        self.assertEqual(out.final_effect, "allow")
        self.assertEqual(out.violations, ())
        self.assertEqual(out.errors, ())


class TestAdvisorFailure(unittest.TestCase):
    def test_crash_keeps_deterministic_verdict_loud(self):
        for det in ("allow", "deny"):
            events = []
            out = AdvisoryComposer([_Crash()],
                                   audit=events.append).compose(_ctx(det))
            self.assertEqual(out.final_effect, det)
            self.assertEqual(len(out.errors), 1)
            self.assertTrue(any(e.get("event") == "advisory_error"
                                for e in events))

    def test_garbage_floor_is_advisor_error(self):
        out = AdvisoryComposer([_Garbage()]).compose(_ctx("allow"))
        self.assertEqual(out.final_effect, "allow")
        self.assertEqual(len(out.errors), 1)

    def test_non_verdict_return_is_advisor_error(self):
        out = AdvisoryComposer([_NotAVerdict()]).compose(_ctx("allow"))
        self.assertEqual(out.final_effect, "allow")
        self.assertEqual(len(out.errors), 1)

    def test_advisor_without_advise_rejected_at_construction(self):
        with self.assertRaises(TypeError):
            AdvisoryComposer([object()])


class TestAdvisorPrivacy(unittest.TestCase):
    def test_no_raw_args_in_context(self):
        ctx = _ctx()
        blob = repr(ctx.to_dict())
        self.assertNotIn("secret", blob)
        # the digest is present; the preimage is not
        self.assertIn(ctx.args_digest, blob)


class TestDecisionBOM(unittest.TestCase):
    def _chain(self, n=3):
        comp = AdvisoryComposer([_Noop()])
        recs, prev = [], ""
        for i in range(n):
            out = comp.compose(_ctx())
            rec = DecisionBOM.build(
                tool="t", agent_id="a1", role="coder", principal="u1",
                run_id="r1", policy_version="v1", policy_digest="pd",
                deterministic_effect="allow",
                deterministic_policy_id="p", composed=out,
                timestamp="2026-09-27T00:00:00Z", prev_bom_digest=prev)
            prev = DecisionBOM.digest(rec)
            recs.append(rec)
        return recs

    def test_chain_verifies(self):
        ok, _ = DecisionBOM.verify_chain(self._chain(4))
        self.assertTrue(ok)

    def test_field_flip_detected(self):
        recs = self._chain()
        recs[1]["final_effect"] = "deny"
        ok, why = DecisionBOM.verify_chain(recs)
        self.assertFalse(ok)
        self.assertIn("tampered", why)

    def test_recomputed_digest_breaks_linkage(self):
        recs = self._chain()
        forged = dict(recs[1])
        forged["final_effect"] = "deny"
        forged["bom_digest"] = DecisionBOM.digest(
            {k: v for k, v in forged.items() if k != "bom_digest"})
        recs[1] = forged
        ok, why = DecisionBOM.verify_chain(recs)
        self.assertFalse(ok)
        self.assertIn("linkage", why)

    def test_dropped_record_detected(self):
        recs = self._chain()
        ok, _ = DecisionBOM.verify_chain([recs[0], recs[2]])
        self.assertFalse(ok)

    def test_bom_records_advisor_io_digests(self):
        comp = AdvisoryComposer([_Deny()])
        out = comp.compose(_ctx())
        rec = DecisionBOM.build(
            tool="t", agent_id="a1", role="coder", principal="u1",
            run_id="r1", policy_version="v1", policy_digest="pd",
            deterministic_effect="allow", deterministic_policy_id="p",
            composed=out, timestamp="2026-09-27T00:00:00Z")
        adv = rec["advisors"][0]
        self.assertEqual(adv["name"], "_Deny")
        self.assertTrue(adv["input_digest"])
        self.assertTrue(adv["output_digest"])
        self.assertNotEqual(adv["input_digest"], adv["output_digest"])
        self.assertEqual(rec["final_effect"], "deny")


def _executor(run_dir, advisors, tool_rate_limits=None):
    policy = PolicyEngine("policies/default.yaml")
    if tool_rate_limits is not None:
        # Wave-335: per-tool rate limiting is default-enforced; tests that
        # hammer one tool for non-velocity reasons (e.g. BOM-chain
        # integrity under concurrency) opt into a permissive budget here.
        policy.tool_rate_limits = tool_rate_limits
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    kw = dict(ledger_path=run_dir / "egress_ledger.jsonl",
              ungoverned_ack="advisory-unit-tests")
    if advisors is not None:
        kw["advisors"] = advisors
    ex = ToolExecutor(run_dir, policy, log, approvals, **kw)
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    return ex, log


class TestExecutorWiring(unittest.TestCase):
    def test_no_advisors_zero_behavior_change(self):
        d = Path(tempfile.mkdtemp(prefix="adv_ut_"))
        ex, log = _executor(d, None)
        r = ex.call(ex.mint_identity("a1", "coder", "u1"),
                    "write_file", path="z.txt", content="hi")
        self.assertEqual(r.get("status"), "executed")
        boms = [e for e in read_entries(d / "actions.jsonl")
                if e.get("event") == "decision_bom"]
        self.assertEqual(boms, [])

    def test_tightening_denies_and_records_bom(self):
        d = Path(tempfile.mkdtemp(prefix="adv_ut_"))
        ex, log = _executor(d, [_Deny()])
        r = ex.call(ex.mint_identity("a1", "coder", "u1"),
                    "write_file", path="z.txt", content="hi")
        self.assertEqual(r.get("status"), "denied")
        boms = [e for e in read_entries(d / "actions.jsonl")
                if e.get("event") == "decision_bom"]
        self.assertEqual(len(boms), 1)
        bom = boms[0]["bom"]
        self.assertEqual(bom["deterministic_effect"], "allow")
        self.assertEqual(bom["final_effect"], "deny")
        ok, _ = DecisionBOM.verify_chain([bom])
        self.assertTrue(ok)

    def test_violation_is_loud_in_audit_log(self):
        d = Path(tempfile.mkdtemp(prefix="adv_ut_"))
        ex, log = _executor(d, [_Whitelist()])
        # Deterministic DENY at policy evaluation: non-allowlisted
        # domain. The whitelist attempt must violate LOUD.
        r = ex.call(ex.mint_identity("a1", "coder", "u1"),
                    "api_call", url="http://evil.example/x", method="GET")
        self.assertEqual(r.get("status"), "denied")
        viols = [e for e in read_entries(d / "actions.jsonl")
                 if e.get("event") == "advisory_monotonicity_violation"]
        self.assertEqual(len(viols), 1)
        self.assertEqual(viols[0]["attempted_floor"], "allow")

    def test_concurrent_calls_keep_bom_chain_intact(self):
        import threading
        d = Path(tempfile.mkdtemp(prefix="adv_ut_"))
        # 40 rapid write_file calls exceed the default 30/60s per-tool
        # budget; this test hammers for BOM-chain integrity, not velocity,
        # so it opts into a permissive budget (wave-335).
        ex, log = _executor(d, [_Noop()],
                            tool_rate_limits={"write_file": {"window_secs": 60,
                                                            "max_calls": 1000}})
        ident = ex.mint_identity("a1", "coder", "u1")
        errors = []

        def hammer(i):
            try:
                for j in range(10):
                    ex.call(ident, "write_file", path="t%d_%d.txt" % (i, j),
                            content="hello")
            except Exception as e:  # noqa: BLE001 - collected, asserted
                errors.append(e)

        threads = [threading.Thread(target=hammer, args=(i,))
                   for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        boms = [e["bom"] for e in read_entries(d / "actions.jsonl")
                if e.get("event") == "decision_bom"]
        self.assertEqual(len(boms), 40)
        ok, why = DecisionBOM.verify_chain(boms)
        self.assertTrue(ok, why)


if __name__ == "__main__":
    unittest.main()
