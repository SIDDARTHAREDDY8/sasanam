"""Tests for gov/capability_measure.py (Safeguard Benchmark §2a).

CapabilityHarness: tool/autonomy inventory, capability deltas between
log checkpoints, and the human-review gate that refuses to proceed
without an approval ticket when the delta meets the threshold.

$0 spend, synthetic/local only. Keys are fresh random per test via the
explicit GOV_LOG_KEY env backend (same production path tests use).
"""

import os
import secrets
import tempfile
import unittest

from gov.capability_measure import (  # noqa: E402
    CapabilityHarness,
    CapabilityMeasureError,
    DEFAULT_THRESHOLDS as CM_DEFAULTS,
)

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _provision_key():
    saved = {k: os.environ.get(k) for k in _KEY_VARS}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)

    def restore():
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def _append(log, event, **kw):
    rec = {"event": event}
    rec.update(kw)
    return log.append(rec)


class _FakeQueue:
    """Minimal gov/approvals.py-compatible queue seam for gate() tests."""

    def __init__(self):
        self.tickets = []

    def queue(self, action, decision, provenance="", **kw):
        ticket = {"action": action, "decision": decision,
                  "provenance": provenance}
        ticket.update(kw)
        ticket["id"] = "T-%d" % len(self.tickets)
        self.tickets.append(ticket)
        return ticket["id"]


class TestInventory(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow")
        _append(log, "tool_call", tool="send_email", agent_id="a1",
                run_id="r1", decision="allow")

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()

    def test_inventory_lists_observed_tools_with_tier(self):
        inv = CapabilityHarness(self.log_path).inventory()
        tools = inv["tool_surface"]["value"]["observed_tools"]
        self.assertEqual(sorted(tools), ["read_file", "send_email"])
        # read_file {untrusted_content, private_data} + send_email
        # {external_comm} = the trifecta -> elevated.
        self.assertEqual(
            inv["autonomy_posture"]["value"]["session_tier"]["value"],
            "elevated")

    def test_inventory_standard_tier_for_narrow_grants(self):
        from gov.log import ActionLog
        tmp2 = tempfile.TemporaryDirectory()
        self.addCleanup(tmp2.cleanup)
        p2 = os.path.join(tmp2.name, "audit2.log")
        log = ActionLog(p2)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow")
        inv = CapabilityHarness(p2).inventory()
        self.assertEqual(
            inv["autonomy_posture"]["value"]["session_tier"]["value"],
            "standard")

    def test_unregistered_candidates_from_discovery_ledger(self):
        from gov.discovery import DiscoveryLedger
        ledger_path = os.path.join(self.tmp.name, "discovery.jsonl")
        ledger = DiscoveryLedger(ledger_path)
        ledger.note_signals([{"kind": "agent_process", "source": "pwn.py",
                              "detail": {"pid": 4242}, "strength": 3}])
        inv = CapabilityHarness(
            self.log_path,
            discovery_ledger_path=ledger_path).inventory()
        cands = inv["unregistered_candidates"]["value"]
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "candidate")

    def test_sandbox_cage_unknowable_is_operator_supplied(self):
        # No cage-mode event in the log: the field must be null, not
        # defaulted to False (absence of evidence is not evidence).
        inv = CapabilityHarness(self.log_path).inventory()
        cage = inv["autonomy_posture"]["value"]["sandbox_cage_mode"]
        self.assertIsNone(cage["value"])
        self.assertEqual(cage["provenance"]["kind"],
                         "operator_must_supply")

    def test_inventory_refuses_unverifiable_chain(self):
        with open(self.log_path, "r+b") as f:
            data = f.read()
            idx = data.find(b"read_file")
            f.seek(idx)
            f.write(b"X")
        with self.assertRaises(CapabilityMeasureError):
            CapabilityHarness(self.log_path).inventory()

    def test_delegation_and_lease_counts_are_log_derived(self):
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "delegation_token_issued", token_id="dt-1")
        _append(log, "capability_lease_granted", lease_id="cl-1")
        inv = CapabilityHarness(self.log_path).inventory()
        post = inv["autonomy_posture"]["value"]
        self.assertEqual(
            post["delegation_tokens_issued"]["value"], 1)
        self.assertEqual(post["capability_leases"]["value"], 1)


class TestMeasure(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow")
        self.checkpoint = log.append(
            {"event": "checkpoint_note", "note": "window start"})["seq"]

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()

    def test_measure_detects_tool_gain_and_tier_transition(self):
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="send_email", agent_id="a1",
                run_id="r1", decision="allow")
        _append(log, "tool_call", tool="api_call", agent_id="a1",
                run_id="r1", decision="allow")
        delta = CapabilityHarness(self.log_path).measure(
            self.checkpoint,
            log.append({"event": "checkpoint_note"})["seq"])
        self.assertEqual(sorted(delta["value"]["tools_added"]),
                         ["api_call", "send_email"])
        self.assertEqual(delta["value"]["tier_transition"],
                         ["standard", "elevated"])
        self.assertGreater(delta["value"]["delta_score"], 0)
        # The delta record as a whole carries log-window provenance.
        self.assertEqual(delta["provenance"]["kind"], "log_window")
        self.assertEqual(delta["provenance"]["from_seq"], self.checkpoint)

    def test_measure_empty_window_scores_zero(self):
        delta = CapabilityHarness(self.log_path).measure(
            self.checkpoint, self.checkpoint)
        self.assertEqual(delta["value"]["delta_score"], 0)


class TestGate(unittest.TestCase):
    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow")
        self.checkpoint = log.append(
            {"event": "checkpoint_note"})["seq"]

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()

    def _big_delta(self):
        return {"value": {
            "from_seq": self.checkpoint, "to_seq": self.checkpoint + 1,
            "tools_added": ["send_email", "api_call", "install_package"],
            "tier_transition": ["standard", "elevated"],
            "new_unregistered_candidates": 1,
            "new_egress_domains": ["evil.example"],
            "delta_score": CM_DEFAULTS["human_review_delta"] + 1.0,
            "delta_score_meta": {"provenance": {"kind": "log_window"}},
        }}

    def test_gate_proceeds_below_threshold(self):
        small = {"value": dict(self._big_delta()["value"])}
        small["value"]["delta_score"] = 0.0
        out = CapabilityHarness(self.log_path).gate(small)
        self.assertTrue(out["proceed"])
        self.assertIsNone(out["approval_required"])

    def test_gate_refuses_at_threshold_and_logs_refusal(self):
        from gov.log import read_entries
        out = CapabilityHarness(self.log_path).gate(self._big_delta())
        self.assertFalse(out["proceed"])
        ticket = out["approval_required"]
        self.assertEqual(ticket["kind"], "capability_delta_review")
        self.assertGreaterEqual(
            ticket["delta_score"], CM_DEFAULTS["human_review_delta"])
        # The refusal is itself audited in the hash-chained log.
        events = [e["event"] for e in read_entries(self.log_path)]
        self.assertIn("capability_gate_refused", events)

    def test_gate_emits_ticket_into_queue(self):
        q = _FakeQueue()
        out = CapabilityHarness(self.log_path).gate(
            self._big_delta(), queue=q,
            caller_identity=object())  # fake queue: no auth performed
        self.assertFalse(out["proceed"])
        self.assertEqual(len(q.tickets), 1)
        self.assertEqual(q.tickets[0]["provenance"],
                         "capability_harness")
        self.assertIn("approval_id", out["approval_required"])

def _real_queue_with_verifier(tmpdir):
    """A REAL gov/approvals.py ApprovalQueue with an executor-style
    identity verifier installed (mirrors ToolExecutor._verify_approval_identity:
    only minted (agent_id, role, run_id, principal) tuples pass)."""
    from gov.approvals import ApprovalQueue
    from gov.identity import (AgentIdentity, UnmintedIdentityError)
    from gov.log import ActionLog
    run_dir = os.path.join(tmpdir, "run-gate")
    os.makedirs(run_dir, exist_ok=True)
    qlog = ActionLog(os.path.join(run_dir, "actions.jsonl"))
    q = ApprovalQueue(run_dir, qlog)
    minted = set()

    def verifier(ident):
        if (ident.run_id != q.run_id
                or (ident.agent_id, ident.role, ident.run_id,
                    ident.principal) not in minted):
            raise UnmintedIdentityError(
                "not minted for run %r: %r" % (q.run_id, ident))
        return True

    q.set_identity_verifier(verifier)
    ident = AgentIdentity(agent_id="capability-harness", role="governance",
                          run_id=q.run_id, principal="operator",
                          provenance="minted")
    minted.add((ident.agent_id, ident.role, ident.run_id,
                ident.principal))
    return q, ident


class TestGateRealQueue(unittest.TestCase):
    """gate() against the REAL gov/approvals.py ApprovalQueue.

    Regression for the review NO-GO: gate() raised TypeError against
    the real queue (no caller_identity, string decision instead of a
    decision object with policy_id) and only worked against the
    _FakeQueue, which hid the incompatibility.
    """

    def setUp(self):
        self._restore = _provision_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, "audit.log")
        from gov.log import ActionLog
        log = ActionLog(self.log_path)
        _append(log, "tool_call", tool="read_file", agent_id="a1",
                run_id="r1", decision="allow")
        self.checkpoint = log.append(
            {"event": "checkpoint_note"})["seq"]

    def tearDown(self):
        self._restore()
        self.tmp.cleanup()

    def _big_delta(self):
        return {"value": {
            "from_seq": self.checkpoint, "to_seq": self.checkpoint + 1,
            "tools_added": ["send_email", "api_call", "install_package"],
            "tier_transition": ["standard", "elevated"],
            "new_unregistered_candidates": 1,
            "new_egress_domains": ["evil.example"],
            "delta_score": CM_DEFAULTS["human_review_delta"] + 1.0,
        }}

    def test_gate_queues_ticket_on_real_approval_queue(self):
        q, ident = _real_queue_with_verifier(self.tmp.name)
        out = CapabilityHarness(self.log_path).gate(
            self._big_delta(), queue=q, caller_identity=ident)
        self.assertFalse(out["proceed"])
        pending = q.pending()
        self.assertEqual(len(pending), 1)
        rec = pending[0]
        self.assertEqual(rec["policy_id"],
                         "capability-delta-human-review")
        self.assertEqual(rec["policy_flag"],
                         "capability-delta-human-review")
        self.assertEqual(rec["agent_id"], "capability-harness")
        self.assertEqual(out["approval_required"]["approval_id"],
                         rec["id"])
        # The refusal audit references the real ticket (queue-first
        # ordering: the log never records a refusal with no ticket).
        from gov.log import read_entries
        refusals = [e for e in read_entries(self.log_path)
                    if e["event"] == "capability_gate_refused"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["approval_id"], rec["id"])

    def test_gate_without_caller_identity_fails_closed(self):
        # F42: the real queue refuses queue() without a caller
        # identity; gate() must fail closed up front, not TypeError
        # from deep inside the queue.
        q, _ident = _real_queue_with_verifier(self.tmp.name)
        with self.assertRaises(CapabilityMeasureError):
            CapabilityHarness(self.log_path).gate(
                self._big_delta(), queue=q)

    def test_gate_rejects_unminted_caller_identity(self):
        # The queue's verifier (executor-minted check) still applies:
        # a hand-built identity is refused, not silently queued.
        from gov.identity import AgentIdentity
        q, _ident = _real_queue_with_verifier(self.tmp.name)
        rogue = AgentIdentity(agent_id="rogue", role="x",
                              run_id=q.run_id, principal="y")
        with self.assertRaises(Exception):
            CapabilityHarness(self.log_path).gate(
                self._big_delta(), queue=q, caller_identity=rogue)

    def test_gate_is_idempotent_for_same_delta(self):
        # A retry loop must not flood the queue or the audit log: a
        # second above-threshold gate() on the same delta reuses the
        # still-open ticket.
        q, ident = _real_queue_with_verifier(self.tmp.name)
        harness = CapabilityHarness(self.log_path)
        first = harness.gate(self._big_delta(), queue=q,
                             caller_identity=ident)
        second = harness.gate(self._big_delta(), queue=q,
                              caller_identity=ident)
        self.assertFalse(second["proceed"])
        self.assertEqual(len(q.pending()), 1)
        self.assertEqual(
            second["approval_required"]["approval_id"],
            first["approval_required"]["approval_id"])
        self.assertTrue(
            second["approval_required"].get("idempotent_reuse"))
        from gov.log import read_entries
        refusals = [e for e in read_entries(self.log_path)
                    if e["event"] == "capability_gate_refused"]
        self.assertEqual(len(refusals), 1,
                         "retry must not flood the audit log")

    def test_gate_queue_failure_leaves_no_orphan_refusal(self):
        # Atomicity: if queue.queue() raises, the refusal must NOT be
        # logged without a ticket (the old log-before-queue order did
        # exactly that). The failure itself is audited, then re-raised.
        class _BoomQueue:
            def queue(self, *a, **k):
                raise RuntimeError("queue exploded")

        with self.assertRaises(RuntimeError):
            CapabilityHarness(self.log_path).gate(
                self._big_delta(), queue=_BoomQueue(),
                caller_identity=object())
        from gov.log import read_entries
        events = [e["event"] for e in read_entries(self.log_path)]
        self.assertNotIn("capability_gate_refused", events)
        self.assertIn("capability_gate_ticket_failed", events)


if __name__ == "__main__":
    unittest.main()
