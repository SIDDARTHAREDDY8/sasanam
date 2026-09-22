"""Wave-24 D1 bridge surface: adversarial + contract tests.

Covers gov/approvals.py's bridge surface (queue_external /
wait_for_decision / get_record), the T12/F85 sweep invariant for
bridge records, and the gov/bridges/ adapters (core ABC helpers +
AGT-Python shim).

Adversarial focus per the wave brief:
* foreign-digest forgery -> rejected (MAC-bound foreign data);
* replayed external_request_id -> idempotent (no duplicate entries);
* late decision after bridge_expired -> audit-only, NEVER executable
  (T12 sweep check);
* timeout -> deny with the record staying pending.

Terminology guard (A12, binding): "approval delegation" (D1-core
human stewardship) vs "authority delegation" (P10 agent-to-agent) are
distinct primitives. These tests never use "delegation" for bridge
behavior; the bridge tests assert the bridge surface does not
implement, bypass, or rename either primitive.
"""

import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run
from gov.approvals import _pending_record_content_ok, approval_digest_ok
from gov.bridges import BridgeAdapter, BridgeHandle, compute_request_digest
from gov.bridges.agt import DurableQueueApprovalHandler


def _events(run, name):
    path = Path(run["run_dir"]) / "actions.jsonl"
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            if e.get("event") == name:
                out.append(e)
    return out


def _rewrite_approvals(run, fn):
    path = Path(run["run_dir"]) / "approvals.jsonl"
    recs = [json.loads(l) for l in
            path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for r in recs:
        fn(r)
    path.write_text(
        "\n".join(json.dumps(r) for r in recs) + "\n", encoding="utf-8")


def _bridge_identity(run, agent_id="agt:did:agentmesh:test-1"):
    return run["executor"].mint_identity(agent_id, "foreign-agent",
                                        "did:agentmesh:test-1")


def _queue_bridge(run, external_request_id="agt-req-1",
                  bridge_id="agt-python",
                  digest="sha256:abc123",
                  tool="agt:send_notification",
                  agent_identity=None):
    return run["approvals"].queue_external(
        tool=tool,
        args={"to": "ops@synthetic.local", "text": "deploy done"},
        policy_id="agt:policy-7",
        agent_identity=(agent_identity if agent_identity is not None
                        else _bridge_identity(run)),
        preview="Foreign approval request via AGT-Python bridge:\n"
                "  action: send_notification",
        bridge_id=bridge_id,
        external_request_id=external_request_id,
        bridge_request_digest=digest,
        bridge_versions={"action": "v3", "policy": "v7"},
        agent_justification="foreign caller claim (UNVERIFIED): "
                            "did:agentmesh:test-1",
    )


class TestQueueExternal(unittest.TestCase):
    """queue_external(): bridge ingress contract."""

    def test_happy_path_record_shape(self):
        run = make_run()
        aid = _queue_bridge(run)
        rec = run["approvals"].get(aid)
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(rec["provenance"], "bridge")
        self.assertEqual(rec["bridge_id"], "agt-python")
        self.assertEqual(rec["external_request_id"], "agt-req-1")
        self.assertEqual(rec["bridge_request_digest"], "sha256:abc123")
        self.assertEqual(rec["bridge_versions"],
                         {"action": "v3", "policy": "v7"})
        self.assertEqual(rec["decision_mode"], "single")
        self.assertIsNone(rec["policy_hash"],
                          "foreign policy: our policy_hash pinning "
                          "does not apply")
        self.assertTrue(_pending_record_content_ok(rec),
                        "bridge record must be MAC-bound from birth")
        queued = _events(run, "bridge_external_queued")
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["approval_id"], aid)
        self.assertEqual(queued[0]["bridge_id"], "agt-python")

    def test_requires_minted_identity_f42(self):
        run = make_run()
        with self.assertRaises(TypeError):
            _queue_bridge(run, agent_identity="not-an-identity")
        with self.assertRaises(TypeError):
            run["approvals"].queue_external(
                tool="agt:x", args={}, policy_id="agt:p",
                agent_identity=None, preview="p", bridge_id="b")

    def test_rejects_bad_bridge_id(self):
        run = make_run()
        ident = _bridge_identity(run)
        for bad in ("", "   ", None, "x" * 65):
            with self.assertRaises(ValueError):
                run["approvals"].queue_external(
                    tool="agt:x", args={}, policy_id="agt:p",
                    agent_identity=ident, preview="p", bridge_id=bad)

    def test_replay_is_idempotent_no_duplicate(self):
        run = make_run()
        aid1 = _queue_bridge(run)
        # A replay with DIFFERENT payload still returns the original —
        # idempotency keys on the foreign request id, and the second
        # call must not queue a second record.
        aid2 = run["approvals"].queue_external(
            tool="agt:totally_different", args={"evil": True},
            policy_id="agt:policy-9",
            agent_identity=_bridge_identity(run, "agt:did:agentmesh:x"),
            preview="different", bridge_id="agt-python",
            external_request_id="agt-req-1",
            bridge_request_digest="sha256:different")
        self.assertEqual(aid1, aid2)
        recs = [r for r in run["approvals"].all()
                if r.get("external_request_id") == "agt-req-1"]
        self.assertEqual(len(recs), 1,
                         "replayed external_request_id queued a duplicate")
        self.assertEqual(recs[0]["tool"], "agt:send_notification",
                         "replay must not overwrite the original record")
        replay = _events(run, "bridge_idempotency_replay")
        self.assertEqual(len(replay), 1)
        self.assertEqual(replay[0]["approval_id"], aid1)

    def test_cross_bridge_key_claim_refused(self):
        run = make_run()
        aid = _queue_bridge(run, bridge_id="agt-python")
        with self.assertRaises(ValueError):
            _queue_bridge(run, bridge_id="some-other-bridge")
        conflict = _events(run, "bridge_idempotency_conflict")
        self.assertEqual(len(conflict), 1)
        # Still exactly one record for the key, owned by agt-python.
        recs = [r for r in run["approvals"].all()
                if r.get("external_request_id") == "agt-req-1"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["id"], aid)
        self.assertEqual(recs[0]["bridge_id"], "agt-python")

    def test_replay_of_decided_record_returns_id(self):
        run = make_run()
        aid = _queue_bridge(run)
        run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
        aid2 = _queue_bridge(run)
        self.assertEqual(aid, aid2,
                         "idempotency covers decided records too — never "
                         "a second record")

    def test_foreign_digest_forgery_rejected(self):
        run = make_run()
        aid = _queue_bridge(run)
        # Attacker swaps the stored foreign digest post-queue (e.g. to
        # launder a different foreign request under this approval).
        _rewrite_approvals(
            run, lambda r: r.update(
                {"bridge_request_digest": "sha256:forged"})
            if r["id"] == aid else None)
        rec = run["approvals"].get(aid)
        self.assertFalse(_pending_record_content_ok(rec),
                         "forged bridge_request_digest must break the MAC")
        with self.assertRaises(ValueError):
            run["approvals"].decide(aid, True, "ok",
                                    decided_by="human-operator")

    def test_external_request_id_tamper_rejected(self):
        run = make_run()
        aid = _queue_bridge(run)
        _rewrite_approvals(
            run, lambda r: r.update({"external_request_id": "agt-req-evil"})
            if r["id"] == aid else None)
        self.assertFalse(_pending_record_content_ok(
            run["approvals"].get(aid)),
            "rewriting the idempotency key must break the MAC")

    def test_bridge_id_badge_tamper_rejected(self):
        run = make_run()
        aid = _queue_bridge(run)
        _rewrite_approvals(
            run, lambda r: r.update({"bridge_id": "trusted-native"})
            if r["id"] == aid else None)
        self.assertFalse(_pending_record_content_ok(
            run["approvals"].get(aid)),
                         "badge spoofing (bridge_id rewrite) must break "
                         "the MAC")

    def test_no_quorum_snapshot_on_bridge_records(self):
        run = make_run()
        run["approvals"].set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["alice", "bob", "carol"]})
        aid = _queue_bridge(run)
        rec = run["approvals"].get(aid)
        self.assertEqual(rec["decision_mode"], "single")
        self.assertIsNone(rec["quorum"],
                          "bridge path is single-steward: the foreign "
                          "wait is bounded in minutes")


class TestWaitForDecision(unittest.TestCase):
    """wait_for_decision(): bounded waits, timeouts, late decisions."""

    def test_wait_returns_human_approval(self):
        run = make_run()
        aid = _queue_bridge(run)

        def _decide_later():
            time.sleep(0.3)
            run["approvals"].decide(aid, True, "human ok",
                                    decided_by="human-operator")

        t = threading.Thread(target=_decide_later)
        t.start()
        try:
            self.assertEqual(
                run["approvals"].wait_for_decision(aid, 5.0), "approved")
        finally:
            t.join()

    def test_wait_returns_human_rejection(self):
        run = make_run()
        aid = _queue_bridge(run)

        def _decide_later():
            time.sleep(0.3)
            run["approvals"].decide(aid, False, "human no",
                                    decided_by="human-operator")

        t = threading.Thread(target=_decide_later)
        t.start()
        try:
            self.assertEqual(
                run["approvals"].wait_for_decision(aid, 5.0), "rejected")
        finally:
            t.join()

    def test_timeout_denies_and_record_stays_pending(self):
        run = make_run()
        aid = _queue_bridge(run)
        self.assertEqual(
            run["approvals"].wait_for_decision(aid, 0.2), "timeout")
        rec = run["approvals"].get(aid)
        self.assertEqual(rec["status"], "pending",
                         "timeout must not decide the record")
        self.assertTrue(rec["bridge_expired"])
        self.assertIsNotNone(rec["bridge_expired_at"])
        expired = _events(run, "bridge_wait_expired")
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["approval_id"], aid)

    def test_late_decision_after_timeout_never_executes_t12(self):
        # F85 regression: the D1-core T12 invariant — a human approval
        # recorded AFTER the bridge wait expired is audit-only and can
        # NEVER execute. The sweep must refuse it loudly.
        run = make_run()
        aid = _queue_bridge(run)
        self.assertEqual(
            run["approvals"].wait_for_decision(aid, 0.2), "timeout")
        record, _ = run["approvals"].decide(
            aid, True, "human still wants it", decided_by="human-operator")
        self.assertTrue(record["late_decision"])
        self.assertEqual(record["status"], "approved")
        done = run["executor"].execute_approved()
        self.assertEqual(done, [],
                         "T12: bridge_expired record must never execute")
        rec = run["approvals"].get(aid)
        self.assertFalse(rec["executed"])
        refused = [e for e in _events(run, "approval_execution_refused")
                   if e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "bridge_expired")

    def test_timeout_validation(self):
        run = make_run()
        aid = _queue_bridge(run)
        q = run["approvals"]
        for bad in (0, -1, -0.5):
            with self.assertRaises(ValueError):
                q.wait_for_decision(aid, bad)
        with self.assertRaises(ValueError):
            q.wait_for_decision(aid, q.BRIDGE_WAIT_MAX_TIMEOUT_SECS + 1)
        with self.assertRaises(ValueError):
            q.wait_for_decision(aid, float("inf"))
        with self.assertRaises(TypeError):
            q.wait_for_decision(aid, "soon")
        with self.assertRaises(TypeError):
            q.wait_for_decision(aid, True)

    def test_unknown_id_refused(self):
        run = make_run()
        with self.assertRaises(ValueError):
            run["approvals"].wait_for_decision("no-such-id", 1.0)
        unknown = _events(run, "bridge_wait_unknown_id")
        self.assertEqual(len(unknown), 1)

    def test_record_vanishing_midwait_is_timeout(self):
        run = make_run()
        aid = _queue_bridge(run)
        path = Path(run["run_dir"]) / "approvals.jsonl"

        def _delete_later():
            time.sleep(0.2)
            path.unlink()

        t = threading.Thread(target=_delete_later)
        t.start()
        try:
            self.assertEqual(
                run["approvals"].wait_for_decision(aid, 5.0), "timeout",
                "a vanished record must fail toward deny, never approve")
        finally:
            t.join()
        missing = _events(run, "bridge_wait_record_missing")
        self.assertEqual(len(missing), 1)


class TestForeignRecordSweep(unittest.TestCase):
    """Our sweep never executes foreign (bridge-queued) records."""

    def test_approved_bridge_record_not_executed_by_our_sweep(self):
        run = make_run()
        aid = _queue_bridge(run)
        run["approvals"].decide(aid, True, "human ok",
                                decided_by="human-operator")
        done = run["executor"].execute_approved()
        self.assertEqual(done, [])
        rec = run["approvals"].get(aid)
        self.assertFalse(rec["executed"],
                         "bridge records are foreign-executed; our sweep "
                         "must never execute them (double execution)")
        self.assertEqual(rec["status"], "approved")
        refused = [e for e in _events(run, "approval_execution_refused")
                   if e.get("approval_id") == aid]
        self.assertEqual(refused, [],
                         "healthy foreign records skip quietly — the "
                         "bridge_id marker is by-design, not a refusal")

    def test_tampered_bridge_record_still_refused_loudly(self):
        run = make_run()
        aid = _queue_bridge(run)
        run["approvals"].decide(aid, True, "human ok",
                                decided_by="human-operator")
        _rewrite_approvals(
            run, lambda r: r.update({"tool": "agt:evil_tool"})
            if r["id"] == aid else None)
        done = run["executor"].execute_approved()
        self.assertEqual(done, [])
        refused = [e for e in _events(run, "approval_execution_refused")
                   if e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_integrity_violation")

    def test_native_record_still_executes(self):
        # The foreign-record skip must not swallow native approvals.
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support",
                                              "agent-1")
        res = run["executor"].call(
            ident, "send_email", to="victim@synthetic.local",
            subject="hello", body="hello")
        self.assertEqual(res["status"], "queued")
        aid = res["approval_id"]
        run["approvals"].decide(aid, True, "ok", decided_by="human-operator")
        done = run["executor"].execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(run["approvals"].get(aid)["executed"])


class TestGetRecord(unittest.TestCase):
    """get_record(): detached read-only view for bridges."""

    def test_returns_detached_copy(self):
        run = make_run()
        aid = _queue_bridge(run)
        rec = run["approvals"].get_record(aid)
        self.assertEqual(rec["bridge_id"], "agt-python")
        self.assertEqual(rec["external_request_id"], "agt-req-1")
        # Mutating the copy (including nested structures) must not
        # touch the queue file.
        rec["bridge_id"] = "mutated"
        rec["bridge_versions"]["action"] = "mutated"
        rec["args"]["to"] = "mutated@synthetic.local"
        stored = run["approvals"].get(aid)
        self.assertEqual(stored["bridge_id"], "agt-python")
        self.assertEqual(stored["bridge_versions"]["action"], "v3")
        self.assertEqual(stored["args"]["to"], "ops@synthetic.local")

    def test_unknown_id_returns_none(self):
        run = make_run()
        self.assertIsNone(run["approvals"].get_record("nope"))


class TestBridgeCoreHelpers(unittest.TestCase):
    """gov/bridges/core.py: digest + fail-safe helpers."""

    def test_compute_request_digest_deterministic(self):
        env = {"request_id": "r1", "action": "a", "arguments": {"x": 1},
               "caller": "did:agentmesh:1"}
        d1 = compute_request_digest(env)
        d2 = compute_request_digest(dict(env))
        self.assertEqual(d1, d2)
        self.assertTrue(d1.startswith("sha256:"))
        env2 = dict(env, arguments={"x": 2})
        self.assertNotEqual(d1, compute_request_digest(env2))
        with self.assertRaises(TypeError):
            compute_request_digest("not-a-dict")

    def test_bridge_handle_validation(self):
        h = BridgeHandle("aid1", "agt-python", "req-1")
        self.assertEqual(h.to_dict()["approval_id"], "aid1")
        with self.assertRaises(ValueError):
            BridgeHandle("", "agt-python")
        with self.assertRaises(ValueError):
            BridgeHandle("aid1", "")

    def test_bounded_wait_maps_failure_to_deny(self):
        run = make_run()

        class _Concrete(BridgeAdapter):
            def request_approval(self, ctx):
                raise NotImplementedError

            def wait_for_decision(self, handle, timeout_s):
                raise NotImplementedError

            def abort(self, handle, reason):
                raise NotImplementedError

        adapter = _Concrete()
        adapter.bridge_id = "test-bridge"
        handle = BridgeHandle("no-such-id", "test-bridge")
        self.assertEqual(
            adapter.bounded_wait(run["approvals"], handle, 1.0),
            "rejected")
        failed = _events(run, "bridge_wait_failed")
        self.assertEqual(len(failed), 1)

    def test_adapter_is_abstract(self):
        with self.assertRaises(TypeError):
            BridgeAdapter()


class TestAgtShim(unittest.TestCase):
    """gov/bridges/agt.py: the AGT-Python shim."""

    def _ctx(self, **over):
        ctx = {"action": "send_notification",
               "arguments": {"to": "ops@synthetic.local"},
               "request_id": "agt-req-42",
               "caller_did": "did:agentmesh:agent-9",
               "policy_id": "policy-7",
               "versions": {"action": "v3"}}
        ctx.update(over)
        return ctx

    def test_request_approval_queues_bridge_record(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(run["approvals"],
                                             run["executor"])
        handle = handler.request_approval(self._ctx())
        self.assertIsInstance(handle, BridgeHandle)
        self.assertEqual(handle.bridge_id, "agt-python")
        self.assertEqual(handle.external_request_id, "agt-req-42")
        rec = run["approvals"].get_record(handle.approval_id)
        self.assertEqual(rec["bridge_id"], "agt-python")
        self.assertEqual(rec["tool"], "agt:send_notification")
        self.assertEqual(rec["external_request_id"], "agt-req-42")
        self.assertEqual(rec["bridge_versions"], {"action": "v3"})
        # The DID is recorded verbatim as UNVERIFIED framing; the
        # human-facing preview is bridge-generated.
        self.assertIn("did:agentmesh:agent-9",
                      rec["agent_justification"])
        self.assertIn("UNVERIFIED", rec["agent_justification"])
        self.assertIn("UNVERIFIED", rec["preview"])
        self.assertTrue(_pending_record_content_ok(
            run["approvals"].get(handle.approval_id)))

    def test_request_approval_idempotent_on_foreign_request_id(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(run["approvals"],
                                             run["executor"])
        h1 = handler.request_approval(self._ctx())
        h2 = handler.request_approval(self._ctx())
        self.assertEqual(h1.approval_id, h2.approval_id)
        recs = [r for r in run["approvals"].all()
                if r.get("external_request_id") == "agt-req-42"]
        self.assertEqual(len(recs), 1)

    def test_wait_timeout_means_deny(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(
            run["approvals"], run["executor"], wait_timeout_s=0.2)
        handle = handler.request_approval(self._ctx())
        # The QUEUE reports "timeout"; the SHIM maps every non-approval
        # to deny (fail-safe: only an explicit human "approved" approves).
        self.assertEqual(
            run["approvals"].wait_for_decision(handle.approval_id, 0.2),
            "timeout")
        handle2 = handler.request_approval(
            self._ctx(request_id="agt-req-43"))
        self.assertEqual(handler.wait_for_decision(handle2), "rejected")
        self.assertEqual(handler.to_agt_decision("timeout"), "REJECTED")
        self.assertEqual(handler.to_agt_decision("rejected"), "REJECTED")
        self.assertEqual(handler.to_agt_decision("approved"), "APPROVED")
        self.assertEqual(handler.to_agt_decision("weird"), "REJECTED")

    def test_wait_honors_human_approval(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(
            run["approvals"], run["executor"], wait_timeout_s=5.0)
        handle = handler.request_approval(self._ctx())

        def _decide_later():
            time.sleep(0.3)
            run["approvals"].decide(handle.approval_id, True, "human ok",
                                    decided_by="human-operator")

        t = threading.Thread(target=_decide_later)
        t.start()
        try:
            self.assertEqual(handler.wait_for_decision(handle), "approved")
        finally:
            t.join()
        self.assertEqual(handler.to_agt_decision("approved"), "APPROVED")

    def test_wait_must_be_strictly_shorter_than_foreign(self):
        run = make_run()
        with self.assertRaises(ValueError):
            DurableQueueApprovalHandler(run["approvals"], run["executor"],
                                        wait_timeout_s=300.0)
        with self.assertRaises(ValueError):
            DurableQueueApprovalHandler(run["approvals"], run["executor"],
                                        wait_timeout_s=600.0)
        with self.assertRaises(ValueError):
            DurableQueueApprovalHandler(run["approvals"], run["executor"],
                                        wait_timeout_s=0)

    def test_abort_is_audited(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(run["approvals"],
                                             run["executor"])
        handle = handler.request_approval(self._ctx())
        handler.abort(handle, "agent disconnected")
        aborted = _events(run, "bridge_aborted")
        self.assertEqual(len(aborted), 1)
        self.assertEqual(aborted[0]["approval_id"], handle.approval_id)
        # The queued record stands — abort cannot un-queue.
        self.assertEqual(run["approvals"].get(handle.approval_id)["status"],
                         "pending")

    def test_rejects_null_or_shapeless_context(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(run["approvals"],
                                             run["executor"])
        with self.assertRaises(ValueError):
            handler.request_approval(None)
        with self.assertRaises(ValueError):
            handler.request_approval({"no_action": True})

    def test_object_context_supported(self):
        run = make_run()
        handler = DurableQueueApprovalHandler(run["approvals"],
                                             run["executor"])

        class Ctx:
            action = "read_file"
            arguments = {"path": "/tmp/x"}
            request_id = "obj-1"
            caller_did = "did:agentmesh:obj"

        handle = handler.request_approval(Ctx())
        self.assertEqual(handle.external_request_id, "obj-1")

    def test_end_to_end_deny_on_timeout(self):
        # Full shim flow: request -> human never decides -> timeout ->
        # bridge returns deny; record stays pending, bridge_expired.
        run = make_run()
        handler = DurableQueueApprovalHandler(
            run["approvals"], run["executor"], wait_timeout_s=0.2)
        handle = handler.request_approval(self._ctx())
        outcome = handler.wait_for_decision(handle)
        agt_decision = handler.to_agt_decision(outcome)
        self.assertEqual(agt_decision, "REJECTED")
        rec = run["approvals"].get_record(handle.approval_id)
        self.assertEqual(rec["status"], "pending")
        self.assertTrue(rec["bridge_expired"])


if __name__ == "__main__":
    unittest.main()
