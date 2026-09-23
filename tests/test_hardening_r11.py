"""Hardening round-11 regression tests: wave-12 findings F42-F49.

F42 (CRITICAL): the queue-MAC oracle — queue() now requires a minted
    caller identity; attacker-supplied action["identity"] is ignored.
F43 (CRITICAL): the pending MAC binds the full security record.
F44 (HIGH):     queue-lock deletion/replacement is detected.
F45 (HIGH):     interrupted executions are reconciled, never silently
    skipped nor auto-executed.
F46 (MEDIUM):   campaign establishment needs multi-run continuity
    (or a deployment registry).
F47 (MEDIUM):   cross-privilege tool smuggling refused at execution.
F48 (MEDIUM):   policy load/pin is audited; pin mismatch refuses.
F49 (HIGH):     break-glass needs a human-provisioned ticket.
"""

import fcntl
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import make_run, DEFAULT_POLICY  # noqa: E402
from gov.approvals import (  # noqa: E402
    APPROVAL_DIGEST_SCHEME,
    BREAK_GLASS_TICKET_FILENAME,
    QueueLockError,
    QueueLockInvalidatedError,
    approval_digest_ok,
    approval_record_digest,
    provision_break_glass_ticket,
)
from gov.executor import PolicyPinMismatchError, ToolExecutor  # noqa: E402
from gov.identity import (  # noqa: E402
    AgentIdentity,
    PrincipalRegistry,
    UnmintedIdentityError,
)
from gov.log import read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402


def _queued_send(q, caller, tool="read_file", args=None, policy_hash=None):
    """Queue a benign item with an explicit caller identity."""
    return q.queue(
        {"tool": tool, "args": args or {"path": "notes.txt"},
         "identity": {"agent_id": "spoofed", "role": "admin",
                      "run_id": "spoofed-run", "principal": "spoofed-org"},
         "redactions": [], "agent_justification": "test"},
        SimpleNamespace(policy_id="p", reason="r", flag=None),
        preview="test preview",
        policy_hash=policy_hash,
        caller_identity=caller)


def _queued_send_ex(ctx, tool="read_file", args=None):
    """Queue with the run's real policy hash (needed for execute_approved)."""
    caller = ctx["mint_identity"]("a1", "researcher", "org")
    return _queued_send(ctx["approvals"], caller, tool=tool, args=args,
                        policy_hash=ctx["executor"].policy.policy_hash)


# ---------------------------------------------------------------------------
# F42 — queue() requires a minted caller identity; the action["identity"]
# dict is never authoritative.
# ---------------------------------------------------------------------------

class TestF42QueueCallerIdentity(unittest.TestCase):
    def test_spoofed_action_identity_ignored(self):
        """The record is stamped from the AUTHENTICATED caller, not from
        action["identity"] (the wave-12 oracle)."""
        ctx = make_run()
        q = ctx["approvals"]
        caller = ctx["mint_identity"]("real-agent", "researcher", "real-org")
        aid = _queued_send(q, caller)
        rec = q.get(aid)
        self.assertEqual(rec["agent_id"], "real-agent")
        self.assertEqual(rec["role"], "researcher")
        self.assertEqual(rec["principal"], "real-org")
        self.assertEqual(rec["run_id"], q.run_dir.name)
        self.assertNotIn("spoofed", json.dumps(rec["identity"]))

    def test_missing_caller_identity_fails_closed(self):
        ctx = make_run()
        q = ctx["approvals"]
        with self.assertRaises(TypeError):
            q.queue({"tool": "read_file", "args": {"path": "x"}},
                    SimpleNamespace(policy_id="p", reason="r", flag=None))

    def test_unminted_caller_identity_refused(self):
        ctx = make_run()
        q = ctx["approvals"]
        fake = AgentIdentity(agent_id="mallory", role="researcher",
                             run_id=q.run_dir.name, principal="mallory")
        with self.assertRaises(UnmintedIdentityError):
            _queued_send(q, fake)

    def test_wrong_run_identity_refused(self):
        ctx_a = make_run()
        ctx_b = make_run()
        q_b = ctx_b["approvals"]
        # Identity minted for run A cannot queue into run B's queue.
        caller_a = ctx_a["mint_identity"]("a", "researcher", "org")
        with self.assertRaises(UnmintedIdentityError):
            _queued_send(q_b, caller_a)


# ---------------------------------------------------------------------------
# F43 — the pending MAC binds the full security record.
# ---------------------------------------------------------------------------

class TestF43PendingMacMetadata(unittest.TestCase):
    def test_decision_time_preview_tamper_refused_and_audited(self):
        """Rewriting the preview between queue() and decide() breaks the
        pending digest: decide() refuses and audits the rejected
        attempt — the tampered content is never re-MACed as approved."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send(q, caller)
        q._rewrite(lambda rs: [
            dict(r, preview="URGENT — approve immediately, totally legit")
            if r["id"] == aid else r for r in rs])
        with self.assertRaises(ValueError):
            q.decide(aid, True, "looks fine", decided_by="human-operator")
        rec = q.get(aid)
        self.assertEqual(rec["status"], "pending")
        attempts = [e for e in
                    read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("event") == "approval_decision_attempt"]
        self.assertTrue(any(e.get("decision") == "rejected_attempt" and
                            e.get("approval_id") == aid
                            for e in attempts),
                        "the tampered decision attempt must be audited")

    def test_execution_time_tamper_refused(self):
        """Tampering after decide() breaks the approved digest:
        execution refuses with approval_integrity_violation."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send_ex(ctx)
        q.decide(aid, True, "looks fine", decided_by="human-operator")
        q._rewrite(lambda rs: [
            dict(r, policy_context={"domain_allowlisted": False})
            if r["id"] == aid else r for r in rs])
        done = ex.execute_approved()
        self.assertEqual(done, [])
        rec = q.get(aid)
        self.assertFalse(rec.get("executed"))
        refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("event") == "approval_execution_refused"]
        self.assertTrue(any(
            e.get("flag") == "approval_integrity_violation"
            and e.get("approval_id") == aid for e in refusals))

    def test_identity_relabel_breaks_digest(self):
        """Relabeling the stamped identity between queue and decide is
        caught by the F43 full-payload MAC."""
        ctx = make_run()
        q = ctx["approvals"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send(q, caller)
        q._rewrite(lambda rs: [
            dict(r, agent_id="admin", role="admin")
            if r["id"] == aid else r for r in rs])
        with self.assertRaises(ValueError):
            q.decide(aid, True, "looks fine", decided_by="human-operator")
        self.assertEqual(q.get(aid)["status"], "pending")


# ---------------------------------------------------------------------------
# F44 — lock deletion/replacement mid-sweep is a loud refusal.
# ---------------------------------------------------------------------------

class TestF44QueueLockInvalidation(unittest.TestCase):
    def _delete_lock_mid_acquisition(self):
        """Patch fcntl.flock so the lock FILE is deleted between open()
        and the lock being granted — the wave-12 race."""
        lock_deleted = []
        q = self._q
        lock_path = q._lock_path()
        real_flock = fcntl.flock

        def evil_flock(fd, op):
            if op & fcntl.LOCK_EX and op & fcntl.LOCK_NB:
                try:
                    os.unlink(lock_path)
                    lock_deleted.append(True)
                except FileNotFoundError:
                    pass
            return real_flock(fd, op)

        return mock.patch("fcntl.flock", evil_flock), lock_deleted

    def test_deleted_lock_raises_invalidated(self):
        ctx = make_run()
        self._q = ctx["approvals"]
        patcher, deleted = self._delete_lock_mid_acquisition()
        with patcher, self.assertRaises(QueueLockInvalidatedError):
            with self._q._queue_locked(timeout=5):
                pass  # pragma: no cover
        self.assertTrue(deleted, "the simulated race must delete the file")

    def test_executor_audits_invalidated_lock_distinctly(self):
        ctx = make_run()
        self._q = ctx["approvals"]
        ex = ctx["executor"]
        patcher, _ = self._delete_lock_mid_acquisition()
        with patcher, self.assertRaises(QueueLockInvalidatedError):
            ex.execute_approved()
        refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("event") == "approval_sweep_refused"]
        self.assertTrue(any(e.get("flag") == "queue_lock_invalidated"
                            for e in refusals),
                        "lock invalidation must audit as "
                        "queue_lock_invalidated, not queue_lock_timeout")

    def test_ordinary_timeout_keeps_timeout_flag(self):
        """Control: an ordinary lock timeout still audits
        queue_lock_timeout (the invalidated flag is not a relabel)."""
        ctx = make_run()
        q = ctx["approvals"]
        ex = ctx["executor"]
        holder = open(q._lock_path(), "a")
        try:
            fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(QueueLockError):
                ex.execute_approved()
        finally:
            fcntl.flock(holder.fileno(), fcntl.LOCK_UN)
            holder.close()
        refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("event") == "approval_sweep_refused"]
        self.assertTrue(any(e.get("flag") == "queue_lock_timeout"
                            for e in refusals))


# ---------------------------------------------------------------------------
# F45 — interrupted executions reconcile without auto-execution.
# ---------------------------------------------------------------------------

class TestF45InterruptedReconciliation(unittest.TestCase):
    def _simulate_crash_mid_execution(self, ctx, aid):
        """Simulate a crash between the durable claim and the completion
        marker: the write-ahead ``execution_authorized`` audit exists and
        the record is claimed (executed=True), but no
        ``approved_executed`` was ever written."""
        q, ex = ctx["approvals"], ctx["executor"]
        rec = q.get(aid)
        ctx["log"].append({
            "event": "tool_call",
            "run_id": ex.run_id,
            "agent_id": rec.get("agent_id"),
            "role": rec.get("role"),
            "principal": (rec.get("identity") or {}).get("principal"),
            "tool": rec["tool"],
            "args": rec["args"],
            "decision": "execution_authorized",
            "policy_id": rec.get("policy_id"),
            "approval_id": aid,
            "reason": "Human approval %s authorized execution." % aid,
        })
        q.mark_executed(aid)  # the durable claim, before the "crash"

    def test_interrupted_claim_reconciles_without_auto_execution(self):
        """A crashed execution (authorized + claimed, never completed)
        reconciles the record back to pending — and never executes."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send_ex(ctx)
        q.decide(aid, True, "approved", decided_by="human-operator")
        self._simulate_crash_mid_execution(ctx, aid)
        self.assertEqual(ex.execute_approved(), [],
                         "reconciliation must never auto-execute")
        rec = q.get(aid)
        self.assertEqual(rec["status"], "pending")
        self.assertFalse(rec.get("executed"))
        self.assertIsNone(rec.get("decided_by"))
        self.assertIn("execution_interrupted_warning", rec)
        self.assertIn("MAY ALREADY HAVE HAPPENED",
                      rec["execution_interrupted_warning"])
        # The re-MACed pending record verifies.
        self.assertTrue(approval_digest_ok(rec))
        events = [e.get("event") for e in
                  read_entries(ctx["run_dir"] / "actions.jsonl")]
        self.assertIn("approval_execution_interrupted", events)

    def test_reconcile_does_not_realert_on_repeat_sweep(self):
        """The authorization-seq pin stops repeat alerts on every sweep,
        but a NEW interruption reconciles again."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send_ex(ctx)
        q.decide(aid, True, "approved", decided_by="human-operator")
        self._simulate_crash_mid_execution(ctx, aid)
        ex.execute_approved()
        ex.execute_approved()
        interrupted = [e for e in
                       read_entries(ctx["run_dir"] / "actions.jsonl")
                       if e.get("event") == "approval_execution_interrupted"]
        self.assertEqual(len(interrupted), 1,
                         "one interruption reconciles exactly once")

    def test_completed_execution_not_reconciled(self):
        """Control: a genuinely completed execution is left alone."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        aid = _queued_send_ex(ctx)
        q.decide(aid, True, "approved", decided_by="human-operator")
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["tool"], "read_file")
        self.assertEqual(ex.execute_approved(), [])
        rec = q.get(aid)
        self.assertTrue(rec.get("executed"))
        events = [e.get("event") for e in
                  read_entries(ctx["run_dir"] / "actions.jsonl")]
        self.assertNotIn("approval_execution_interrupted", events)


# ---------------------------------------------------------------------------
# F46 — campaign establishment needs multi-run continuity.
# ---------------------------------------------------------------------------

class TestF46CampaignEstablishment(unittest.TestCase):
    def _campaign_call(self, ledger_path, principal, run_ctx=None):
        ctx = run_ctx or make_run(ledger_path=ledger_path)
        ex = ctx["executor"]
        ident = ex.mint_identity("agent", "researcher", principal)
        return ex.call(ident, "api_call",
                       endpoint="https://shard0.collector.synthetic.local/x",
                       params={"blob": "A1B2C3D4E5F6G7H8!", "seq": 1})

    def test_same_run_priming_does_not_establish(self):
        """Five fragment-shaped calls from one principal in ONE run do
        not establish it — the cross-principal quorum needs distinct
        run IDs, so a second principal's matching shape executes."""
        with tempfile.TemporaryDirectory(prefix="govr46-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            ctx = make_run(ledger_path=led)
            ex = ctx["executor"]
            ident = ex.mint_identity("agent", "researcher", "primer")
            for _ in range(5):
                ex.call(ident, "api_call",
                        endpoint="https://shard0.collector.synthetic.local/x",
                        params={"blob": "A1B2C3D4E5F6G7H8!", "seq": 1})
            # A different principal with the same shape is NOT queued —
            # the primer was never established (single run ID).
            r = self._campaign_call(led, "fresh")
            self.assertEqual(r["status"], "executed")

    def test_multi_run_campaign_still_fires(self):
        """Three principals each emitting across two distinct runs are
        established; the quorum fires on the campaign shape."""
        with tempfile.TemporaryDirectory(prefix="govr46-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            st = []
            for _ in range(2):
                for p in ("c1", "c2", "c3"):
                    r = self._campaign_call(led, p)
                    st.append(r["status"])
            self.assertIn("queued", st,
                          "multi-run established campaign must queue: %r"
                          % (st,))

    def test_registry_mode_establishes_registered_principals(self):
        """In registry mode, registered principals count as
        deployment-established even on first sight."""
        with tempfile.TemporaryDirectory(prefix="govr46-") as td:
            led = str(Path(td) / "egress_ledger.jsonl")
            reg = PrincipalRegistry({"r1", "r2", "r3",
                                     # make_run mints these standard agents
                                     # at construction.
                                     "customer-org", "dev-org",
                                     "research-org"})
            st = []
            for p in ("r1", "r2", "r3"):
                ctx = make_run(ledger_path=led,
                               principal_registry=reg)
                ex = ctx["executor"]
                ident = ex.mint_identity("agent", "researcher", p)
                r = ex.call(ident, "api_call",
                            endpoint="https://shard0.collector.synthetic.local/x",
                            params={"blob": "A1B2C3D4E5F6G7H8!", "seq": 1})
                st.append(r["status"])
            self.assertIn("queued", st,
                          "registered principals must be treated as "
                          "established: %r" % (st,))


# ---------------------------------------------------------------------------
# F47 — cross-privilege smuggling refused at execution.
# ---------------------------------------------------------------------------

class TestF47RoleAllowlistExecution(unittest.TestCase):
    def test_cross_privilege_smuggling_refused(self):
        """A researcher (no write_file) queues write_file DIRECTLY via
        queue() — bypassing call()'s role gate — and gets it approved.
        Execution refuses with role_allowlist_violation."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("lowpriv", "researcher", "org")
        aid = q.queue(
            {"tool": "write_file", "args": {"path": "out.txt",
                                            "content": "pwned"},
             "redactions": [], "agent_justification": "test"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="write out.txt",
            policy_hash=ex.policy.policy_hash,
            caller_identity=caller)
        q.decide(aid, True, "looks benign", decided_by="human-operator")
        self.assertEqual(ex.execute_approved(), [])
        rec = q.get(aid)
        self.assertFalse(rec.get("executed"))
        refusals = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                    if e.get("event") == "approval_execution_refused"]
        self.assertTrue(any(e.get("flag") == "role_allowlist_violation"
                            and e.get("policy_id") == "role-allowlist"
                            and e.get("approval_id") == aid
                            for e in refusals))

    def test_same_role_approval_executes(self):
        """Control: a coder (write_file allowed) approval executes."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        caller = ctx["mint_identity"]("dev", "coder", "org")
        aid = q.queue(
            {"tool": "write_file", "args": {"path": "out.txt",
                                            "content": "hello"},
             "redactions": [], "agent_justification": "test"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="write out.txt",
            policy_hash=ex.policy.policy_hash,
            caller_identity=caller)
        q.decide(aid, True, "approved", decided_by="human-operator")
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["tool"], "write_file")
        self.assertTrue(q.get(aid).get("executed"))


# ---------------------------------------------------------------------------
# F48 — policy load/pin audit.
# ---------------------------------------------------------------------------

class TestF48PolicyPin(unittest.TestCase):
    def _policy_hash(self):
        return PolicyEngine(str(DEFAULT_POLICY)).policy_hash

    def test_matching_pin_constructs_and_audits(self):
        os.environ["GOV_POLICY_HASH"] = self._policy_hash()
        try:
            ctx = make_run()
        finally:
            os.environ.pop("GOV_POLICY_HASH", None)
        entries = read_entries(ctx["run_dir"] / "actions.jsonl")
        loaded = [e for e in entries if e["event"] == "policy_loaded"]
        self.assertTrue(loaded, "policy_loaded must always be audited")
        self.assertTrue(loaded[0]["pinned"])
        self.assertEqual(loaded[0]["policy_hash"], self._policy_hash())
        self.assertFalse(any(e["event"] == "policy_pin_mismatch"
                             for e in entries))
        self.assertFalse(any(e["event"] == "policy_pin_absent"
                             for e in entries))

    def test_pin_mismatch_refuses_construction_and_audits(self):
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        os.environ["GOV_POLICY_HASH"] = "deadbeef-wrong-pin"
        try:
            with tempfile.TemporaryDirectory(prefix="govr11pin-") as td:
                run_dir = Path(td) / "run"
                run_dir.mkdir()
                log = ActionLog(run_dir / "actions.jsonl")
                q = ApprovalQueue(run_dir, log)
                policy = PolicyEngine(str(DEFAULT_POLICY))
                with self.assertRaises(PolicyPinMismatchError):
                    ToolExecutor(run_dir, policy, log, q,
                                 # Wave-85: the pin machinery is the
                                 # subject here; the raw pipeline is
                                 # declared, not silent.
                                 ungoverned_ack=(
                                     "F48 policy-pin test: exercises the "
                                     "pin-refusal path; raw pipeline by "
                                     "design"))
                events = [e["event"] for e in
                          read_entries(run_dir / "actions.jsonl")]
                self.assertIn("policy_loaded", events)
                self.assertIn("policy_pin_mismatch", events)
        finally:
            os.environ.pop("GOV_POLICY_HASH", None)

    def test_absent_pin_warns_explicitly(self):
        old = os.environ.pop("GOV_POLICY_HASH", None)
        try:
            ctx = make_run()
        finally:
            if old is not None:
                os.environ["GOV_POLICY_HASH"] = old
        entries = read_entries(ctx["run_dir"] / "actions.jsonl")
        absent = [e for e in entries if e["event"] == "policy_pin_absent"]
        self.assertTrue(absent, "an unpinned policy must warn loudly")
        self.assertIn("NOT pinned", absent[0]["reason"])


# ---------------------------------------------------------------------------
# F49 — human-provisioned break-glass tickets.
# ---------------------------------------------------------------------------

class TestF49BreakGlassTickets(unittest.TestCase):
    def _run_with_ticket(self, ticket_id="T-1", operator="ops-lead",
                         reviewer="duty-reviewer"):
        ctx = make_run(break_glass_tickets=[(ticket_id, operator,
                                             reviewer)])
        ctx["operator"] = ctx["mint_identity"]("op-1", "operator",
                                               operator)
        return ctx

    def _pending(self, ctx):
        q = ctx["approvals"]
        caller = ctx["mint_identity"]("a1", "researcher", "org")
        return q.queue(
            {"tool": "api_call",
             "args": {"endpoint": "https://y.synthetic.local/"},
             "redactions": [], "agent_justification": "test"},
            SimpleNamespace(policy_id="p", reason="r", flag=None),
            preview="test",
            caller_identity=caller)

    def test_break_glass_without_ticket_refused(self):
        ctx = make_run()
        ctx["operator"] = ctx["mint_identity"]("op-1", "operator",
                                              "ops-lead")
        aid = self._pending(ctx)
        with self.assertRaises(ValueError):
            ctx["approvals"].break_glass(aid, "incident",
                                         operator_identity=ctx["operator"])
        self.assertEqual(ctx["approvals"].get(aid)["status"], "pending")

    def test_break_glass_with_valid_ticket_approves(self):
        ctx = self._run_with_ticket()
        aid = self._pending(ctx)
        record, ticket = ctx["approvals"].break_glass(
            aid, "incident", operator_identity=ctx["operator"],
            ticket_id="T-1")
        self.assertEqual(record["status"], "approved")
        self.assertTrue(record["break_glass"])
        # The audit log binds the HUMAN-PROVISIONED ticket id.
        bg = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
              if e.get("event") == "approval_break_glass"]
        self.assertTrue(any(e.get("provision_ticket_id") == "T-1"
                            for e in bg))

    def test_ticket_bound_to_operator_principal(self):
        """A ticket provisioned for ops-lead cannot be used by mallory."""
        ctx = self._run_with_ticket(operator="ops-lead")
        aid = self._pending(ctx)
        mallory = ctx["mint_identity"]("mallory", "operator", "mallory")
        with self.assertRaises(ValueError):
            ctx["approvals"].break_glass(aid, "incident",
                                         operator_identity=mallory,
                                         ticket_id="T-1")
        self.assertEqual(ctx["approvals"].get(aid)["status"], "pending")

    def test_used_ticket_cannot_be_reused(self):
        ctx = self._run_with_ticket()
        q = ctx["approvals"]
        aid1 = self._pending(ctx)
        _, ticket = q.break_glass(aid1, "incident",
                                  operator_identity=ctx["operator"],
                                  ticket_id="T-1")
        # Resolve the post-review so stacking is not the refusal reason.
        q.resolve_review(ticket["ticket_id"], "reviewed",
                         reviewer_identity=ctx["mint_identity"](
                             "rev-1", "reviewer", "duty-reviewer"))
        aid2 = self._pending(ctx)
        with self.assertRaises(ValueError):
            q.break_glass(aid2, "incident",
                          operator_identity=ctx["operator"],
                          ticket_id="T-1")
        self.assertEqual(q.get(aid2)["status"], "pending")

    def test_mid_run_provisioning_ignored(self):
        """A ticket dropped into the store AFTER run start is not in the
        snapshot — the run seals its ticket set at construction."""
        ctx = self._run_with_ticket()
        provision_break_glass_ticket(
            ctx["run_dir"] / BREAK_GLASS_TICKET_FILENAME,
            "T-LATE", "ops-lead", "duty-reviewer")
        aid = self._pending(ctx)
        with self.assertRaises(ValueError):
            ctx["approvals"].break_glass(aid, "incident",
                                         operator_identity=ctx["operator"],
                                         ticket_id="T-LATE")
        self.assertEqual(ctx["approvals"].get(aid)["status"], "pending")

    def test_provisioning_rejects_operator_reviewer_overlap(self):
        with tempfile.TemporaryDirectory(prefix="govr11bg-") as td:
            store = Path(td) / BREAK_GLASS_TICKET_FILENAME
            with self.assertRaises(ValueError):
                provision_break_glass_ticket(store, "T-X", "same", "same")

    def test_provisioning_rejects_duplicate_ticket_id(self):
        with tempfile.TemporaryDirectory(prefix="govr11bg-") as td:
            store = Path(td) / BREAK_GLASS_TICKET_FILENAME
            provision_break_glass_ticket(store, "T-1", "op", "rev")
            with self.assertRaises(ValueError):
                provision_break_glass_ticket(store, "T-1", "op2", "rev2")

    def test_concurrent_ticket_use_single_winner(self):
        """Two threads racing break_glass with the same ticket_id: exactly
        one succeeds, the other is refused (F49 single-use)."""
        import threading
        ctx = self._run_with_ticket()
        q = ctx["approvals"]
        aid1 = self._pending(ctx)
        aid2 = self._pending(ctx)
        results = []
        barrier = threading.Barrier(2)

        def _try(aid):
            barrier.wait()
            try:
                q.break_glass(aid, "incident",
                              operator_identity=ctx["operator"],
                              ticket_id="T-1")
                results.append("ok")
            except ValueError:
                results.append("refused")

        t1 = threading.Thread(target=_try, args=(aid1,))
        t2 = threading.Thread(target=_try, args=(aid2,))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(sorted(results), ["ok", "refused"],
                         "exactly one concurrent break_glass must win")

    def test_wrong_reviewer_cannot_resolve(self):
        """Post-review resolution requires the PROVISIONED reviewer
        principal — a different minted reviewer is refused."""
        ctx = self._run_with_ticket()
        q = ctx["approvals"]
        aid = self._pending(ctx)
        _, ticket = q.break_glass(aid, "incident",
                                  operator_identity=ctx["operator"],
                                  ticket_id="T-1")
        wrong_reviewer = ctx["mint_identity"]("rev-9", "reviewer",
                                              "someone-else")
        with self.assertRaises(ValueError):
            q.resolve_review(ticket["ticket_id"], "reviewed",
                             reviewer_identity=wrong_reviewer)
        # The ticket is still pending — the wrong reviewer did not close it.
        pending = [t for t in q.pending_reviews()
                   if t["ticket_id"] == ticket["ticket_id"]]
        self.assertEqual(len(pending), 1)
