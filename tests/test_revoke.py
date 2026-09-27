"""Revoke-after-approve unit tests (wave-131, row-7 second half).

Covers the public revocation seam (``ApprovalQueue.revoke`` /
``gov.revoke.revoke_approval``) and the executor's execution-boundary
intent re-validation: a countermand arriving between human approval
and the sweep auto-revokes the approval and refuses execution with
``approval_intent_changed``.

Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
GOV_DEPLOYMENT_MODE=staging. No env scrubbing here (tearDown never
touches key env vars).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import make_run  # noqa: E402
from gov import revoke as revoke_mod  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402


def _queue_delete(q, ex, ident, justification="cleaning temp files"):
    """Queue a delete_file inside the run sandbox (policy-allowed)."""
    target = str(ex.sandbox / "x.txt")
    return q.queue(
        {"tool": "delete_file", "args": {"path": target},
         "identity": ident.as_dict(),
         "agent_justification": justification, "redactions": []},
        PolicyDecision("require_approval", "revoke tests",
                       policy_id="test", flag="test_revoke"),
        "agent_direct", "delete preview",
        policy_hash=ex.policy.policy_hash,
        caller_identity=ident)


def _approved_delete(ctx, justification="cleaning temp files"):
    q, ex = ctx["approvals"], ctx["executor"]
    ident = ctx["mint_identity"]("a1", "coder", "org")
    aid = _queue_delete(q, ex, ident, justification)
    q.decide(aid, True, "human says ok", decided_by="human-operator")
    return aid, ident


class RevokeSeamTest(unittest.TestCase):
    def test_revoke_by_granter_succeeds(self):
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        rec = q.revoke(aid, "no longer needed", "human-operator")
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], "human-operator")
        self.assertEqual(rec["revoked_reason"], "no longer needed")
        self.assertIn("revoked_at", rec)

    def test_revoke_unknown_id_fails_closed(self):
        ctx = make_run()
        q = ctx["approvals"]
        with self.assertRaises(ValueError):
            q.revoke("no-such-id", "x", "human-operator")

    def test_revoke_executed_fails_closed(self):
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        q.mark_executed(aid)
        with self.assertRaises(ValueError):
            q.revoke(aid, "too late", "human-operator")
        # The execution stands; the record is executed, not revoked.
        self.assertTrue(q.get(aid)["executed"])
        self.assertNotEqual(q.get(aid)["status"], "revoked")

    def test_revoke_by_stranger_refused(self):
        """Only the granter (or the intent system) may revoke: a forged
        revocation by anyone else is refused and audited."""
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        with self.assertRaises(ValueError):
            q.revoke(aid, "forged", "agent-1")
        # The approval survives the forgery attempt untouched.
        rec = q.get(aid)
        self.assertEqual(rec["status"], "approved")
        self.assertIsNone(rec.get("revoked_by"))

    def test_revoke_by_intent_system_succeeds(self):
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        rec = q.revoke(aid, "intent changed", revoke_mod.INTENT_SYSTEM)
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], revoke_mod.INTENT_SYSTEM)

    def test_double_revoke_refused(self):
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        q.revoke(aid, "first", "human-operator")
        with self.assertRaises(ValueError):
            q.revoke(aid, "second", "human-operator")

    def test_revoke_pending_record(self):
        """A not-yet-decided approval can be revoked too: the requester
        may withdraw its own pending item (it becomes undecidable —
        decide() only accepts pending records)."""
        ctx = make_run()
        q = ctx["approvals"]
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("a1", "coder", "org")
        aid = _queue_delete(q, ex, ident)
        q.revoke(aid, "withdrawn", "a1")
        with self.assertRaises(ValueError):
            q.decide(aid, True, "too late", decided_by="human-operator")

    def test_revoke_pending_by_stranger_refused(self):
        """Nobody else may revoke a pending approval — not another
        agent, not another human. The operator's path is decide()."""
        ctx = make_run()
        q = ctx["approvals"]
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("a1", "coder", "org")
        aid = _queue_delete(q, ex, ident)
        with self.assertRaises(ValueError):
            q.revoke(aid, "forged", "human-operator")
        self.assertEqual(q.get(aid)["status"], "pending")

    def test_revoked_record_cannot_be_decided(self):
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        q.revoke(aid, "changed mind", "human-operator")
        with self.assertRaises(ValueError):
            q.decide(aid, False, "reject after revoke",
                     decided_by="human-operator")

    def test_mark_executed_refuses_revoked(self):
        """Belt-and-braces: even a direct mark_executed on a revoked
        record fails closed — revocation is terminal."""
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        q.revoke(aid, "revoked", "human-operator")
        with self.assertRaises(ValueError):
            q.mark_executed(aid)
        self.assertIsNot(q.get(aid).get("executed"), True)

    def test_revoked_never_executes_in_sweep(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid, _ident = _approved_delete(ctx)
        q.revoke(aid, "revoked before sweep", "human-operator")
        done = ex.execute_approved()
        self.assertEqual(done, [])
        self.assertIsNot(q.get(aid).get("executed"), True)

    def test_revoke_audited_loud(self):
        from gov.log import read_entries
        ctx = make_run()
        q = ctx["approvals"]
        aid, _ident = _approved_delete(ctx)
        q.revoke(aid, "audit me", "human-operator")
        evts = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
                if e.get("event") == "approval_revoked"]
        self.assertEqual(len(evts), 1)
        self.assertEqual(evts[0]["approval_id"], aid)
        self.assertEqual(evts[0]["revoked_by"], "human-operator")


class IntentRevalidationTest(unittest.TestCase):
    def _approved_with_context(self, ctx, turns, justification):
        """Queue + approve a delete under the given intent context,
        stamping the queue-time judge verdict like the real call path."""
        q, ex = ctx["approvals"], ctx["executor"]
        ident = ctx["mint_identity"]("a1", "coder", "org")
        ex.set_intent_context(turns)
        verdict = ex._intent_slice_verdict(
            "delete_file",
            {"path": str(ex.sandbox / "x.txt")},
            justification, ident)
        aid = q.queue(
            {"tool": "delete_file",
             "args": {"path": str(ex.sandbox / "x.txt")},
             "identity": ident.as_dict(),
             "agent_justification": justification, "redactions": []},
            PolicyDecision("require_approval", "revoke tests",
                           policy_id="test", flag="test_revoke"),
            "agent_direct", "delete preview",
            policy_hash=ex.policy.policy_hash,
            caller_identity=ident,
            intent_slice_verdict=verdict)
        q.decide(aid, True, "human says ok", decided_by="human-operator")
        return aid

    def test_countermand_after_approval_auto_revokes_and_refuses(self):
        from gov.log import read_entries
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved_with_context(
            ctx, ["Delete the temp files in the scratch dir."],
            "cleaning temp files per your instruction")
        # The countermand arrives AFTER the human approved.
        ex.set_intent_context(
            ["Delete the temp files in the scratch dir.",
             "Stop -- don't delete anything in the scratch dir."])
        done = ex.execute_approved()
        self.assertEqual(done, [])
        rec = q.get(aid)
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], revoke_mod.INTENT_SYSTEM)
        self.assertIsNot(rec.get("executed"), True)
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in evts
                   if e.get("event") == "approval_execution_refused"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_intent_changed")
        revoked = [e for e in evts
                   if e.get("event") == "approval_revoked"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(revoked), 1)

    def test_no_intent_change_executes(self):
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved_with_context(
            ctx, ["Delete the temp files in the scratch dir."],
            "cleaning temp files per your instruction")
        # Same intent at execution time: the sweep executes.
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid)["executed"])

    def test_human_override_of_queue_time_stale_flag_stands(self):
        """The human approved DESPITE the queue-time stale flag; with no
        new intent information the override stands and the sweep
        executes (no auto-revoke)."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        turns = ["Delete the temp files in the scratch dir.",
                 "Stop -- don't delete anything in the scratch dir."]
        aid = self._approved_with_context(
            ctx, turns, "cleaning temp files per your instruction")
        rec = q.get(aid)
        self.assertTrue((rec.get("intent_slice") or {}).get("flagged"))
        # Intent unchanged since approval: the human's override stands.
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid)["executed"])

    def test_inert_without_intent_context(self):
        """No intent context anywhere: the re-validation is inert and
        the sweep behaves exactly as before."""
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid, _ident = _approved_delete(ctx)
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid)["executed"])


if __name__ == "__main__":
    unittest.main()
