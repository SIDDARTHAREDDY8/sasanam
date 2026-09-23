"""Wave-88 (F135): the execution boundary re-validates the three-token
delegation — revocation and expiry are re-checked at execute_approved()
time, not just at call()/queue time.

Closure tests for F135 (MEDIUM): execute_approved() executed approved
actions after the three-token delegation was revoked or expired, because
the sweep's TOCTOU re-validations never re-ran the delegation gate.
The fix re-runs enforce_tool_call per approved record (when the executor
has a bound DelegationContext) and refuses fail-closed + audited.

Deterministic: the expiry test freezes the delegation-token clock
(mocked _now_dt) at t0 for issuance/queue/approval and advances 600s —
past the 300s CLOCK_SKEW_S acceptance window — for the sweep.
"""

import datetime
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evals.w88_identity_probes import _governed_run  # noqa: E402
from gov import delegation_tokens as _dt  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import read_entries  # noqa: E402


def _queue_and_approve(g):
    ex = g["executor"]
    res = ex.call(g["identity"], "send_email", to="x@y.z",
                  subject="s", body="b")
    assert res["status"] == "queued", res
    aid = res["approval_id"]
    g["approvals"].decide(aid, True, reason="looks fine",
                          decided_by="human-operator")
    return ex, aid


def _refusal_events(g, aid):
    return [e for e in read_entries(g["run_dir"] / "actions.jsonl")
            if e.get("event") == "approval_execution_refused"
            and e.get("approval_id") == aid]


class TestF135ExecutionBoundaryDelegation(unittest.TestCase):
    def test_revoked_delegation_refused_at_execution(self):
        g = _governed_run()
        try:
            ex, aid = _queue_and_approve(g)
            g["ledger"].revoke(g["tokens"][2])
            done = ex.execute_approved()
            self.assertEqual(done, [])
            rec = [r for r in g["approvals"].all()
                   if r["id"] == aid][0]
            self.assertIn("revoked", rec.get("execution_refused_reason",
                                             ""))
            events = _refusal_events(g, aid)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["flag"],
                             "delegation_revoked_at_execution")
            self.assertEqual(events[0]["decision"], "refused")
        finally:
            g["td"].cleanup()

    def test_expired_delegation_refused_at_execution(self):
        t0 = datetime.datetime.now(
            datetime.timezone.utc).replace(microsecond=0)
        with mock.patch.object(_dt, "_now_dt", return_value=t0):
            g = _governed_run(ttl_s=1)
        try:
            with mock.patch.object(_dt, "_now_dt", return_value=t0):
                ex, aid = _queue_and_approve(g)
            future = t0 + datetime.timedelta(seconds=600)
            with mock.patch.object(_dt, "_now_dt", return_value=future):
                done = ex.execute_approved()
            self.assertEqual(done, [])
            rec = [r for r in g["approvals"].all()
                   if r["id"] == aid][0]
            self.assertIn("expired", rec.get("execution_refused_reason",
                                             ""))
            events = _refusal_events(g, aid)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["flag"],
                             "delegation_expired_at_execution")
        finally:
            g["td"].cleanup()

    def test_valid_delegation_still_executes(self):
        # No-regression: a still-valid delegation + human approval
        # executes exactly as before the fix.
        g = _governed_run()
        try:
            ex, aid = _queue_and_approve(g)
            done = ex.execute_approved()
            self.assertEqual(len(done), 1)
            self.assertEqual(done[0]["tool"], "send_email")
            self.assertEqual(_refusal_events(g, aid), [])
        finally:
            g["td"].cleanup()

    def test_ungoverned_executor_keeps_legacy_behavior(self):
        # Executors without a bound DelegationContext (legacy/harness
        # pipeline) have no gate to re-run: execution behavior unchanged.
        g = _governed_run()
        try:
            legacy_ex = ToolExecutor(
                g["run_dir"], g["engine"], g["log"], g["approvals"],
                policy_store=None, delegation_context=None,
                session_identity=("agent-a", "scout", "alice"),
                ungoverned_ack="w88 F135 test: legacy executor keeps "
                               "pre-fix execution behavior")
            res = legacy_ex.call(legacy_ex._session_identity, "send_email",
                                 to="x@y.z", subject="s", body="b")
            self.assertEqual(res["status"], "queued")
            aid = res["approval_id"]
            g["approvals"].decide(aid, True, reason="ok",
                                  decided_by="human-operator")
            done = legacy_ex.execute_approved()
            self.assertEqual(len(done), 1)
        finally:
            g["td"].cleanup()

    def test_revocation_checked_across_executor_rotation(self):
        # Executor rotation (a fresh executor per sweep, same run dir):
        # queue + approve with executor 1, revoke, then sweep with a
        # freshly constructed executor 2. The re-validation must still
        # see the revocation through the shared ledger.
        g = _governed_run()
        try:
            _ex1, aid = _queue_and_approve(g)
            g["ledger"].revoke(g["tokens"][2])
            toks = g["tokens"]
            ctx2 = _dt.DelegationContext(
                user_token=toks[0], agent_token=toks[1],
                delegation_token=toks[2], parent_chain=[],
                trust=g["keys"].trust(),
                session_id=g["run_dir"].name).bind()
            ex2 = ToolExecutor(
                g["run_dir"], g["engine"], g["log"],
                ApprovalQueue(g["run_dir"], g["log"]),
                policy_store=g["policy_store"],
                delegation_context=ctx2,
                revocation_checker=g["ledger"],
                session_identity=("agent-a", "scout", "alice"))
            done = ex2.execute_approved()
            self.assertEqual(done, [])
            events = _refusal_events(g, aid)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["flag"],
                             "delegation_revoked_at_execution")
        finally:
            g["td"].cleanup()


if __name__ == "__main__":
    unittest.main()
