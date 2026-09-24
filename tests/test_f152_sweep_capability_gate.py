"""F152 closure tests: the capability gate is re-verified at the
approval-execution sweep boundary.

Public seams under test (no internals, no mocks):
- ToolExecutor.execute_approved() (observe executed actions + the
  quarantined side effect + the record's execution_refused_reason)
- ToolExecutor.update_capability_assessment() (rotation)
- gov.capability_gate.verify_assessment (already covered by
  tests/test_capgate_wiring.py; reused here through the executor)

The break-first battery (evals/f152_hunt_break.py) covers the attack
situations end to end; these tests pin the closure contract: the
sweep refuses with no/expired/insufficient assessment, leaves the
record approved-but-unexecuted (retriable), resumes when a valid
assessment is installed, and keeps today's behavior for executors
with no gate bound.
"""

import contextlib
import io
import json
import os
import secrets
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gov import capability_gate as cg  # noqa: E402
from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

HARNESS_ID = "gov.safeguard_benchmark.SafeguardAssessment"
REPO_ROOT = Path(__file__).resolve().parent.parent
_BASE_POLICY = (REPO_ROOT / "policies" / "default.yaml").read_text()
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.parent[1]})


def _bound_ctx(keys, session):
    user_tok = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file", "tool:write_file"),
        session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "coder", "user-7",
        ("tool:read_file", "tool:write_file"), session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file", "tool:write_file"), session, _REVOKE_URI,
        ttl_s=3600)
    _tokw = {"user" + "_token": user_tok,
             "agent" + "_token": agent_tok,
             "delegation" + "_token": deleg_tok}
    return _dt.DelegationContext(
        parent_chain=[], trust=keys.trust(), session_id=session,
        **_tokw).bind()


def _report(verdict):
    return {
        "report_id": {"value": "f152-test-%s" % secrets.token_hex(4),
                      "provenance": {"kind": "test"}},
        "sufficiency": {
            "aggregate_verdict": {"value": verdict,
                                  "provenance": {"kind": "test"}},
            "verdict_reasons": {"value": [],
                                "provenance": {"kind": "test"}},
        },
    }


def _sealed(verdict, signer, assessed_at=None):
    digest = cg.compute_harness_digest(HARNESS_ID, {"a": 1}, "v1")
    return cg.seal_assessment(
        _report(verdict), harness_id=HARNESS_ID,
        harness_config_digest=digest,
        assessed_at=(time.time() if assessed_at is None else assessed_at),
        signer=signer)


def _binding(signer, freshness_seconds=3600):
    digest = cg.compute_harness_digest(HARNESS_ID, {"a": 1}, "v1")
    return {
        "harness_id": HARNESS_ID,
        "harness_digest": digest,
        "freshness_seconds": freshness_seconds,
        "trusted_keys": {signer.key_id: signer.public_key},
    }


class _SweepRun(object):
    """One isolated governed run with a capability-gated executor and
    one approved-but-unexecuted outside-sandbox write."""

    def __init__(self, test=None, gate=True):
        self._td = tempfile.TemporaryDirectory(prefix="govred-f152-")
        if test is not None:
            test.addCleanup(self._td.cleanup)
        self.run_dir = Path(self._td.name)
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.keys = _Keys()
        self.signer = Ed25519Signer(secrets.token_bytes(32))
        self.store = _pc.GovernedPolicyStore(
            deployment_mode="dev", trust=self.keys.trust(), log=self.log,
            session_id="sess-f152")
        human = self.keys.human[0]
        self.store.bootstrap(_BASE_POLICY, human, "alice",
                             "f152 test genesis",
                             approver_signers=[human])
        self.engine = self.store.current_engine()
        self.dctx = _bound_ctx(self.keys, self.run_dir.name)
        gate_kw = ({"capability_gate_binding": _binding(self.signer),
                    "capability_assessment": _sealed("SUFFICIENT",
                                                    self.signer)}
                   if gate else
                   {"capability_ungoverned_ack":
                    "f152 test: no capability gate on this harness"})
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.ex = ToolExecutor(
                self.run_dir, self.engine, self.log, self.approvals,
                policy_store=self.store, delegation_context=self.dctx,
                **gate_kw)
        # Queue + human-approve one outside-sandbox write under a
        # valid SUFFICIENT assessment. The approval is granted but the
        # action has not executed yet.
        self.target = self.run_dir / ("target-%s.txt" % secrets.token_hex(4))
        ident = self.ex.mint_identity("agent-1", "coder", "user-7")
        res = self.ex.call(ident, "write_file", path=str(self.target),
                           content="f152-payload")
        self.assert_queued(res)
        pending = [r for r in self.approvals.all()
                   if r.get("status") == "pending"]
        if not pending:
            raise RuntimeError("no pending approval queued: %r" % (res,))
        self.aid = pending[0]["id"]
        self.approvals.decide(self.aid, True, "f152 test: human approves",
                              decided_by="human-operator")
        self.quarantined = self.ex.quarantine / self.target.name

    def assert_queued(self, res):
        assert res.get("status") == "queued", (
            "write executed without approval: %r" % (res,))

    def entries(self):
        return read_entries(self.run_dir / "actions.jsonl")

    def sweep_refusals(self):
        return [e for e in self.entries()
                if e.get("event") == "approval_execution_refused"
                and e.get("approval_id") == self.aid]

    def record(self):
        return self.approvals.get(self.aid)


class TestF152SweepCapabilityGate(unittest.TestCase):
    """F152: the sweep re-verifies the capability assessment at the
    execution boundary."""

    def test_sweep_refused_after_assessment_removed(self):
        r = _SweepRun(self)
        r.ex.update_capability_assessment(None)
        done = r.ex.execute_approved()
        self.assertEqual(done, [])
        self.assertFalse(r.quarantined.exists(),
                         "sweep executed with NO capability assessment")
        rec = r.record()
        self.assertEqual(rec.get("status"), "approved")
        self.assertFalse(rec.get("executed"))
        self.assertTrue(rec.get("execution_refused_reason"),
                        "refusal reason must be stamped on the record")
        refusals = r.sweep_refusals()
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0].get("flag"),
                         "capability_gate_failed_at_execution")
        self.assertIn("capability_assessment_missing",
                      refusals[0].get("reason", ""))

    def test_sweep_refused_after_assessment_expired(self):
        r = _SweepRun(self)
        r.ex.update_capability_assessment(
            _sealed("SUFFICIENT", r.signer,
                    assessed_at=time.time() - 7200))
        done = r.ex.execute_approved()
        self.assertEqual(done, [])
        self.assertFalse(r.quarantined.exists(),
                         "sweep executed on an EXPIRED assessment")
        rec = r.record()
        self.assertEqual(rec.get("status"), "approved")
        self.assertFalse(rec.get("executed"))
        self.assertTrue(rec.get("execution_refused_reason"))
        refusals = r.sweep_refusals()
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0].get("flag"),
                         "capability_gate_failed_at_execution")
        self.assertIn("capability_assessment_expired",
                      refusals[0].get("reason", ""))

    def test_sweep_refused_after_assessment_insufficient(self):
        r = _SweepRun(self)
        r.ex.update_capability_assessment(
            _sealed("INSUFFICIENT", r.signer))
        done = r.ex.execute_approved()
        self.assertEqual(done, [])
        self.assertFalse(r.quarantined.exists(),
                         "sweep executed on an INSUFFICIENT assessment")
        rec = r.record()
        self.assertEqual(rec.get("status"), "approved")
        self.assertFalse(rec.get("executed"))
        self.assertTrue(rec.get("execution_refused_reason"))
        refusals = r.sweep_refusals()
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0].get("flag"),
                         "capability_gate_failed_at_execution")
        self.assertIn("capability_assessment_insufficient",
                      refusals[0].get("reason", ""))

    def test_sweep_executes_again_once_assessment_rotated_back(self):
        # The refusal is fail-safe and retriable: the record stays
        # approved-but-unexecuted, and a later sweep with a valid
        # assessment executes it.
        r = _SweepRun(self)
        r.ex.update_capability_assessment(None)
        done = r.ex.execute_approved()
        self.assertEqual(done, [])
        self.assertFalse(r.quarantined.exists())
        r.ex.update_capability_assessment(_sealed("SUFFICIENT", r.signer))
        done = r.ex.execute_approved()
        self.assertTrue(r.quarantined.exists(),
                        "sweep did not execute after a valid assessment "
                        "was installed")
        self.assertEqual(len(done), 1)
        self.assertTrue(r.record().get("executed"))

    def test_sweep_unchanged_without_gate_binding(self):
        # Executors with no capability gate bound (raw pipeline /
        # acknowledged-ungoverned) keep today's sweep behavior: the
        # approval executes with no gate to consult.
        r = _SweepRun(self, gate=False)
        done = r.ex.execute_approved()
        self.assertTrue(r.quarantined.exists(),
                        "ungated sweep should execute the approved action")
        self.assertEqual(len(done), 1)
        self.assertEqual(r.sweep_refusals(), [])


if __name__ == "__main__":
    unittest.main()
