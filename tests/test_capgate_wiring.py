"""Stream-1 closure tests: the capability gate wired to the runtime.

Public seams under test (no internals, no mocks):
- gov.capability_gate.verify_assessment / seal_assessment /
  compute_harness_digest / validate_binding
- ToolExecutor.__init__ (capability_gate_binding /
  capability_assessment / capability_ungoverned_ack)
- ToolExecutor.call / spawn_sub_agent (refuse without a valid
  assessment; the refusal is chained)
- ToolExecutor.update_capability_assessment (rotation)

The break-first battery (evals/capgate_break.py) covers the attack
situations end to end; these tests pin the contract details the
battery does not: spawn-lineage binding, rotation, malformed inputs,
the acknowledged-ungoverned posture, and the raw-pipeline no-op.
"""

import contextlib
import hashlib
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
from gov.policy import PolicyEngine  # noqa: E402
from gov.safeguard_benchmark import DEFAULT_THRESHOLDS, SCHEMA_VERSION  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

HARNESS_ID = "gov.safeguard_benchmark.SafeguardAssessment"
REPO_ROOT = Path(__file__).resolve().parent.parent
_BASE_POLICY = (REPO_ROOT / "policies" / "default.yaml").read_text()
_REVOKE_URI = "https://revoke.example.invalid/deleg"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


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
        keys.idp[0], "user-7", ("tool:read_file", "tool:send_email"),
        session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file", "tool:send_email"), session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI, ttl_s=3600)
    return _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=keys.trust(), session_id=session).bind()


def _report(verdict):
    return {
        "report_id": {"value": "capgate-test-%s" % secrets.token_hex(4),
                      "provenance": {"kind": "test"}},
        "sufficiency": {
            "aggregate_verdict": {"value": verdict,
                                  "provenance": {"kind": "test"}},
            "verdict_reasons": {"value": [], "provenance": {"kind": "test"}},
        },
    }


def _binding(signer, freshness_seconds=3600):
    digest = cg.compute_harness_digest(HARNESS_ID, DEFAULT_THRESHOLDS,
                                       SCHEMA_VERSION)
    return {
        "harness_id": HARNESS_ID,
        "harness_digest": digest,
        "freshness_seconds": freshness_seconds,
        "trusted_keys": {signer.key_id: signer.public_key},
    }


def _sealed(verdict, signer, assessed_at=None):
    digest = cg.compute_harness_digest(HARNESS_ID, DEFAULT_THRESHOLDS,
                                       SCHEMA_VERSION)
    return cg.seal_assessment(
        _report(verdict), harness_id=HARNESS_ID,
        harness_config_digest=digest,
        assessed_at=(time.time() if assessed_at is None else assessed_at),
        signer=signer)


@contextlib.contextmanager
def _quiet():
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        yield buf


class _GovernedRun(object):
    """One isolated governed-looking run (real policy store, real bound
    delegation context, real chained log)."""

    def __init__(self, test=None):
        self._td = tempfile.TemporaryDirectory(prefix="govred-capgtest-")
        if test is not None:
            test.addCleanup(self._td.cleanup)
        self.run_dir = Path(self._td.name)
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.keys = _Keys()
        self.signer = Ed25519Signer(secrets.token_bytes(32))
        self.store = _pc.GovernedPolicyStore(
            deployment_mode="dev", trust=self.keys.trust(), log=self.log,
            session_id="sess-capgtest")
        human = self.keys.human[0]
        self.store.bootstrap(_BASE_POLICY, human, "alice",
                             "capgate test genesis",
                             approver_signers=[human])
        self.engine = self.store.current_engine()
        self.dctx = _bound_ctx(self.keys, self.run_dir.name)
        (self.run_dir / "notes.txt").write_text("capgate test file\n")

    def executor(self, **kw):
        kw.setdefault("policy_store", self.store)
        kw.setdefault("delegation_context", self.dctx)
        with _quiet():
            return ToolExecutor(self.run_dir, self.engine, self.log,
                                self.approvals, **kw)

    def entries(self):
        return read_entries(self.run_dir / "actions.jsonl")

    def call(self, ex):
        ident = ex.mint_identity("agent-1", "scout", "user-7")
        return ex.call(ident, "read_file", path="notes.txt")


# ---------------------------------------------------------------------------
# The gate module: verify_assessment contract
# ---------------------------------------------------------------------------

class TestVerifyAssessment(unittest.TestCase):
    def test_round_trip_sealed_assessment_verifies(self):
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer)
        decision = cg.verify_assessment(_binding(r.signer), a)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["harness_id"], HARNESS_ID)

    def test_missing_assessment_refused(self):
        r = _GovernedRun(self)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), None)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_missing")

    def test_insufficient_verdict_refused(self):
        r = _GovernedRun(self)
        a = _sealed("INSUFFICIENT", r.signer)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_insufficient")

    def test_harness_id_mismatch_refused(self):
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer)
        a["manifest"]["harness_id"] = "some.other.Harness"
        # Re-seal is impossible without the key; the digest check is
        # bypassed here on purpose -- harness_id is checked FIRST.
        # (The seal would also fail; the point is the id mismatch is
        # named.)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause, "harness_id_mismatch")

    def test_stale_config_digest_refused(self):
        r = _GovernedRun(self)
        other = dict(DEFAULT_THRESHOLDS, human_review_delta=999.0)
        digest = cg.compute_harness_digest(HARNESS_ID, other,
                                           SCHEMA_VERSION)
        a = cg.seal_assessment(_report("SUFFICIENT"), harness_id=HARNESS_ID,
                               harness_config_digest=digest,
                               assessed_at=time.time(), signer=r.signer)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause,
                         "harness_config_digest_mismatch")

    def test_expired_assessment_refused(self):
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer,
                    assessed_at=time.time() - 7200)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer, freshness_seconds=3600),
                                 a)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_expired")

    def test_future_dated_assessment_refused(self):
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer,
                    assessed_at=time.time() + 3600)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause,
                         "assessment_from_future")

    def test_tampered_report_refused(self):
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer)
        a["report"]["sufficiency"]["aggregate_verdict"]["value"] = \
            "INSUFFICIENT"
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause,
                         "assessment_report_digest_mismatch")

    def test_forged_sufficient_refused_on_seal(self):
        # The battery's forgery shape, pinned at the unit level: flip
        # the verdict, recompute the report digest (so the digest check
        # passes), keep the genuine seal -- the seal must fail.
        r = _GovernedRun(self)
        a = _sealed("INSUFFICIENT", r.signer)
        report = json.loads(json.dumps(a["report"]))
        report["sufficiency"]["aggregate_verdict"]["value"] = "SUFFICIENT"
        manifest = json.loads(json.dumps(a["manifest"]))
        manifest["export_sha256"] = hashlib.sha256(
            _canonical(report)).hexdigest()
        forged = {"report": report, "manifest": manifest}
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), forged)
        self.assertEqual(cm.exception.refusal_cause,
                         "assessment_signature_invalid")

    def test_untrusted_seal_key_refused(self):
        r = _GovernedRun(self)
        other = Ed25519Signer(secrets.token_bytes(32))
        a = _sealed("SUFFICIENT", other)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause,
                         "assessment_untrusted_key")

    def test_unsealed_manifest_always_refused(self):
        # There is no unsealed mode: the seal is mandatory, so a
        # flipped-verdict + recomputed-digest forgery can never pass.
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer)
        a["manifest"]["signing"] = {"scheme": "none"}
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(_binding(r.signer), a)
        self.assertEqual(cm.exception.refusal_cause, "assessment_unsealed")
        # A binding without trusted_keys is malformed, not "unsealed
        # allowed": the seal can never be optional.
        bad = _binding(r.signer)
        bad["trusted_keys"] = {}
        with self.assertRaises(cg.CapabilityGateBindingError):
            cg.validate_binding(bad)

    def test_unsealed_binding_cannot_be_widened(self):
        # An unknown extra key is tolerated by the binding contract, but
        # a legacy require_sealed=false entry must NOT re-open unsealed
        # mode: unknown keys are ignored, the seal stays mandatory.
        r = _GovernedRun(self)
        a = _sealed("SUFFICIENT", r.signer)
        a["manifest"]["signing"] = {"scheme": "none"}
        b = _binding(r.signer)
        b["require_sealed"] = False  # legacy key: ignored, not honored
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            cg.verify_assessment(b, a)
        self.assertEqual(cm.exception.refusal_cause, "assessment_unsealed")

    def test_malformed_binding_refused(self):
        r = _GovernedRun(self)
        good = _binding(r.signer)
        for bad_key, bad_val in [
                ("harness_digest", "not-a-digest"),
                ("freshness_seconds", 0),
                ("freshness_seconds", -5),
                ("harness_id", ""),
                ("harness_id", None),
                ("trusted_keys", {}),
                ("trusted_keys", ["not", "a", "mapping"])]:
            bad = dict(good, **{bad_key: bad_val})
            with self.assertRaises(cg.CapabilityGateBindingError,
                                   msg=bad_key):
                cg.validate_binding(bad)

    def test_harness_digest_deterministic_and_sensitive(self):
        d1 = cg.compute_harness_digest(HARNESS_ID, DEFAULT_THRESHOLDS,
                                       SCHEMA_VERSION)
        d2 = cg.compute_harness_digest(HARNESS_ID, DEFAULT_THRESHOLDS,
                                       SCHEMA_VERSION)
        self.assertEqual(d1, d2)
        other = dict(DEFAULT_THRESHOLDS, human_review_delta=999.0)
        d3 = cg.compute_harness_digest(HARNESS_ID, other, SCHEMA_VERSION)
        self.assertNotEqual(d1, d3)


# ---------------------------------------------------------------------------
# The executor wiring: construction, call, spawn, rotation
# ---------------------------------------------------------------------------

class TestExecutorWiring(unittest.TestCase):
    def test_no_binding_looks_governed_refused_explicitly(self):
        r = _GovernedRun(self)
        with _quiet():
            with self.assertRaises(cg.CapabilityGateBindingError) as cm:
                r.executor()
        msg = str(cm.exception)
        self.assertIn("capability_gate_binding", msg)
        self.assertIn("capability_ungoverned_ack", msg)
        refused = [e for e in r.entries()
                   if e.get("event") == "capability_gate_unconfigured_refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["refusal_cause"], "no_binding_no_ack")

    def test_call_refused_without_assessment_and_chained(self):
        r = _GovernedRun(self)
        ex = r.executor(capability_gate_binding=_binding(r.signer),
                        capability_assessment=None)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            r.call(ex)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_missing")
        refused = [e for e in r.entries()
                   if e.get("event") == "capability_gate_refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["refusal_cause"],
                         "capability_assessment_missing")
        self.assertEqual(refused[0]["tool"], "read_file")

    def test_call_refused_on_stale_assessment(self):
        r = _GovernedRun(self)
        stale = _sealed("SUFFICIENT", r.signer,
                        assessed_at=time.time() - 7200)
        ex = r.executor(
            capability_gate_binding=_binding(r.signer,
                                             freshness_seconds=3600),
            capability_assessment=stale)
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            r.call(ex)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_expired")

    def test_spawn_refused_on_bad_assessment(self):
        r = _GovernedRun(self)
        ex = r.executor(
            capability_gate_binding=_binding(r.signer),
            capability_assessment=None,
            session_identity=("agent-1", "scout", "user-7"))
        with self.assertRaises(cg.CapabilityGateRefusal):
            ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                               r.keys.parent[0])
        spawns = [e for e in r.entries()
                  if e.get("event") == "agent_spawn"]
        self.assertEqual(spawns, [])

    def test_spawn_inherits_binding_and_child_runs(self):
        r = _GovernedRun(self)
        good = _sealed("SUFFICIENT", r.signer)
        ex = r.executor(
            capability_gate_binding=_binding(r.signer),
            capability_assessment=good,
            session_identity=("agent-1", "scout", "user-7"))
        with _quiet():
            child = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                       r.keys.parent[0])
        # The child re-enforces the same gate: it inherited the binding.
        self.assertIsNotNone(child._capability_gate_binding)
        res = child.call(child._session_identity, "read_file",
                         path="notes.txt")
        self.assertEqual(res.get("status"), "executed")

    def test_assessment_rotation(self):
        r = _GovernedRun(self)
        good = _sealed("SUFFICIENT", r.signer)
        ex = r.executor(capability_gate_binding=_binding(r.signer),
                        capability_assessment=good)
        res = r.call(ex)
        self.assertEqual(res.get("status"), "executed")
        # Rotate to an expired assessment: the next call refuses.
        ex.update_capability_assessment(
            _sealed("SUFFICIENT", r.signer,
                    assessed_at=time.time() - 7200))
        with self.assertRaises(cg.CapabilityGateRefusal) as cm:
            r.call(ex)
        self.assertEqual(cm.exception.refusal_cause,
                         "capability_assessment_expired")
        # Rotate back to fresh: the run resumes.
        ex.update_capability_assessment(
            _sealed("SUFFICIENT", r.signer))
        res = r.call(ex)
        self.assertEqual(res.get("status"), "executed")
        # A non-mapping rotation is rejected at install time.
        with self.assertRaises(cg.CapabilityGateError):
            ex.update_capability_assessment("not-a-mapping")
        updated = [e for e in r.entries()
                   if e.get("event") == "capability_assessment_updated"]
        self.assertEqual(len(updated), 2)

    def test_blank_ack_refused(self):
        r = _GovernedRun(self)
        with _quiet():
            with self.assertRaises(cg.CapabilityGateBindingError):
                r.executor(capability_ungoverned_ack="   ")

    def test_contradictory_binding_and_ack_refused(self):
        r = _GovernedRun(self)
        with _quiet():
            with self.assertRaises(cg.CapabilityGateBindingError) as cm:
                r.executor(capability_gate_binding=_binding(r.signer),
                           capability_ungoverned_ack="both given")
        self.assertIn("contradictory", str(cm.exception))

    def test_malformed_binding_refused_at_construction(self):
        r = _GovernedRun(self)
        bad = _binding(r.signer)
        bad["harness_digest"] = "zz"
        with _quiet():
            with self.assertRaises(cg.CapabilityGateBindingError):
                r.executor(capability_gate_binding=bad)

    def test_acknowledged_ungoverned_declared_and_runs(self):
        r = _GovernedRun(self)
        with _quiet():
            ex = r.executor(capability_ungoverned_ack=(
                "capgate test: deliberate ungoverned-capability run"))
        declared = [e for e in r.entries()
                    if e.get("event")
                    == "capability_gate_ungoverned_declared"]
        self.assertEqual(len(declared), 1)
        self.assertIn("deliberate ungoverned-capability",
                      declared[0]["ungoverned_reason"])
        res = r.call(ex)
        self.assertEqual(res.get("status"), "executed")

    def test_ack_refused_in_production(self):
        import unittest.mock as mock
        r = _GovernedRun(self)
        with mock.patch.dict(os.environ, {"GOV_DEPLOYMENT_MODE":
                                           "production"}):
            with _quiet():
                with self.assertRaises(cg.CapabilityGateBindingError):
                    r.executor(capability_ungoverned_ack="prod bypass")

    def test_raw_pipeline_untouched(self):
        # No governed core + wave-85 ack: construction and calls work
        # exactly as before -- the gate does not pretend to govern the
        # raw pipeline.
        from harness import make_run
        with _quiet():
            ctx = make_run()
        ex = ctx["executor"]
        ident = ex.mint_identity("a1", "researcher", "org")
        (ctx["run_dir"] / "notes.txt").write_text("x\n")
        res = ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(res.get("status"), "executed")


if __name__ == "__main__":
    unittest.main()
