"""Wave-85 unit tests: the fail-closed construction seam.

Aviation checklist discipline: the safe state (governed core:
policy_store + delegation_context) is the DEFAULT. Constructing a
ToolExecutor without the core requires an explicit, non-blank,
recorded ungoverned_ack — refused outright in production, and
unknown/unresolvable deployment modes fail closed toward refusal.

These tests assert the REFUSAL paths directly (they omit
ungoverned_ack on purpose); the rest of the suite declares its bypass
via tests/harness.py.
"""

import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import (ToolExecutor,  # noqa: E402
                          UngovernedConstructionError)
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from gov.capability_gate import compute_harness_digest  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
_BASE_POLICY = (REPO_ROOT / "policies" / "default.yaml").read_text(
    encoding="utf-8")

_SID = "sess-w85"
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _Keys(object):
    """One synthetic Ed25519 key per trust layer (mirrors w74)."""

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


def _bound_ctx(keys, session=_SID):
    user_tok = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file",), session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file",), session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI, ttl_s=3600)
    return _dt.DelegationContext(
        user_token=user_tok,
        agent_token=agent_tok,
        delegation_token=deleg_tok,
        trust=keys.trust(),
        session_id=session,
        parent_chain=[]).bind()


def _human():
    return Ed25519Signer(secrets.token_bytes(32))


def _store(humans, log=None, mode="staging"):
    h1 = humans[0]
    trust = _dt.DelegationTrust(
        human_keys={h.key_id: h.public_key for h in humans},
        authority_keys={h1.key_id: h1.public_key},
        user_issuer_keys={h1.key_id: h1.public_key})
    store = _pc.GovernedPolicyStore(
        deployment_mode=mode, trust=trust, log=log,
        session_id="sess-w85-store")
    # Production tier requires two distinct human approvers.
    approvers = humans if mode == "production" else [h1]
    store.bootstrap(_BASE_POLICY, h1, "alice", "initial policy",
                    approver_signers=approvers)
    return store


class _Run(object):
    """Fresh run dir + log + approvals + engine, mode patched."""

    def __init__(self, test, mode="staging"):
        self._td = tempfile.TemporaryDirectory(prefix="govw85-")
        test.addCleanup(self._td.cleanup)
        self.run_dir = Path(self._td.name) / "run"
        self.run_dir.mkdir()
        self.log = ActionLog(self.run_dir / "actions.jsonl")
        self.approvals = ApprovalQueue(self.run_dir, self.log)
        self.engine = PolicyEngine.from_text(
            _BASE_POLICY, source_label="<w85>")
        self._patcher = mock.patch.dict(
            os.environ, {"GOV_DEPLOYMENT_MODE": mode})
        self._patcher.start()
        test.addCleanup(self._patcher.stop)

    def build(self, **kw):
        return ToolExecutor(self.run_dir, self.engine, self.log,
                            self.approvals, **kw)

    def entries(self):
        return read_entries(self.run_dir / "actions.jsonl")


class TestGovernedCoreConstructsWithoutAck(unittest.TestCase):
    def test_full_core_needs_no_ack(self):
        r = _Run(self)
        keys, h1 = _Keys(), _human()
        ex = r.build(policy_store=_store([h1], log=r.log),
                     delegation_context=_bound_ctx(keys),
                     # Wave-100: this test's subject is the wave-85
                     # construction gate (full core needs no ungoverned
                     # ACK). The capability gate is a separate, newer
                     # seam, so the build declares that posture
                     # explicitly; declared, not silent.
                     capability_ungoverned_ack=(
                         "w85 test: wave-85 subject is the construction "
                         "gate; the capability gate is not under test"))
        self.assertTrue(ex.is_governed)
        # No bypass declaration was chained for a governed construction.
        kinds = [e.get("event") for e in r.entries()]
        self.assertNotIn("ungoverned_bypass", kinds)
        self.assertNotIn("ungoverned_bypass_refused", kinds)

    def test_missing_policy_store_refused_without_ack(self):
        r = _Run(self)
        with self.assertRaises(UngovernedConstructionError):
            r.build(delegation_context=_bound_ctx(_Keys()))

    def test_missing_delegation_context_refused_without_ack(self):
        r = _Run(self)
        with self.assertRaises(UngovernedConstructionError):
            r.build(policy_store=_store([_human()], log=r.log))

    def test_missing_both_refused_without_ack(self):
        r = _Run(self)
        with self.assertRaises(UngovernedConstructionError):
            r.build()
        refused = [e for e in r.entries()
                   if e.get("event") == "ungoverned_bypass_refused"]
        self.assertTrue(refused, "the refusal must be chained")
        self.assertEqual(refused[0]["refusal_cause"], "no_ack")
        self.assertEqual(set(refused[0]["missing_components"]),
                         {"policy_store", "delegation_context"})


class TestAckShape(unittest.TestCase):
    def test_blank_ack_refused(self):
        r = _Run(self)
        for bad in ("", "   ", "\t\n "):
            with self.assertRaises(UngovernedConstructionError,
                                   msg="ack=%r" % (bad,)):
                r.build(ungoverned_ack=bad)
        causes = [e.get("refusal_cause") for e in r.entries()
                  if e.get("event") == "ungoverned_bypass_refused"]
        self.assertTrue(all(c == "blank_ack" for c in causes))
        self.assertEqual(len(causes), 3)

    def test_non_string_ack_refused(self):
        r = _Run(self)
        for bad in (None, 123, b"bytes", ["x"]):
            # None is "no ack"; the rest are non-string acks.
            with self.assertRaises(UngovernedConstructionError):
                r.build(ungoverned_ack=bad)

    def test_valid_ack_records_loud_declaration(self):
        r = _Run(self)
        reason = "w85 unit test: deliberate raw construction"
        # Construct DIRECTLY (not via the _Run.build helper) so the
        # caller-attribution assertion names this test method.
        ex = ToolExecutor(r.run_dir, r.engine, r.log, r.approvals,
                          ungoverned_ack=reason)
        self.assertFalse(ex.is_governed)
        decls = [e for e in r.entries()
                 if e.get("event") == "ungoverned_bypass"]
        self.assertEqual(len(decls), 1)
        d = decls[0]
        self.assertEqual(d["ungoverned_reason"], reason)
        self.assertEqual(set(d["missing_components"]),
                         {"policy_store", "delegation_context"})
        self.assertEqual(d["deployment_mode"], "staging")
        # Caller attribution: this test file, this test method.
        self.assertEqual(d["caller_file"], "test_w85_legacy_seam.py")
        self.assertEqual(d["caller_function"],
                         "test_valid_ack_records_loud_declaration")
        self.assertGreater(d["caller_line"], 0)
        # The declaration is the FIRST chained record of the run.
        self.assertEqual(d["seq"], 1)
        # Loud semantics travel in the human-readable reason.
        self.assertIn("LOUD", d["reason"])
        self.assertIn(reason, d["reason"])

    def test_partial_core_ack_names_only_missing(self):
        r = _Run(self)
        r.build(policy_store=_store([_human()], log=r.log),
                ungoverned_ack="store-only construction")
        decls = [e for e in r.entries()
                 if e.get("event") == "ungoverned_bypass"]
        self.assertEqual(decls[0]["missing_components"],
                         ["delegation_context"])

    def test_declaration_reports_absent_non_core_components(self):
        # Wave-85: the declaration reports the FULL deployment shape —
        # missing core (invalidating) plus absent non-core components
        # (deployment choices, never invalidating).
        r = _Run(self)
        r.build(ungoverned_ack="bare construction")
        decls = [e for e in r.entries()
                 if e.get("event") == "ungoverned_bypass"]
        self.assertEqual(decls[0]["missing_components"],
                         ["policy_store", "delegation_context"])
        self.assertEqual(decls[0]["absent_non_core_components"],
                         # Wave-119: erosion_monitor joins the declared
                         # non-core set (opt-in trajectory monitor,
                         # detection_monitor precedent).
                         ["detection_monitor", "erosion_monitor", "recovery",
                          "lease_verifier", "precommit_gate",
                          "trifecta_floor"])

    def test_present_non_core_component_not_reported_absent(self):
        r = _Run(self)
        r.build(ungoverned_ack="bare construction",
                detection_monitor=object(), trifecta_floor=True)
        decls = [e for e in r.entries()
                 if e.get("event") == "ungoverned_bypass"]
        absent = decls[0]["absent_non_core_components"]
        self.assertNotIn("detection_monitor", absent)
        self.assertNotIn("trifecta_floor", absent)
        self.assertIn("recovery", absent)


class TestProductionRefusesEvenDeclared(unittest.TestCase):
    def test_production_refuses_valid_ack(self):
        r = _Run(self, mode="production")
        with self.assertRaises(UngovernedConstructionError) as cm:
            r.build(ungoverned_ack="a perfectly good reason")
        self.assertIn("production", str(cm.exception).lower())
        refused = [e for e in r.entries()
                   if e.get("event") == "ungoverned_bypass_refused"]
        self.assertTrue(refused)
        self.assertEqual(refused[0]["refusal_cause"], "production")
        # No declaration was chained for the refused production bypass.
        self.assertNotIn("ungoverned_bypass",
                         [e.get("event") for e in r.entries()])

    def test_production_governed_core_still_constructs(self):
        r = _Run(self, mode="production")
        keys, h1 = _Keys(), _human()
        # Wave-100: the capability-ungoverned ACK is refused in production,
        # so a production governed deployment binds a real capability gate
        # instead. Construction validates the binding shape; the assessment
        # itself is verified per call, which this test never makes.
        seal_key = Ed25519Signer(secrets.token_bytes(32))
        binding = {
            "harness_id": "w85-test-harness",
            "harness_digest": compute_harness_digest(
                "w85-test-harness", {"thresholds": "w85-test"}, 1),
            "freshness_seconds": 3600,
            "trusted_keys": {"seal-key": seal_key.public_key},
        }
        ex = r.build(policy_store=_store([h1, _human()], log=r.log,
                                    mode="production"),
                     delegation_context=_bound_ctx(keys),
                     capability_gate_binding=binding,
                     # Wave-158 (row 12): the deployment manifest is
                     # default-on -- production construction requires a
                     # manifest decision. This test's subject is the
                     # wave-85 gate (governed production constructs), so
                     # it records the orthogonal opt-out explicitly.
                     deployment_manifest_opt_out=(
                         "w85 test: manifest seam not under test; no "
                         "deployment-critical files in this fixture"))
        self.assertTrue(ex.is_governed)


class TestUnknownModeFailsClosed(unittest.TestCase):
    def test_unknown_mode_refused_as_construction_error(self):
        # Build the log BEFORE the mode goes unknown: the point is the
        # construction seam, not the key layer.
        td = tempfile.TemporaryDirectory(prefix="govw85-")
        self.addCleanup(td.cleanup)
        run_dir = Path(td.name) / "run"
        run_dir.mkdir()
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        engine = PolicyEngine.from_text(_BASE_POLICY,
                                        source_label="<w85>")
        with mock.patch.dict(os.environ,
                             {"GOV_DEPLOYMENT_MODE": "warp-drive-9"}):
            with self.assertRaises(UngovernedConstructionError) as cm:
                ToolExecutor(run_dir, engine, log, approvals,
                             ungoverned_ack="any reason at all")
        # The refusal stands even though the key layer ALSO rejects the
        # unknown mode: the chained refusal record is best-effort (the
        # log's own HMAC needs a resolvable mode), but the exception is
        # the seam's UngovernedConstructionError, never a silent pass.
        self.assertIn("unresolvable", str(cm.exception).lower())


class TestDeclarationMustChain(unittest.TestCase):
    def test_accepted_bypass_fails_closed_if_declaration_cannot_chain(self):
        r = _Run(self)

        class _BoomLog(object):
            def append(self, entry):
                raise IOError("synthetic disk-full")

        with self.assertRaises(UngovernedConstructionError) as cm:
            ToolExecutor(r.run_dir, r.engine, _BoomLog(), r.approvals,
                         ungoverned_ack="declared but unchainable")
        self.assertIn("could not be chained", str(cm.exception))

    def test_refusal_record_is_best_effort_not_load_bearing(self):
        # The refusal stands even when the audit write itself fails:
        # the exception type is what the caller catches.
        r = _Run(self)

        class _BoomLog(object):
            def append(self, entry):
                raise IOError("synthetic disk-full")

        with self.assertRaises(UngovernedConstructionError):
            ToolExecutor(r.run_dir, r.engine, _BoomLog(), r.approvals)


class TestSameRunAttribution(unittest.TestCase):
    def test_governed_and_declared_share_a_run_without_confusion(self):
        r = _Run(self)
        keys, h1 = _Keys(), _human()
        gov_ex = r.build(policy_store=_store([h1], log=r.log),
                         delegation_context=_bound_ctx(
                             keys, session=r.run_dir.name),
                         # Wave-100: governed core installed, so the
                         # capability posture is declared explicitly (out
                         # of scope for this attribution probe).
                         capability_ungoverned_ack=(
                             "w85 attribution test: governed tool_call vs "
                             "declared bypass; the capability gate is not "
                             "the subject under test"))
        ident = gov_ex.mint_identity("agent-1", "scout", "user-7")
        r1 = gov_ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r1["status"], "executed")
        # A second, declared-ungoverned executor over the SAME run dir.
        r.build(ungoverned_ack="w85 unit test: attribution probe")
        decls = [e for e in r.entries()
                 if e.get("event") == "ungoverned_bypass"]
        self.assertEqual(len(decls), 1)
        # The governed tool_call and the bypass declaration are
        # distinguishable by regime markers in one chain.
        regimes = [(e.get("event"),
                    "bypass" if e.get("event") == "ungoverned_bypass"
                    else "governed")
                   for e in r.entries()
                   if e.get("event") in ("tool_call", "ungoverned_bypass")]
        self.assertIn(("tool_call", "governed"), regimes)
        self.assertIn(("ungoverned_bypass", "bypass"), regimes)


class TestEvidenceRendersBypass(unittest.TestCase):
    def _bundle(self, entries):
        sys.path.insert(0, str(REPO_ROOT / "demo"))
        try:
            import verify_evidence as _ve
        finally:
            sys.path.remove(str(REPO_ROOT / "demo"))
        td = tempfile.TemporaryDirectory(prefix="govw85ev-")
        self.addCleanup(td.cleanup)
        bdir = Path(td.name)
        (bdir / "bundle.json").write_text(json.dumps({
            "bundle_version": _ve.BUNDLE_VERSION,
            "run_id": "w85-evidence-probe",
            "chain_segment": {"entries": entries},
            "anchors": [],
        }), encoding="utf-8")
        (bdir / "witness.json").write_text(json.dumps({}),
                                           encoding="utf-8")
        return _ve, bdir

    def _ve(self):
        sys.path.insert(0, str(REPO_ROOT / "demo"))
        try:
            import verify_evidence as _ve
            return _ve
        finally:
            sys.path.remove(str(REPO_ROOT / "demo"))

    def test_declared_bypass_renders_loud(self):
        _ve = self._ve()
        entries = [
            {"seq": 1, "event": "ungoverned_bypass",
             "ungoverned_reason": "w85 unit test reason",
             "missing_components": ["policy_store", "delegation_context"],
             "deployment_mode": "staging",
             "caller_file": "test_w85_legacy_seam.py",
             "caller_line": 4242, "caller_function": "probe_fn"},
            {"seq": 2, "event": "tool_call", "decision": "executed"},
        ]
        _ve2, bdir = self._bundle(entries)
        report = _ve2.verify_bundle(bdir)
        ub = report["ungoverned_bypasses"]
        self.assertEqual(ub["verdict"], "DECLARED")
        self.assertEqual(ub["declarations"][0]["reason"],
                         "w85 unit test reason")
        text = _ve2.render_report(report)
        self.assertIn("UNGOVERNED BYPASS DECLARATIONS: DECLARED", text)
        self.assertIn("w85 unit test reason", text)
        self.assertIn("AUDITOR", text)

    def test_no_bypass_renders_none_loudly(self):
        _ve, bdir = self._bundle([
            {"seq": 1, "event": "tool_call", "decision": "executed"},
        ])
        report = _ve.verify_bundle(bdir)
        self.assertEqual(report["ungoverned_bypasses"]["verdict"], "NONE")
        text = _ve.render_report(report)
        self.assertIn("UNGOVERNED BYPASS DECLARATIONS: NONE", text)

    def test_refused_attempt_renders(self):
        _ve, bdir = self._bundle([
            {"seq": 1, "event": "ungoverned_bypass_refused",
             "refusal_cause": "production",
             "missing_components": ["policy_store", "delegation_context"],
             "caller_file": "x.py", "caller_line": 1,
             "caller_function": "f"},
        ])
        report = _ve.verify_bundle(bdir)
        self.assertEqual(report["ungoverned_bypasses"]["verdict"],
                         "REFUSED-ONLY")
        text = _ve.render_report(report)
        self.assertIn("REFUSED-ONLY", text)
        self.assertIn("production", text)


if __name__ == "__main__":
    unittest.main()
