"""Row-12 wave-158 unit tests: default-on deployment-manifest attachment.

Break-first discipline: every behavior here was demonstrated red by
evals/manifest_default_on_probes.py (0 HELD / 15 BREAK pre-seam) before
the gate existed.

Deterministic, $0, stdlib only, unittest only. The suite runs in
staging (tests/__init__.py); production-mode paths are pinned through
the gate function directly with the mode patched, plus one full
governed-core production refusal.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gov import artifact_inventory_manifest as man
from gov import artifacts as _artifacts_mod
from gov.approvals import ApprovalQueue
from gov.executor import (
    DeploymentManifestRequiredError,
    ToolExecutor,
    _deployment_manifest_construction_check,
)
from gov.log import ActionLog, read_entries
from gov.policy import PolicyEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

_UNGOVERNED_ACK = (
    "manifest-default-on unit: synthetic harness; raw pre-wave-74/75 "
    "pipeline by design, declared and chained")
_OPT_OUT_REASON = "no deployment-critical files in this deployment"


def _make_executor(**kw):
    run_dir = Path(tempfile.mkdtemp(prefix="govmanif-unit-"))
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK, **kw)
    return run_dir, ex


def _events(run_dir, name):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if isinstance(e, dict) and e.get("event") == name]


def _pin(entries):
    return man.pin_manifest(entries)


class TestStagingDecision(unittest.TestCase):
    """Staging: the decision is default-on and LOUD, never silent."""

    def test_silent_absence_is_loud(self):
        run_dir, ex = _make_executor()
        self.assertEqual(ex._deployment_manifest_decision, "absent")
        evs = _events(run_dir, "deployment_manifest_absent")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].get("deployment_mode"), "staging")

    def test_envelope_attached_and_chained(self):
        env = _pin({"a.bin": "ab" * 32})
        run_dir, ex = _make_executor(deployment_manifest=env)
        self.assertEqual(ex._deployment_manifest_decision, "attached")
        self.assertTrue(ex.artifacts.has_deployment_manifest)
        evs = _events(run_dir, "deployment_manifest_attached")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].get("manifest_digest"),
                         man.manifest_digest(env))
        self.assertEqual(evs[0].get("entry_count"), 1)

    def test_opt_out_recorded_with_reason(self):
        run_dir, ex = _make_executor(
            deployment_manifest_opt_out=_OPT_OUT_REASON)
        self.assertEqual(ex._deployment_manifest_decision, "opt_out")
        self.assertFalse(ex.artifacts.has_deployment_manifest)
        evs = _events(run_dir, "deployment_manifest_opt_out")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].get("opt_out_reason"), _OPT_OUT_REASON)

    def test_contradiction_refused(self):
        env = _pin({"a.bin": "ab" * 32})
        with self.assertRaises(DeploymentManifestRequiredError):
            _make_executor(deployment_manifest=env,
                           deployment_manifest_opt_out=_OPT_OUT_REASON)

    def test_blank_opt_out_refused(self):
        for bad in ("", "   ", "\t\n", 12345, None.__class__):
            with self.assertRaises(DeploymentManifestRequiredError,
                                   msg="opt_out=%r" % (bad,)):
                _make_executor(deployment_manifest_opt_out=bad)

    def test_forged_envelope_fail_loud(self):
        env = _pin({"a.bin": "ab" * 32})
        env["pin"] = "00" * 32
        with self.assertRaises(ValueError):
            _make_executor(deployment_manifest=env)

    def test_pinstripped_envelope_fail_loud(self):
        env = _pin({"a.bin": "ab" * 32})
        del env["pin"]
        with self.assertRaises(ValueError):
            _make_executor(deployment_manifest=env)

    def test_spawn_inputs_remembered(self):
        """The deployment's decision inputs are kept on the executor so
        spawned children inherit the posture (spawn itself is pinned by
        the eval battery with real delegation plumbing)."""
        env = _pin({"a.bin": "ab" * 32})
        _, ex = _make_executor(deployment_manifest=env)
        self.assertIs(ex._deployment_manifest_envelope, env)
        self.assertIsNone(ex._deployment_manifest_opt_out_reason)
        _, ex2 = _make_executor(
            deployment_manifest_opt_out=_OPT_OUT_REASON)
        self.assertIsNone(ex2._deployment_manifest_envelope)
        self.assertEqual(ex2._deployment_manifest_opt_out_reason,
                         _OPT_OUT_REASON)


class TestGateFunctionModes(unittest.TestCase):
    """The gate function across deployment modes (mode patched around
    the call; resolve_deployment_mode reads the env at call time)."""

    def _check(self, mode, manifest=None, opt_out=None):
        inv = _artifacts_mod.ArtifactInventory()
        appended = []
        with mock.patch.dict(os.environ, {"GOV_DEPLOYMENT_MODE": mode}):
            return _deployment_manifest_construction_check(
                "run-unit", appended.append, inv, manifest, opt_out), appended

    def test_production_silent_refused_and_chained(self):
        with self.assertRaises(DeploymentManifestRequiredError):
            self._check("production")
        # The refusal attempt itself is evidence: chained before raise.
        inv = _artifacts_mod.ArtifactInventory()
        appended = []
        with mock.patch.dict(os.environ, {"GOV_DEPLOYMENT_MODE": "production"}):
            with self.assertRaises(DeploymentManifestRequiredError):
                _deployment_manifest_construction_check(
                    "run-unit", appended.append, inv, None, None)
        self.assertEqual(len(appended), 1)
        self.assertEqual(appended[0]["event"],
                         "deployment_manifest_refused")

    def test_production_opt_out_ok(self):
        (decision, reason), appended = self._check(
            "production", opt_out=_OPT_OUT_REASON)
        self.assertEqual(decision, "opt_out")
        self.assertEqual(reason, _OPT_OUT_REASON)
        self.assertEqual(appended[0]["event"],
                         "deployment_manifest_opt_out")

    def test_production_envelope_ok(self):
        env = _pin({"a.bin": "ab" * 32})
        inv = _artifacts_mod.ArtifactInventory()
        appended = []
        with mock.patch.dict(os.environ, {"GOV_DEPLOYMENT_MODE": "production"}):
            decision, _ = _deployment_manifest_construction_check(
                "run-unit", appended.append, inv, env, None)
        self.assertEqual(decision, "attached")
        self.assertTrue(inv.has_deployment_manifest)

    def test_unknown_mode_fails_closed_toward_refusal(self):
        with self.assertRaises(DeploymentManifestRequiredError):
            self._check("bogus-mode")

    def test_empty_mode_defaults_to_production_refusal(self):
        # Unset mode resolves to production (least-privilege default).
        inv = _artifacts_mod.ArtifactInventory()
        appended = []
        env = dict(os.environ)
        env.pop("GOV_DEPLOYMENT_MODE", None)
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(DeploymentManifestRequiredError):
                _deployment_manifest_construction_check(
                    "run-unit", appended.append, inv, None, None)


if __name__ == "__main__":
    unittest.main()
