"""Row-12 wave-162 unit tests: undeclared-path write binding.

Break-first discipline: every behavior here was demonstrated red by
evals/row12_undeclared_path_probes.py (13 BREAK pre-seam) before the
seam existed.

Deterministic, $0, stdlib only, unittest only. The suite runs in
staging (tests/__init__.py).
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gov import artifact_inventory_manifest as man
from gov.approvals import ApprovalQueue
from gov.executor import (
    ToolExecutor,
    _normalize_declared_write_dirs,
)
from gov.log import ActionLog, read_entries
from gov.policy import PolicyEngine

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

_UNGOVERNED_ACK = (
    "undeclared-path unit: synthetic harness; raw pre-wave-74/75 "
    "pipeline by design, declared and chained")
_OPT_OUT_REASON = "no deployment-critical files in this deployment"

SHA = "ab" * 32


def _pin(entries):
    return man.pin_manifest(entries)


def _make_executor(**kw):
    run_dir = Path(tempfile.mkdtemp(prefix="govundecl-unit-"))
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    kw = dict(kw)
    if "deployment_manifest" not in kw:
        kw.setdefault("deployment_manifest_opt_out", _OPT_OUT_REASON)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK, **kw)
    return run_dir, ex, approvals


def _events(run_dir, name):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if isinstance(e, dict) and e.get("event") == name]


def _ident(ex):
    return ex.mint_identity("coder-1", "coder", "user-1")


class TestCheckWriteDeclaredPath(unittest.TestCase):
    """The write-binding check seam, called directly."""

    def test_declared_path_allowed(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", "a.bin",
                                          declared_path="a.bin")
        self.assertEqual(res["verdict"], "allow")
        self.assertTrue(res["declared"])
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_undeclared_path_require_approval_loud(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", "evil.bin",
                                          declared_path="evil.bin")
        self.assertEqual(res["verdict"], "require_approval")
        self.assertFalse(res["declared"])
        evs = _events(run_dir, "write_undeclared_path")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev["flag"], "undeclared_write_path")
        self.assertEqual(ev["policy_id"], "manifest-write-binding")
        self.assertEqual(ev["decision"], "require_approval")
        self.assertEqual(ev["path"], "evil.bin")
        self.assertIn("manifest_digest", ev)
        # No content in the audit event.
        self.assertNotIn("content", ev)

    def test_no_manifest_silent_allow(self):
        run_dir, ex, _ = _make_executor()
        res = ex.check_write_declared_path("coder-1", "evil.bin",
                                          declared_path="evil.bin")
        self.assertEqual(res["verdict"], "allow")
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_outside_sandbox_silent_allow(self):
        # The quarantine-outside-writes seam owns outside writes; the
        # manifest binding must not fork the audit trail.
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path(
            "coder-1", str(run_dir / "quarantine" / "evil.bin"))
        self.assertEqual(res["verdict"], "allow")
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_dotdot_collapsed_before_compare(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", "sub/../evil.bin",
                                          declared_path="sub/../evil.bin")
        self.assertEqual(res["verdict"], "require_approval")
        self.assertEqual(_events(run_dir, "write_undeclared_path")
                         [0]["path"], "evil.bin")

    def test_case_variant_distinct(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", "A.BIN",
                                          declared_path="A.BIN")
        self.assertEqual(res["verdict"], "require_approval")

    def test_declared_write_dir_prefix(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}),
            declared_write_dirs=("scratch",))
        ok = ex.check_write_declared_path("coder-1", "scratch/notes.txt")
        self.assertEqual(ok["verdict"], "allow")
        # A prefix that merely shares characters is not a dir.
        bad = ex.check_write_declared_path("coder-1", "scratchx/notes.txt")
        self.assertEqual(bad["verdict"], "require_approval")
        self.assertEqual(len(_events(run_dir, "write_undeclared_path")),
                         1)

    def test_no_resolved_target_silent(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", None)
        self.assertEqual(res["verdict"], "allow")
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_post_construction_attach_binds(self):
        # The binding follows the EFFECTIVE manifest -- the same
        # envelope the egress consult reads. A post-construction
        # attach binds writes even though the constructor decision
        # was opt-out.
        run_dir, ex, _ = _make_executor()
        ex.artifacts.attach_deployment_manifest(_pin({"a.bin": SHA}))
        res = ex.check_write_declared_path("coder-1", "evil.bin",
                                          declared_path="evil.bin")
        self.assertEqual(res["verdict"], "require_approval")
        self.assertEqual(len(_events(run_dir, "write_undeclared_path")),
                         1)

    def test_detach_releases_binding(self):
        # Detach returns the inventory to run-scoped only; the egress
        # consult stops reading the manifest, and so does the binding.
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        ex.artifacts.detach_deployment_manifest()
        res = ex.check_write_declared_path("coder-1", "evil.bin",
                                          declared_path="evil.bin")
        self.assertEqual(res["verdict"], "allow")
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])


class TestCallIntegration(unittest.TestCase):
    """The call() path: the hold forces human review on allow."""

    def test_undeclared_write_queued_not_executed(self):
        run_dir, ex, approvals = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        ident = _ident(ex)
        res = ex.call(ident, "write_file", path="evil.bin",
                      content="hostile bytes")
        self.assertEqual(res["status"], "queued")
        self.assertTrue(res["approval_id"])
        self.assertEqual(res["policy_id"], "manifest-write-binding")
        self.assertFalse((run_dir / "sandbox" / "evil.bin").is_file())
        evs = _events(run_dir, "write_undeclared_path")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["flag"], "undeclared_write_path")
        # The queued record shows the forcing.
        rec = approvals.get(res["approval_id"]) or {}
        self.assertEqual(rec.get("policy_flag"), "undeclared_write_path")

    def test_declared_write_executes(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        ident = _ident(ex)
        res = ex.call(ident, "write_file", path="a.bin",
                      content="legit bytes")
        self.assertEqual(res["status"], "executed")
        self.assertTrue((run_dir / "sandbox" / "a.bin").is_file())
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_no_manifest_write_executes_silent(self):
        # No-monitor deployments stay silent-allow (wave-160
        # precedent); the seam is opt-in by manifest attachment.
        run_dir, ex, _ = _make_executor()
        ident = _ident(ex)
        res = ex.call(ident, "write_file", path="evil.bin",
                      content="x")
        self.assertEqual(res["status"], "executed")
        self.assertEqual(_events(run_dir, "write_undeclared_path"), [])

    def test_approved_sweep_executes_once_no_requeue(self):
        run_dir, ex, approvals = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        ident = _ident(ex)
        res = ex.call(ident, "write_file", path="evil.bin",
                      content="hostile bytes")
        self.assertEqual(res["status"], "queued")
        approvals.decide(res["approval_id"], True,
                         reason="operator reviewed undeclared artifact",
                         decided_by="human-operator")
        done = ex.execute_approved() or []
        wrote = [d for d in done
                 if isinstance(d, dict) and d.get("tool") == "write_file"]
        self.assertTrue((run_dir / "sandbox" / "evil.bin").is_file())
        self.assertEqual(len(wrote), 1)
        # No re-queue: the human reviewed the MAC-bound record
        # (wave-160 precedent); exactly one hold event total.
        self.assertEqual(len(_events(run_dir, "write_undeclared_path")),
                         1)

    def test_symlink_alias_to_undeclared_held(self):
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}))
        sb = run_dir / "sandbox"
        (sb / "sub2").mkdir(parents=True, exist_ok=True)
        (sb / "link2").symlink_to(sb / "sub2")
        ident = _ident(ex)
        res = ex.call(ident, "write_file", path="link2/evil.bin",
                      content="x")
        self.assertEqual(res["status"], "queued")
        self.assertFalse((sb / "sub2" / "evil.bin").is_file())


class TestDeclaredWriteDirsNormalization(unittest.TestCase):
    def test_none_and_empty(self):
        self.assertEqual(_normalize_declared_write_dirs(None), ())
        self.assertEqual(_normalize_declared_write_dirs([]), ())

    def test_prefixes_normalized(self):
        self.assertEqual(
            _normalize_declared_write_dirs(["./scratch/", "out\\x"]),
            ("scratch", "out/x"))

    def test_rejects_escape(self):
        with self.assertRaises(ValueError):
            _normalize_declared_write_dirs(["../out"])
        with self.assertRaises(ValueError):
            _normalize_declared_write_dirs([""])

    def test_rejects_non_string(self):
        with self.assertRaises(ValueError):
            _normalize_declared_write_dirs([123])

    def test_constructor_fail_closed(self):
        with self.assertRaises(ValueError):
            _make_executor(
                deployment_manifest=_pin({"a.bin": SHA}),
                declared_write_dirs=["../out"])


class TestSpawnContract(unittest.TestCase):
    def test_child_inherits_binding(self):
        # spawn_sub_agent needs delegation plumbing; the unit pins the
        # contract directly (repo precedent: test_artifacts
        # TestSpawnSharing) -- the child is constructed with the
        # parent's envelope and declared dirs, exactly as the spawn
        # line does.
        run_dir, ex, _ = _make_executor(
            deployment_manifest=_pin({"a.bin": SHA}),
            declared_write_dirs=("scratch",))
        child = ToolExecutor(run_dir, ex.policy, ex.log,
                             ApprovalQueue(run_dir, ex.log),
                             ledger_path=run_dir / "egress2.jsonl",
                             ungoverned_ack=_UNGOVERNED_ACK,
                             deployment_manifest=(
                                 ex._deployment_manifest_envelope),
                             declared_write_dirs=ex._declared_write_dirs)
        self.assertEqual(child._declared_write_dirs, ("scratch",))
        ident = child.mint_identity("sub-1", "coder", "user-1")
        r1 = child.call(ident, "write_file", path="evil.bin",
                        content="x")
        self.assertEqual(r1["status"], "queued")
        self.assertEqual(r1["policy_id"], "manifest-write-binding")
        r2 = child.call(ident, "write_file", path="scratch/n.txt",
                        content="x")
        self.assertEqual(r2["status"], "executed")


if __name__ == "__main__":
    unittest.main()
