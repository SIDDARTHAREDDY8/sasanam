#!/usr/bin/env python3
"""Unit tests for gov/artifact_sweep.py and the Row-12 executor wiring.

Covers: sweep_run_dir findings (never_registered / integrity_violation),
finding fields (path/size/sha256/mtime), path normalization, symlink
skipping, missing sandbox, re-registration currency, nested dirs, and
the executor wiring (run_artifact_sweep LOUD audit, opt-in auto-sweep
after execute_approved, default = zero behavior change).
"""

import hashlib
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "artifact-sweep-unittest")

from gov import artifact_sweep as _sweep  # noqa: E402
from gov.artifacts import ArtifactInventory  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"
PRINCIPAL = "user-1"

_UNGOVERNED_ACK = ("artifact-sweep unittest: synthetic harness; raw "
                   "pre-wave-74/75 pipeline by design, declared and "
                   "chained")


def _mk_run_dir():
    run_dir = Path(tempfile.mkdtemp(prefix="sweeptest-"))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    return run_dir


def _write(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def _register(inv, relpath, data, agent_id="a1", run_id="r1"):
    if not isinstance(data, bytes):
        data = data.encode()
    return inv.register(relpath, sha256=hashlib.sha256(data).hexdigest(),
                        size=len(data), agent_id=agent_id, run_id=run_id)


class SweepRunDir(unittest.TestCase):
    def setUp(self):
        self.run_dir = _mk_run_dir()
        self.inv = ArtifactInventory()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_empty_sandbox_no_findings(self):
        findings, stats = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(findings, [])
        self.assertEqual(stats["findings"], 0)
        self.assertEqual(stats["files_seen"], 0)

    def test_missing_sandbox_no_findings(self):
        findings, stats = _sweep.sweep_run_dir(
            self.run_dir / "no-such-run", self.inv)
        self.assertEqual(findings, [])
        self.assertIsNone(stats["sandbox"])

    def test_never_registered_fields(self):
        p = _write(self.run_dir / "sandbox" / "drop.txt", b"secret bytes")
        findings, stats = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["finding"], "unregistered_artifact")
        self.assertEqual(f["kind"], _sweep.NEVER_REGISTERED)
        self.assertEqual(f["path"], "drop.txt")
        self.assertEqual(f["size"], p.stat().st_size)
        self.assertEqual(f["sha256"], hashlib.sha256(b"secret bytes")
                         .hexdigest())
        self.assertTrue(f["mtime"])  # ISO timestamp present
        self.assertIn("detail", f)

    def test_registered_matching_clean(self):
        _write(self.run_dir / "sandbox" / "ok.txt", b"fine")
        _register(self.inv, "ok.txt", b"fine")
        findings, _ = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(findings, [])

    def test_integrity_violation_fields(self):
        _write(self.run_dir / "sandbox" / "r.txt", b"v1")
        rec = _register(self.inv, "r.txt", b"v1")
        _write(self.run_dir / "sandbox" / "r.txt", b"v2 tampered")
        findings, _ = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["kind"], _sweep.INTEGRITY_VIOLATION)
        self.assertEqual(f["path"], "r.txt")
        self.assertEqual(f["registered_sha256"], rec.sha256)
        self.assertNotEqual(f["sha256"], rec.sha256)

    def test_reregistration_currency(self):
        # Re-registering after a governed rewrite tracks the latest
        # bytes: no finding.
        _write(self.run_dir / "sandbox" / "r.txt", b"v2")
        _register(self.inv, "r.txt", b"v1")
        _register(self.inv, "r.txt", b"v2")
        findings, _ = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(findings, [])

    def test_nested_dirs_walked(self):
        _write(self.run_dir / "sandbox" / "sub" / "deep" / "x.bin",
               b"deep")
        findings, stats = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["path"], "sub/deep/x.bin")
        self.assertEqual(stats["files_seen"], 1)

    def test_path_normalization(self):
        # "./" and leading "/" forms normalize to the inventory key.
        _write(self.run_dir / "sandbox" / "n.txt", b"data")
        _register(self.inv, "./n.txt", b"data")
        findings, _ = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(findings, [])

    def test_symlink_skipped_not_followed(self):
        target = self.run_dir / "outside_secret.txt"
        target.write_text("not in sandbox\n", encoding="utf-8")
        link = self.run_dir / "sandbox" / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks not supported here")
        findings, stats = _sweep.sweep_run_dir(self.run_dir, self.inv)
        # The symlink is not a file write: no finding, not followed.
        self.assertEqual(findings, [])
        self.assertEqual(stats["files_seen"], 0)

    def test_deleted_registered_file_not_a_finding(self):
        # Inventory entries with no file on disk are not sweep
        # findings (deletion is a separate governed action).
        _register(self.inv, "gone.txt", b"was here")
        findings, _ = _sweep.sweep_run_dir(self.run_dir, self.inv)
        self.assertEqual(findings, [])

    def test_mixed_run(self):
        _write(self.run_dir / "sandbox" / "clean.txt", b"ok")
        _register(self.inv, "clean.txt", b"ok")
        _write(self.run_dir / "sandbox" / "smuggled.txt", b"bad")
        _write(self.run_dir / "sandbox" / "t.txt", b"v1")
        _register(self.inv, "t.txt", b"v1")
        _write(self.run_dir / "sandbox" / "t.txt", b"v2")
        findings, stats = _sweep.sweep_run_dir(self.run_dir, self.inv)
        kinds = sorted(f["kind"] for f in findings)
        self.assertEqual(kinds, [_sweep.INTEGRITY_VIOLATION,
                                _sweep.NEVER_REGISTERED])
        self.assertEqual(stats["findings"], 2)
        self.assertEqual(stats["files_compared"], 3)


class ExecutorWiring(unittest.TestCase):
    def setUp(self):
        self.run_dir = _mk_run_dir()
        self.tmp = self.run_dir  # alias for readability

    def tearDown(self):
        import shutil
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _executor(self, **kw):
        policy = PolicyEngine(str(DEFAULT_POLICY))
        log = ActionLog(self.run_dir / "actions.jsonl")
        approvals = ApprovalQueue(self.run_dir, log)
        return ToolExecutor(
            self.run_dir, policy, log, approvals,
            ledger_path=self.run_dir / "egress_ledger.jsonl",
            ungoverned_ack=_UNGOVERNED_ACK, **kw)

    def _events(self, name):
        return [e for e in read_entries(self.run_dir / "actions.jsonl")
                if isinstance(e, dict) and e.get("event") == name]

    def test_opt_in_absent_by_default(self):
        ex = self._executor()
        self.assertIsNone(ex.artifact_sweep)

    def test_run_artifact_sweep_audits_loud(self):
        ex = self._executor()
        ident = ex.mint_identity("coder-1", "coder", PRINCIPAL)
        r = ex.call(ident, "write_file", path="ok.txt", content="fine\n")
        self.assertEqual(r.get("status"), "executed")
        (self.run_dir / "sandbox" / "smuggled.txt").write_text(
            "smuggled\n", encoding="utf-8")
        findings = ex.run_artifact_sweep()
        self.assertEqual(len(findings), 1)
        evs = self._events(_sweep.SWEEP_FINDING_EVENT)
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["flag"], "unregistered_artifact")
        self.assertEqual(evs[0]["path"], "smuggled.txt")
        comp = self._events(_sweep.SWEEP_COMPLETE_EVENT)
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["findings"], 1)

    def test_auto_sweep_after_execute_approved(self):
        ex = self._executor(artifact_sweep=True)
        ident = ex.mint_identity("coder-1", "coder", PRINCIPAL)
        r = ex.call(ident, "write_file", path="ok.txt", content="fine\n")
        self.assertEqual(r.get("status"), "executed")
        (self.run_dir / "sandbox" / "smuggled.txt").write_text(
            "smuggled\n", encoding="utf-8")
        ex.execute_approved()
        evs = self._events(_sweep.SWEEP_FINDING_EVENT)
        self.assertTrue(any(e.get("path") == "smuggled.txt" for e in evs),
                        evs)

    def test_default_executor_does_not_sweep(self):
        ex = self._executor()
        (self.run_dir / "sandbox" / "smuggled.txt").write_text(
            "smuggled\n", encoding="utf-8")
        ex.execute_approved()
        self.assertEqual(self._events(_sweep.SWEEP_FINDING_EVENT), [])
        self.assertEqual(self._events(_sweep.SWEEP_COMPLETE_EVENT), [])

    def test_child_writes_covered_by_parent_sweep(self):
        # The child shares the parent's inventory by reference; a
        # parent-run sweep sees child-written files.
        ex = self._executor()
        ident = ex.mint_identity("coder-1", "coder", PRINCIPAL)
        r = ex.call(ident, "write_file", path="parent.txt",
                    content="parent\n")
        self.assertEqual(r.get("status"), "executed")
        (self.run_dir / "sandbox" / "child_side.txt").write_text(
            "child side channel\n", encoding="utf-8")
        findings = ex.run_artifact_sweep()
        paths = sorted(f["path"] for f in findings)
        self.assertEqual(paths, ["child_side.txt"])


if __name__ == "__main__":
    unittest.main()
