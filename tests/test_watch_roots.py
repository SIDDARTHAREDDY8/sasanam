#!/usr/bin/env python3
"""Unit tests for the wave-136 watch-root extension (gov/artifact_sweep.py).

Covers: register_watch_root snapshotting (own-inventory baseline,
symlink skipping, fail-closed refusals for / and $HOME and
non-directories), sweep_run_dir watch_roots= wiring (findings carry
the root, per-root stats, overlap rejections against the run sandbox
and between roots, bad entry shapes), and the executor opt-in
(True vs {"watch_roots": [...]} vs None/False).
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
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "watch-root-unittest")

from gov import artifact_sweep as _sweep  # noqa: E402
from gov.artifacts import ArtifactInventory  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"
PRINCIPAL = "user-1"

_UNGOVERNED_ACK = ("watch-root unittest: synthetic harness; raw "
                   "pre-wave-74/75 pipeline by design, declared and "
                   "chained")


def _mk_run_dir():
    run_dir = Path(tempfile.mkdtemp(prefix="watchroottest-"))
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    return run_dir


def _mk_root(files=()):
    root = Path(tempfile.mkdtemp(prefix="watchroot-data-"))
    for rel, data in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return root


def _mk_executor(run_dir, **kw):
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    return ToolExecutor(run_dir, policy, log, approvals,
                        ledger_path=run_dir / "egress_ledger.jsonl",
                        ungoverned_ack=_UNGOVERNED_ACK, **kw)


class TestRegisterWatchRoot(unittest.TestCase):
    def test_snapshot_registers_every_file(self):
        root = _mk_root([("a.txt", b"hello"), ("sub/b.txt", b"world")])
        inv = _sweep.register_watch_root(str(root), ArtifactInventory(),
                                         agent_id="op", run_id="base")
        self.assertIsNotNone(inv.lookup("a.txt"))
        self.assertIsNotNone(inv.lookup("sub/b.txt"))
        self.assertIsNone(inv.lookup("nope.txt"))
        rec = inv.lookup("a.txt")
        self.assertEqual(rec.sha256, hashlib.sha256(b"hello").hexdigest())

    def test_returns_the_inventory(self):
        root = _mk_root()
        inv = ArtifactInventory()
        self.assertIs(_sweep.register_watch_root(str(root), inv), inv)

    def test_slash_refused(self):
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root("/", ArtifactInventory())

    def test_home_refused(self):
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root(os.path.expanduser("~"),
                                       ArtifactInventory())

    def test_nonexistent_refused(self):
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root("/tmp/definitely-not-here-xyz-123",
                                       ArtifactInventory())

    def test_file_not_dir_refused(self):
        root = _mk_root([("f.txt", b"x")])
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root(str(root / "f.txt"),
                                       ArtifactInventory())

    def test_symlink_to_slash_refused(self):
        # A symlink pointing at / resolves to / and is still refused.
        link = Path(tempfile.mkdtemp(prefix="watchroot-link-")) / "lnk"
        os.symlink("/", str(link))
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root(str(link), ArtifactInventory())

    def test_symlinks_inside_root_not_followed(self):
        root = _mk_root([("real.txt", b"data")])
        outside = Path(tempfile.mkdtemp(prefix="watchroot-out-"))
        (outside / "secret.txt").write_bytes(b"secret")
        os.symlink(str(outside / "secret.txt"), str(root / "evil.txt"))
        inv = _sweep.register_watch_root(str(root), ArtifactInventory())
        self.assertIsNone(inv.lookup("evil.txt"))
        self.assertIsNotNone(inv.lookup("real.txt"))

    def test_non_inventory_rejected(self):
        root = _mk_root()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.register_watch_root(str(root), {"not": "inventory"})


class TestSweepWatchRoots(unittest.TestCase):
    def test_unregistered_file_flagged_with_root(self):
        run_dir = _mk_run_dir()
        root = _mk_root()
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        (root / "smuggled.bin").write_bytes(b"SMUGGLED")
        findings, stats = _sweep.sweep_run_dir(
            str(run_dir), ArtifactInventory(),
            watch_roots=[(str(root), baseline)])
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["kind"], _sweep.NEVER_REGISTERED)
        self.assertEqual(f["path"], "smuggled.bin")
        self.assertEqual(f["root"], os.path.realpath(str(root)))
        self.assertEqual(len(stats["watch_roots"]), 1)
        self.assertEqual(stats["watch_roots"][0]["findings"], 1)

    def test_baseline_file_clean(self):
        run_dir = _mk_run_dir()
        root = _mk_root([("keep.txt", b"baseline")])
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        findings, _ = _sweep.sweep_run_dir(
            str(run_dir), ArtifactInventory(),
            watch_roots=[(str(root), baseline)])
        self.assertEqual(findings, [])

    def test_tampered_file_integrity_violation(self):
        run_dir = _mk_run_dir()
        root = _mk_root([("keep.txt", b"baseline")])
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        (root / "keep.txt").write_bytes(b"baseline TAMPERED")
        findings, _ = _sweep.sweep_run_dir(
            str(run_dir), ArtifactInventory(),
            watch_roots=[(str(root), baseline)])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], _sweep.INTEGRITY_VIOLATION)
        self.assertIn("registered_sha256", findings[0])

    def test_no_watch_roots_default_silent(self):
        run_dir = _mk_run_dir()
        root = _mk_root()
        (root / "smuggled.bin").write_bytes(b"SMUGGLED")
        findings, stats = _sweep.sweep_run_dir(str(run_dir),
                                              ArtifactInventory())
        self.assertEqual(findings, [])
        self.assertEqual(stats["watch_roots"], [])

    def test_run_dir_overlap_rejected(self):
        run_dir = _mk_run_dir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(str(run_dir), ArtifactInventory(),
                                 watch_roots=[(str(run_dir),
                                               ArtifactInventory())])

    def test_sandbox_overlap_rejected(self):
        run_dir = _mk_run_dir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(
                str(run_dir), ArtifactInventory(),
                watch_roots=[(str(run_dir / "sandbox"),
                              ArtifactInventory())])

    def test_ancestor_of_run_dir_rejected(self):
        run_dir = _mk_run_dir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(
                str(run_dir), ArtifactInventory(),
                watch_roots=[(str(run_dir.parent), ArtifactInventory())])

    def test_overlapping_watch_roots_rejected(self):
        run_dir = _mk_run_dir()
        root = _mk_root()
        sub = root / "sub"
        sub.mkdir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(
                str(run_dir), ArtifactInventory(),
                watch_roots=[(str(root), ArtifactInventory()),
                             (str(sub), ArtifactInventory())])

    def test_slash_watch_root_rejected_at_sweep(self):
        run_dir = _mk_run_dir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(str(run_dir), ArtifactInventory(),
                                 watch_roots=[("/", ArtifactInventory())])

    def test_bad_entry_shape_rejected(self):
        run_dir = _mk_run_dir()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(str(run_dir), ArtifactInventory(),
                                 watch_roots=["not-a-tuple"])

    def test_non_inventory_baseline_rejected(self):
        run_dir = _mk_run_dir()
        root = _mk_root()
        with self.assertRaises(_sweep.WatchRootError):
            _sweep.sweep_run_dir(str(run_dir), ArtifactInventory(),
                                 watch_roots=[(str(root), {})])

    def test_sandbox_and_watch_root_combined(self):
        # Findings from both trees are returned together, each tagged
        # with its own root.
        run_dir = _mk_run_dir()
        (run_dir / "sandbox" / "side.bin").write_bytes(b"SIDE")
        root = _mk_root()
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        (root / "w.bin").write_bytes(b"W")
        findings, stats = _sweep.sweep_run_dir(
            str(run_dir), ArtifactInventory(),
            watch_roots=[(str(root), baseline)])
        by_path = {f["path"]: f for f in findings}
        self.assertEqual(set(by_path), {"side.bin", "w.bin"})
        self.assertEqual(
            by_path["side.bin"]["root"],
            os.path.realpath(str(run_dir / "sandbox")))
        self.assertEqual(by_path["w.bin"]["root"],
                         os.path.realpath(str(root)))
        self.assertEqual(stats["findings"], 2)


class TestExecutorWiring(unittest.TestCase):
    def _findings(self, run_dir):
        return [e for e in read_entries(run_dir / "actions.jsonl")
                if isinstance(e, dict)
                and e.get("event") == _sweep.SWEEP_FINDING_EVENT]

    def test_dict_optin_sweeps_watch_roots_loud(self):
        run_dir = _mk_run_dir()
        root = _mk_root([("keep.txt", b"v1")])
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        (root / "w.bin").write_bytes(b"W")
        (root / "keep.txt").write_bytes(b"v2 TAMPERED")
        ex = _mk_executor(run_dir, artifact_sweep={"watch_roots": [
            (str(root), baseline)]})
        findings = ex.run_artifact_sweep()
        self.assertEqual(len(findings), 2)
        evs = self._findings(run_dir)
        by_path = {e["path"]: e for e in evs}
        self.assertTrue("w.bin" in by_path
                        and by_path["w.bin"]["root"]
                        == os.path.realpath(str(root)))
        # The LOUD audit record for an integrity_violation keeps the
        # registered hash: evidence of what the bytes changed FROM.
        self.assertEqual(
            by_path["keep.txt"]["registered_sha256"],
            hashlib.sha256(b"v1").hexdigest())

    def test_true_optin_unchanged(self):
        run_dir = _mk_run_dir()
        (run_dir / "sandbox" / "s.bin").write_bytes(b"S")
        ex = _mk_executor(run_dir, artifact_sweep=True)
        findings = ex.run_artifact_sweep()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["path"], "s.bin")

    def test_false_optin_no_sweep(self):
        run_dir = _mk_run_dir()
        (run_dir / "sandbox" / "s.bin").write_bytes(b"S")
        ex = _mk_executor(run_dir, artifact_sweep=False)
        ex.execute_approved()
        self.assertEqual(self._findings(run_dir), [])

    def test_none_optin_no_sweep(self):
        run_dir = _mk_run_dir()
        (run_dir / "sandbox" / "s.bin").write_bytes(b"S")
        ex = _mk_executor(run_dir)
        ex.execute_approved()
        self.assertEqual(self._findings(run_dir), [])

    def test_bad_watch_root_audited_not_raised(self):
        # A misconfigured watch root fails closed at sweep time: the
        # sweep is audited as failed, never fatal to the run.
        run_dir = _mk_run_dir()
        ex = _mk_executor(run_dir, artifact_sweep={"watch_roots": [
            ("/", ArtifactInventory())]})
        findings = ex.run_artifact_sweep()
        self.assertEqual(findings, [])
        failed = [e for e in read_entries(run_dir / "actions.jsonl")
                  if isinstance(e, dict)
                  and e.get("event") == "artifact_sweep_failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("refused", failed[0]["reason"])

    def test_complete_event_lists_watch_roots(self):
        run_dir = _mk_run_dir()
        root = _mk_root()
        baseline = _sweep.register_watch_root(str(root),
                                              ArtifactInventory())
        ex = _mk_executor(run_dir, artifact_sweep={"watch_roots": [
            (str(root), baseline)]})
        ex.run_artifact_sweep()
        comp = [e for e in read_entries(run_dir / "actions.jsonl")
                if isinstance(e, dict)
                and e.get("event") == _sweep.SWEEP_COMPLETE_EVENT]
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0]["watch_roots"],
                         [os.path.realpath(str(root))])


if __name__ == "__main__":
    unittest.main()
