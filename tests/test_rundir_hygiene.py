"""Wave-24 run-dir hygiene tests.

Wave-23 found the suite leaking run dirs under TMPDIR (~10.5k
govred-*/govdur-* dirs filled the 512MB /tmp tmpfs -> Errno 28
failures). These tests pin the cleanup discipline:

1. tests/harness.make_run registers every run dir and
   cleanup_run_dirs() removes them (best-effort, with the safety
   guards); GOV_KEEP_RUN_DIRS=1 retains them for debugging.
2. The /proc liveness guard vetoes removal of a dir another live
   process still has open.
3. A small eval batch (evals/run_evals.run_cell) leaves no new
   directories under TMPDIR afterwards (per-cell registry + sweep
   backstop from the F65 fix).
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import harness


def _tmpdir_dirs():
    tmp = os.path.realpath(tempfile.gettempdir())
    return set(os.listdir(tmp)), tmp


class TestHarnessRegistryCleanup(unittest.TestCase):
    def tearDown(self):
        # Never leak from this test module itself, even on failure.
        harness.cleanup_run_dirs(success=True)

    def test_cleanup_removes_registered_run_dirs(self):
        ctx = harness.make_run()
        run_dir = os.path.realpath(str(ctx["run_dir"]))
        self.assertTrue(os.path.isdir(run_dir))
        self.assertIn(run_dir, harness._RUN_DIR_REGISTRY)
        stats = harness.cleanup_run_dirs(success=True)
        self.assertFalse(os.path.exists(run_dir),
                         "run dir not removed by cleanup_run_dirs")
        self.assertNotIn(run_dir, harness._RUN_DIR_REGISTRY)
        self.assertGreaterEqual(stats["removed"], 1)
        self.assertEqual(stats["errors"], 0)

    def test_keep_env_retains_run_dirs(self):
        with mock.patch.dict(os.environ, {"GOV_KEEP_RUN_DIRS": "1"}):
            ctx = harness.make_run()
            run_dir = os.path.realpath(str(ctx["run_dir"]))
            stats = harness.cleanup_run_dirs(success=True)
            self.assertTrue(os.path.isdir(run_dir),
                            "GOV_KEEP_RUN_DIRS=1 must retain run dirs")
            self.assertGreaterEqual(stats["retained"], 1)
            # manual cleanup: the env asked to keep, the test still must
            # not leak.
            shutil.rmtree(run_dir, ignore_errors=True)
            harness._RUN_DIR_REGISTRY[:] = [
                p for p in harness._RUN_DIR_REGISTRY if p != run_dir]

    def test_red_suite_retains_unless_forced(self):
        ctx = harness.make_run()
        run_dir = os.path.realpath(str(ctx["run_dir"]))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GOV_KEEP_RUN_DIRS", None)
            stats = harness.cleanup_run_dirs(success=False)
            self.assertTrue(os.path.isdir(run_dir),
                            "red suite should retain dirs for debugging")
            self.assertGreaterEqual(stats["retained"], 1)
        with mock.patch.dict(os.environ, {"GOV_KEEP_RUN_DIRS": "0"}):
            harness.cleanup_run_dirs(success=False)
            self.assertFalse(os.path.exists(run_dir),
                             "GOV_KEEP_RUN_DIRS=0 must force cleanup on red")

    def test_liveness_guard_keeps_live_dir(self):
        ctx = harness.make_run()
        run_dir = os.path.realpath(str(ctx["run_dir"]))
        # Hold an open fd under the run dir from ANOTHER live process.
        proc = subprocess.Popen(
            [sys.executable, "-c",
             "import time; f = open(%r, 'w'); f.write('x'); f.flush(); "
             "time.sleep(30)" % os.path.join(run_dir, "held.txt")])
        try:
            # Wait until the child has actually opened the fd (no race:
            # poll the guard itself, which is what cleanup uses).
            import time as _time
            deadline = _time.time() + 10
            while not harness._dir_in_use_by_live_process(run_dir):
                if proc.poll() is not None:
                    self.fail("holder child exited before opening the fd")
                if _time.time() > deadline:
                    self.fail("holder child did not open the fd in time")
                _time.sleep(0.05)
            stats = harness.cleanup_run_dirs(success=True)
            self.assertTrue(os.path.isdir(run_dir),
                            "dir in use by a live process must be kept")
            self.assertGreaterEqual(stats["kept_in_use"], 1)
            self.assertIn(run_dir, harness._RUN_DIR_REGISTRY)
        finally:
            proc.terminate()
            proc.wait(timeout=10)
        stats = harness.cleanup_run_dirs(success=True)
        self.assertFalse(os.path.exists(run_dir),
                         "dir should be removed once no live process "
                         "holds it")
        self.assertGreaterEqual(stats["removed"], 1)


class TestEvalBatchHygiene(unittest.TestCase):
    def test_small_eval_batch_leaves_no_tmpdirs(self):
        # Local import: evals.run_evals is heavy; the canonical suite
        # already imports it (test_adversary_matrix), so this adds no
        # new import cost to a full run.
        from evals import run_evals
        before, tmp = _tmpdir_dirs()
        # Two cheap cells (sit1, decorator harness): exercises the
        # per-cell registry + _sweep_new_tmpdirs backstop across runs.
        for priv in ("low", "standard"):
            run_evals.run_cell("sit1", "decorator", priv, "provisional")
        after, _ = _tmpdir_dirs()
        leaked = sorted(after - before)
        self.assertEqual(
            leaked, [],
            "eval batch leaked %d tmpdir(s) under %s: %s"
            % (len(leaked), tmp, leaked[:10]))


if __name__ == "__main__":
    unittest.main()
