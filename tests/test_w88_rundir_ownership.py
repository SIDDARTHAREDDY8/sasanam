"""Wave-88: PID-stamped run-dir ownership vs the tmpdir sweeps.

Regression pins for the wave-87 flaky FileNotFoundError on
``govred-*/approvals.jsonl``.

Traced mechanism: the suite's tmpdir sweeps
(``tests/harness._safe_remove_run_dir`` via ``cleanup_run_dirs`` /
``run_tests.py``'s backstop, and
``evals/run_evals._sweep_new_tmpdirs``) removed run dirs whose liveness
they could not see -- ``_dir_in_use_by_live_process`` only vetoes OTHER
pids holding an OPEN FD at the scan instant, and a test between file
operations holds no fd at all. A concurrent gate's sweep removing the
dir between a test's ``exists()`` and ``open()`` on approvals.jsonl
raised FileNotFoundError out of the test.

Fix (by construction, not caught-and-swallowed): every make_run() dir
carries a ``.gov-owner-<pid>`` marker; every sweep skips dirs owned by
a LIVE other pid. Own dirs (our pid) and dead-owner dirs are still
finalized, so suite-end hygiene is unchanged.

Intentional boundary (pinned by the R2 diagnostic, not by a test
here): ``cleanup_run_dirs`` finalizes the CALLING process's own
registered dirs unconditionally -- the own-pid exclusion in the fd
liveness guard is load-bearing for suite-end cleanup (wave-23's
Errno-28 leak). In-process threads must be joined by their test before
any sweep; cross-process dirs are what the markers protect.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

from tests import harness


def _fresh_stats():
    return {"removed": 0, "kept_in_use": 0, "kept_outside_tmp": 0,
            "kept_missing": 0, "errors": 0, "retained": 0,
            "registered": 0, "kept_foreign_owned": 0}


def _make_marked_dir(owner_pid):
    """A govred-style dir carrying a .gov-owner-<owner_pid> marker.

    Not registered (foreign to this process); the caller must clean it.
    """
    d = tempfile.mkdtemp(prefix="govred-w88t-")
    (pathlib.Path(d) / (".gov-owner-%d" % owner_pid)).touch()
    return d


class TestOwnerMarker(unittest.TestCase):
    def test_make_run_writes_owner_marker(self):
        ctx = harness.make_run()
        try:
            marker = (pathlib.Path(str(ctx["run_dir"]))
                      / (".gov-owner-%d" % os.getpid()))
            self.assertTrue(marker.is_file(),
                            "make_run must stamp a PID ownership marker")
        finally:
            harness.cleanup_run_dirs(success=True)

    def test_safe_remove_still_removes_own_dir(self):
        # No behavior change for the common case: our own dirs (our pid
        # in the marker, or the registry sweep) are still finalized.
        ctx = harness.make_run()
        run_dir = os.path.realpath(str(ctx["run_dir"]))
        stats = _fresh_stats()
        try:
            self.assertTrue(harness._safe_remove_run_dir(run_dir, stats))
            self.assertFalse(os.path.exists(run_dir))
            self.assertEqual(stats["removed"], 1)
            self.assertEqual(stats["kept_foreign_owned"], 0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
            harness._RUN_DIR_REGISTRY[:] = [
                p for p in harness._RUN_DIR_REGISTRY if p != run_dir]

    def test_unmarked_dir_still_swept(self):
        # Backwards compat: dirs without any marker keep the old
        # behavior (e.g. probe-internal scratch the marker never saw).
        d = tempfile.mkdtemp(prefix="govred-w88t-")
        stats = _fresh_stats()
        try:
            self.assertTrue(harness._safe_remove_run_dir(d, stats))
            self.assertFalse(os.path.exists(d))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_marker_failure_is_fatal(self):
        # Fail-hard: if the ownership marker cannot be created,
        # make_run() must not hand out an unprotected dir — the fresh
        # dir is removed and construction raises.
        from unittest import mock
        real_touch = pathlib.Path.touch

        def flaky_touch(self, *a, **k):
            if os.path.basename(str(self)).startswith(".gov-owner-"):
                raise OSError(28, "No space left on device")
            return real_touch(self, *a, **k)

        before = set(harness._RUN_DIR_REGISTRY)
        import glob
        tmpdir = os.path.realpath(tempfile.gettempdir())
        before_dirs = set(glob.glob(os.path.join(tmpdir, "govred-*")))
        with mock.patch.object(pathlib.Path, "touch", flaky_touch):
            with self.assertRaises(OSError):
                harness.make_run()
        after = set(harness._RUN_DIR_REGISTRY)
        self.assertEqual(before, after,
                         "failed make_run must not register the dir")
        self.assertEqual(
            before_dirs, set(glob.glob(os.path.join(tmpdir, "govred-*"))),
            "failed make_run must remove the unmarked fresh dir")


class TestForeignOwnership(unittest.TestCase):
    def test_pid_alive(self):
        self.assertTrue(harness._pid_alive(os.getpid()))
        self.assertFalse(harness._pid_alive(2 ** 30))  # implausible pid
        proc = subprocess.Popen(
            [sys.executable, "-c", "pass"])
        try:
            self.assertTrue(harness._pid_alive(proc.pid))
        finally:
            proc.wait(timeout=30)
        self.assertFalse(harness._pid_alive(proc.pid),
                         "reaped child pid must read dead")

    def test_sweep_skips_live_foreign_owned_dir(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"])
        d = _make_marked_dir(proc.pid)
        try:
            self.assertTrue(harness._pid_alive(proc.pid))
            self.assertTrue(
                harness.dir_owned_by_live_other_process(d))
            stats = _fresh_stats()
            self.assertFalse(
                harness._safe_remove_run_dir(d, stats),
                "sweep must skip a dir owned by a live other process")
            self.assertTrue(os.path.isdir(d),
                            "live foreign-owned dir must survive the sweep")
            self.assertEqual(stats["kept_foreign_owned"], 1)
            self.assertEqual(stats["removed"], 0)
        finally:
            proc.terminate()
            proc.wait(timeout=30)
            # Dead owner: the stale marker must not leak the dir.
            stats = _fresh_stats()
            self.assertTrue(harness._safe_remove_run_dir(d, stats),
                            "dead-owner dir must still be swept (no leak)")
            self.assertFalse(os.path.exists(d))
            self.assertEqual(stats["removed"], 1)

    def test_sweep_removes_dead_foreign_owned_dir(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait(timeout=30)
        d = _make_marked_dir(proc.pid)
        try:
            self.assertFalse(harness._pid_alive(proc.pid))
            self.assertFalse(
                harness.dir_owned_by_live_other_process(d))
            stats = _fresh_stats()
            self.assertTrue(harness._safe_remove_run_dir(d, stats))
            self.assertFalse(os.path.exists(d))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestCellSweepOwnership(unittest.TestCase):
    def test_sweep_new_tmpdirs_skips_live_foreign(self):
        from evals import run_evals
        tmpdir = os.path.realpath(tempfile.gettempdir())
        before = set(os.listdir(tmpdir))  # snapshot BEFORE our dirs
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"])
        live_d = _make_marked_dir(proc.pid)
        dead_proc = subprocess.Popen([sys.executable, "-c", "pass"])
        dead_proc.wait(timeout=30)
        dead_d = _make_marked_dir(dead_proc.pid)
        try:
            run_evals._sweep_new_tmpdirs(tmpdir, before)
            self.assertTrue(
                os.path.isdir(live_d),
                "cell sweep must skip live foreign-owned dirs")
            self.assertFalse(
                os.path.exists(dead_d),
                "cell sweep must still remove dead-owner dirs")
        finally:
            proc.terminate()
            proc.wait(timeout=30)
            shutil.rmtree(live_d, ignore_errors=True)
            shutil.rmtree(dead_d, ignore_errors=True)


class TestCrossProcessFlakePinned(unittest.TestCase):
    """The wave-87 flake, deterministically: a foreign process's sweep
    racing ApprovalQueue.all() between exists() and read_bytes().

    Pre-fix this test fails (foreign sweep removes the dir;
    FileNotFoundError escapes). Post-fix the sweep is structurally
    unable to remove the live-owned dir.
    """

    def test_foreign_sweep_cannot_remove_live_dir_mid_read(self):
        ctx = harness.make_run()
        q = ctx["approvals"]
        ident = ctx["identities"]["support"]
        res = ctx["executor"].call(
            ident, "send_email", to="victim@synthetic.local", subject="s",
            body="b", justification="routine vendor invoice")
        self.assertEqual(res["status"], "queued", res)
        target = str(q.path)
        run_dir = os.path.realpath(str(ctx["run_dir"]))

        real_exists = pathlib.Path.exists
        parked = threading.Event()
        released = threading.Event()
        state = {"armed": True, "reader_tid": None}
        outcome = {}

        def evil_exists(self):
            r = real_exists(self)
            if (state["armed"] and state["reader_tid"] is not None
                    and threading.get_ident() == state["reader_tid"]
                    and str(self) == target and r):
                state["armed"] = False  # park exactly once
                parked.set()
                released.wait(60)
            return r

        child_code = (
            "import sys, os, json, tempfile; "
            "sys.path.insert(0, %r); " % os.path.dirname(
                os.path.dirname(os.path.abspath(harness.__file__))) +
            "sys.path.insert(0, os.path.join(sys.path[0], 'tests')); "
            "from tests import harness as h; "
            "s = {'removed': 0, 'kept_in_use': 0, 'kept_outside_tmp': 0, "
            "'kept_missing': 0, 'errors': 0, 'retained': 0, "
            "'registered': 0, 'kept_foreign_owned': 0}; "
            "ok = h._safe_remove_run_dir(sys.argv[1], s); "
            "print(json.dumps({'removed': ok, 'stats': s}))"
        )

        def reader():
            state["reader_tid"] = threading.get_ident()
            try:
                outcome["records"] = len(q.all())
            except FileNotFoundError as e:
                outcome["FileNotFoundError"] = str(e)

        pathlib.Path.exists = evil_exists
        t = threading.Thread(target=reader)
        try:
            t.start()
            self.assertTrue(parked.wait(60),
                            "reader never parked inside all()")
            # The foreign gate: a REAL separate process running the
            # REAL sweep function on our live run dir.
            proc = subprocess.run(
                [sys.executable, "-c", child_code, run_dir],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            sweep = json.loads(proc.stdout.strip().splitlines()[-1])
            outcome["foreign_removed"] = sweep["removed"]
            outcome["kept_foreign_owned"] = (
                sweep["stats"]["kept_foreign_owned"])
            released.set()
            t.join(60)
            self.assertFalse(t.is_alive(), "reader thread hung")
        finally:
            pathlib.Path.exists = real_exists
            shutil.rmtree(run_dir, ignore_errors=True)
            harness._RUN_DIR_REGISTRY[:] = [
                p for p in harness._RUN_DIR_REGISTRY if p != run_dir]

        self.assertNotIn("FileNotFoundError", outcome,
                         "foreign sweep removed a live run dir mid-read: %s"
                         % outcome.get("FileNotFoundError"))
        self.assertFalse(outcome.get("foreign_removed"),
                         "foreign sweep must skip live-owned dirs")
        self.assertEqual(outcome.get("kept_foreign_owned"), 1)
        self.assertEqual(outcome.get("records"), 1,
                         "the queued read must complete")


if __name__ == "__main__":
    unittest.main()
