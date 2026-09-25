"""Packaging invariants: the wheel ships the full package plus the policy.

Drift guard: ``gov/data/default.yaml`` (the copy shipped inside the wheel
via package-data) must be byte-identical to the canonical
``policies/default.yaml``. There is exactly one default policy.

v1 ship sprint (Track 1) regression pins for the packaging-spike
defects:

* defect 1: ``gov-approve``'s default run directory resolves to a user
  run dir (cwd, then XDG user data) -- never inside the installed
  package (site-packages).
* defect 4: every console-script entry point honors ``--help``/``-h``.
  (argparse-based ones already did; the demo entry points ignored it
  and ran the demo.)
* defect 9: sequential demo-style runs in one directory -- each
  provisioning a fresh random HMAC key, as the demos do -- never
  collide on the egress ledger (each run's ledger is per-run).
* defect 6: ``gov.__version__`` is the single source of truth.
"""

import contextlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import approvals  # noqa: E402


class PackagingDriftTest(unittest.TestCase):
    def test_shipped_policy_is_byte_identical(self):
        canonical = REPO_ROOT / "policies" / "default.yaml"
        shipped = REPO_ROOT / "gov" / "data" / "default.yaml"
        self.assertTrue(canonical.is_file(), "missing canonical policy")
        self.assertTrue(
            shipped.is_file(),
            "gov/data/default.yaml missing: the wheel would ship no policy",
        )
        self.assertEqual(
            shipped.read_bytes(),
            canonical.read_bytes(),
            "gov/data/default.yaml drifted from policies/default.yaml: "
            "there is exactly one default policy",
        )

    def test_default_policy_path_resolves(self):
        from gov.policy import default_policy_path
        path = default_policy_path()
        self.assertTrue(
            Path(path).is_file(),
            "default_policy_path() does not resolve to a real file",
        )
        self.assertEqual(
            Path(path).read_bytes(),
            (REPO_ROOT / "policies" / "default.yaml").read_bytes(),
            "default_policy_path() must resolve to the canonical policy",
        )


class _Args:
    def __init__(self, rundir=None, latest=False):
        self.rundir = rundir
        self.latest = latest


@contextlib.contextmanager
def _chdir(path):
    prev = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(prev)


class TestApproveRundirResolution(unittest.TestCase):
    """Defect 1: the default run dir is a user dir, never site-packages."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="govpkg-rundir-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # Keep XDG out of the test unless the test sets it.
        self._old_xdg = os.environ.pop("XDG_DATA_HOME", None)
        self.addCleanup(self._restore_xdg)

    def _restore_xdg(self):
        if self._old_xdg is not None:
            os.environ["XDG_DATA_HOME"] = self._old_xdg
        else:
            os.environ.pop("XDG_DATA_HOME", None)

    def _make_run(self, root, name="demo-20260924-120000"):
        d = Path(root) / name
        d.mkdir(parents=True)
        return d

    def test_latest_prefers_cwd_runs(self):
        runs = Path(self.tmp) / "runs"
        want = self._make_run(runs)
        with _chdir(self.tmp):
            got = approvals._resolve_rundir(_Args(latest=True))
        self.assertEqual(got, want)

    def test_latest_never_inside_site_packages(self):
        runs = Path(self.tmp) / "runs"
        want = self._make_run(runs)
        with _chdir(self.tmp):
            got = approvals._resolve_rundir(_Args(latest=True))
        self.assertEqual(got, want)
        self.assertNotIn("site-packages", str(got))

    def test_latest_falls_back_to_xdg_data_home(self):
        xdg = Path(self.tmp) / "xdg"
        os.environ["XDG_DATA_HOME"] = str(xdg)
        want = self._make_run(xdg / "agent-governance" / "runs")
        empty_cwd = Path(self.tmp) / "empty"
        empty_cwd.mkdir()
        with _chdir(str(empty_cwd)):
            got = approvals._resolve_rundir(_Args(latest=True))
        self.assertEqual(got, want)

    def test_latest_no_runs_anywhere_fails_closed_helpfully(self):
        empty_cwd = Path(self.tmp) / "empty"
        empty_cwd.mkdir()
        os.environ["XDG_DATA_HOME"] = str(Path(self.tmp) / "xdg-empty")
        with _chdir(str(empty_cwd)):
            with self.assertRaises(SystemExit) as cm:
                approvals._resolve_rundir(_Args(latest=True))
        self.assertIn("--rundir", str(cm.exception))

    def test_explicit_rundir_wins(self):
        explicit = Path(self.tmp) / "somewhere-else"
        explicit.mkdir()
        with _chdir(self.tmp):
            got = approvals._resolve_rundir(
                _Args(rundir=str(explicit), latest=True))
        self.assertEqual(got, explicit)


class TestDemoEntryPointHelp(unittest.TestCase):
    """Defect 4: demo entry points honor --help/-h instead of running."""

    def _run_help(self, module_name, flag="--help"):
        mod = sys.modules.get(module_name)
        if mod is None:
            mod = __import__(module_name, fromlist=["main"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = mod.main([flag])
        return rc, buf.getvalue()

    def test_run_demo_help(self):
        rc, out = self._run_help("demo.run_demo")
        self.assertEqual(rc, 0)
        self.assertIn("usage", out.lower())

    def test_run_demo_help_short_flag(self):
        rc, out = self._run_help("demo.run_demo", "-h")
        self.assertEqual(rc, 0)
        self.assertIn("usage", out.lower())

    def test_attack_scenario_help(self):
        rc, out = self._run_help("demo.attack_scenario")
        self.assertEqual(rc, 0)
        self.assertIn("usage", out.lower())

    def _run_unknown(self, module_name):
        mod = sys.modules.get(module_name)
        if mod is None:
            mod = __import__(module_name, fromlist=["main"])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(["--bogus-flag"])
        return rc, out.getvalue(), err.getvalue()

    def test_run_demo_rejects_unknown_args(self):
        rc, out, err = self._run_unknown("demo.run_demo")
        self.assertEqual(rc, 2)
        self.assertIn("unknown", (out + err).lower())

    def test_attack_scenario_rejects_unknown_args(self):
        rc, out, err = self._run_unknown("demo.attack_scenario")
        self.assertEqual(rc, 2)
        self.assertIn("unknown", (out + err).lower())


class TestDemoLedgerIsolation(unittest.TestCase):
    """Defect 9: two real demo processes in one directory must not collide.

    Each ``gov-demo`` process provisions a fresh random HMAC key. Before
    the fix, both runs defaulted to the shared ``runs/egress_ledger.jsonl``
    and the second run failed closed (``LedgerUnverifiableError``) on the
    first run's entries. This test launches the ACTUAL demo entry point
    twice as separate processes (fresh keys, same cwd) and asserts both
    complete, land in distinct run directories, and leave no shared
    cross-run ledger behind.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="govpkg-ledger-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run_demo_subprocess(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH")}
        env["TMPDIR"] = self.tmp  # keep sandbox temp files contained
        # The child runs in an empty cwd (like a real user directory), so
        # give it the source tree explicitly; the demo itself then takes
        # over its own sys.path handling.
        env["PYTHONPATH"] = str(REPO_ROOT)
        return subprocess.run(
            [sys.executable, "-c",
             "from demo.run_demo import main; raise SystemExit(main())"],
            cwd=self.tmp, env=env, capture_output=True, text=True,
            timeout=300)

    def test_two_sequential_demo_processes_do_not_collide(self):
        for i in range(2):
            proc = self._run_demo_subprocess()
            self.assertEqual(
                proc.returncode, 0,
                "demo run %d failed (rc=%d):\n%s\n%s"
                % (i + 1, proc.returncode, proc.stdout[-2000:],
                   proc.stderr[-2000:]))
        runs = Path(self.tmp) / "runs"
        run_dirs = sorted(d for d in runs.iterdir() if d.is_dir())
        # Exactly two distinct run dirs: microsecond run ids never repeat.
        self.assertEqual(len(run_dirs), 2,
                         "expected 2 run dirs, got: %s" % run_dirs)
        # No shared cross-run ledger: each run carries its own.
        self.assertFalse((Path(self.tmp) / "runs" / "egress_ledger.jsonl")
                         .exists(),
                         "shared runs/egress_ledger.jsonl must not exist")
        for d in run_dirs:
            self.assertTrue((d / "egress_ledger.jsonl").exists(),
                            "per-run ledger missing in %s" % d)
            self.assertTrue((d / "actions.jsonl").exists(),
                            "actions log missing in %s" % d)


class TestSingleSourceVersion(unittest.TestCase):
    """Defect 6: gov.__version__ is the single source of truth."""

    def test_version_present_and_well_formed(self):
        import gov
        self.assertTrue(hasattr(gov, "__version__"))
        parts = gov.__version__.split(".")
        self.assertGreaterEqual(len(parts), 2)
        self.assertTrue(all(p[:1].isdigit() for p in parts))


if __name__ == "__main__":
    unittest.main()
