"""Tests for evals/green_check.py: the fail-closed green-check contract.

Red-first: these tests were written before the module existed.

Wave-305: the wave-303 merge dropped the entire module header of
evals/w302_redteam_probes.py (NameError on import), yet the inner green
checks of adjacent batteries passed it vacuously -- the allowlist form
counts "[BREAK]" lines, and a traceback emits none, so a broken child
read as "0 BREAK (all expected) / rest held". These tests pin the
contract: a broken dependency battery must fail the check loudly, never
pass as "0 BREAKs".
"""

import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))

import green_check


def _write(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(body))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, pid, verdict, note):
        self.calls.append((pid, verdict, note))


_HEALTHY_ZERO = """\
    import sys
    print("[HELD] probe-a: fine")
    print("child: 0 BREAK / 3 HELD / 0 ERROR")
    sys.exit(0)
    """

_EXPECTED_BREAKS = """\
    import sys
    print("  [BREAK] F999-foo: something expected-open")
    print("child: 1 BREAK / 2 HELD / 0 ERROR")
    sys.exit(1)
    """

# The w302 incident shape: module header (imports) missing, so the class
# body raises NameError at import time and no probe ever runs.
_BROKEN_HEADER = """\
    class BaseStateTest(unittest.TestCase):
        pass
    """

_NO_SUMMARY = """\
    import sys
    print("all good, nothing to report")
    sys.exit(0)
    """

_UNEXPECTED_BREAK = """\
    import sys
    print("  [BREAK] F998-bar: surprise regression")
    print("child: 1 BREAK / 2 HELD / 0 ERROR")
    sys.exit(1)
    """

_SPAWN_MARKER = """\
    import os, sys
    open(os.environ["GREEN_CHECK_MARKER"], "w").write("spawned")
    print("child: 0 BREAK / 0 HELD / 0 ERROR")
    sys.exit(0)
    """

_PASSING_SUITE = """\
    import unittest


    class T(unittest.TestCase):
        def test_ok(self):
            self.assertTrue(True)


    if __name__ == "__main__":
        unittest.main()
    """

# A unittest-style battery child: no N BREAK / M HELD / K ERROR summary,
# just "Ran N tests" + OK.
_UNITTEST_CHILD = """\
    import unittest


    class T(unittest.TestCase):
        def test_ok(self):
            self.assertTrue(True)


    if __name__ == "__main__":
        unittest.main(verbosity=0)
    """

# A child that prints a summary claiming zero probes ran: the vacuous
# sibling of the w302 incident (emptied probe list, early return).
_VACUOUS_ZERO = """\
    import sys
    print("child: 0 BREAK / 0 HELD / 0 ERROR")
    sys.exit(0)
    """

# A child whose probes errored: the process survived, but the
# dependency did not verify cleanly.
_PROBE_ERRORS = """\
    import sys
    print("  [HELD] probe-a: fine")
    print("  [HELD] probe-b: fine")
    print("  [ERROR] probe-c: crashed")
    print("child: 0 BREAK / 2 HELD / 1 ERROR")
    sys.exit(0)
    """

# w302-style all-HELD shape: summary only, no per-probe lines, but a
# non-zero total -- legitimate, must stay HELD.
_SUMMARY_ONLY_NONZERO = """\
    import sys
    print("child: 0 BREAK / 3 HELD / 0 ERROR")
    sys.exit(0)
    """

_ZERO_TESTS_CHILD = """\
    import sys
    print("Ran 0 tests in 0.000s")
    print()
    print("OK")
    sys.exit(0)
    """


def _old_vacuous_green(record, label, child_path, expect_break_ids=()):
    """The pre-wave-305 allowlist form (w303_redteam_probes._green):
    counts [BREAK] lines only. Kept here to pin the hole it left -- a
    traceback emits no [BREAK] lines, so a broken child read as
    "0 BREAK (all expected) / rest held"."""
    proc = subprocess.run([sys.executable, child_path],
                          capture_output=True, text=True, timeout=60)
    out = proc.stdout + proc.stderr
    breaks = re.findall(r"\[BREAK\] ([A-Za-z0-9_.\-]+)", out)
    unexpected = [b for b in breaks if b not in expect_break_ids]
    if unexpected:
        record(label, "BREAK", "unexpected BREAKs %r" % (unexpected,))
    else:
        record(label, "HELD",
               "%d BREAK (all expected) / rest held" % len(breaks))


class GreenCheckContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="green-contract-test-")
        self.rec = _Recorder()
        self._old_env = os.environ.get("GOV_SKIP_GREEN")

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("GOV_SKIP_GREEN", None)
        else:
            os.environ["GOV_SKIP_GREEN"] = self._old_env

    def _child(self, name, body):
        path = os.path.join(self.tmp, name)
        _write(path, body)
        return path

    def test_old_form_passes_broken_child_vacuously(self):
        # Characterization of the w302 incident: the old allowlist form
        # records HELD for a child that never ran its probes.
        child = self._child("broken_header.py", _BROKEN_HEADER)
        _old_vacuous_green(self.rec, "green-x", child)
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_broken_child_fails_closed_not_held(self):
        # The contract: a traceback with no summary is a CHECK FAILURE.
        child = self._child("broken_header.py", _BROKEN_HEADER)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        self.assertEqual(len(self.rec.calls), 1)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "ERROR")
        self.assertIn("raceback", note)

    def test_missing_summary_fails_closed(self):
        # Exit 0 but no parseable summary line: the child did not run
        # its probes. CHECK FAILURE, not HELD.
        child = self._child("no_summary.py", _NO_SUMMARY)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        self.assertEqual(self.rec.calls[0][1], "ERROR")

    def test_healthy_zero_breaks_held(self):
        child = self._child("healthy_zero.py", _HEALTHY_ZERO)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_expected_breaks_held(self):
        # A child with expected-open BREAKs exits 1 legitimately; the
        # allowlist still holds as long as the summary is parseable.
        child = self._child("expected_breaks.py", _EXPECTED_BREAKS)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp,
                                  expect_break_ids=("F999-foo",))
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_unexpected_breaks_break(self):
        child = self._child("unexpected_break.py", _UNEXPECTED_BREAK)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp,
                                  expect_break_ids=("F999-foo",))
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "BREAK")
        self.assertIn("F998-bar", note)

    def test_exact_summary_form_held(self):
        child = self._child("healthy_zero.py", _HEALTHY_ZERO)
        green_check.check_battery(
            self.rec, "green-x", child, repo=self.tmp,
            expected_summary="child: 0 BREAK / 3 HELD / 0 ERROR")
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_exact_summary_form_break_on_drift(self):
        child = self._child("healthy_zero.py", _HEALTHY_ZERO)
        green_check.check_battery(
            self.rec, "green-x", child, repo=self.tmp,
            expected_summary="child: 0 BREAK / 99 HELD / 0 ERROR")
        self.assertEqual(self.rec.calls[0][1], "BREAK")

    def test_skip_var_records_skip_without_spawning(self):
        # GOV_SKIP_GREEN=1: record a skipped note, do NOT spawn the
        # child. A skip is not a pass.
        os.environ["GOV_SKIP_GREEN"] = "1"
        marker = os.path.join(self.tmp, "spawned.marker")
        os.environ["GREEN_CHECK_MARKER"] = marker
        try:
            child = self._child("spawn_marker.py", _SPAWN_MARKER)
            green_check.check_battery(self.rec, "green-x", child,
                                      repo=self.tmp)
        finally:
            os.environ.pop("GREEN_CHECK_MARKER", None)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "HELD")
        self.assertIn("skip", note.lower())
        self.assertFalse(os.path.exists(marker),
                         "child must not be spawned under GOV_SKIP_GREEN=1")

    def test_unittest_missing_suite_fails_closed(self):
        # A missing adjacent suite is a broken tree, not a pass.
        green_check.check_unittest(self.rec, "green-x",
                                   "tests/test_no_such_suite.py",
                                   repo=self.tmp)
        self.assertEqual(self.rec.calls[0][1], "ERROR")

    def test_unittest_style_battery_child_held(self):
        # unittest-style battery children (no N BREAK summary, just
        # "Ran N tests" + OK) are healthy, not broken.
        child = self._child("unittest_child.py", _UNITTEST_CHILD)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "HELD")
        self.assertIn("unittest", note)

    def test_unittest_passing_suite_held(self):
        suite = self._child("test_synthetic_ok.py", _PASSING_SUITE)
        green_check.check_unittest(self.rec, "green-x", suite,
                                   repo=self.tmp)
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_vacuous_zero_summary_fails_closed(self):
        # Wave-307: a summary claiming zero probes ran is not evidence
        # of anything -- an emptied probe list must not read as green.
        child = self._child("vacuous_zero.py", _VACUOUS_ZERO)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "ERROR")
        self.assertIn("vacuous", note)

    def test_summary_with_probe_errors_fails_closed(self):
        # Wave-307: probe ERRORs mean the dependency did not verify
        # cleanly -- crashed probes are not green, even with zero
        # BREAKs.
        child = self._child("probe_errors.py", _PROBE_ERRORS)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "ERROR")
        self.assertIn("1 probe", note)

    def test_summary_only_nonzero_total_stays_held(self):
        # The w302 all-HELD shape (summary only, no per-probe lines)
        # with a non-zero total is legitimate and must stay HELD --
        # the non-vacuity rule must not over-tighten.
        child = self._child("summary_only.py", _SUMMARY_ONLY_NONZERO)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        self.assertEqual(self.rec.calls[0][1], "HELD")

    def test_unittest_zero_tests_fails_closed(self):
        # Wave-307: "Ran 0 tests" + OK ran nothing -- vacuous, not
        # green.
        child = self._child("zero_tests.py", _ZERO_TESTS_CHILD)
        green_check.check_battery(self.rec, "green-x", child,
                                  repo=self.tmp)
        pid, verdict, note = self.rec.calls[0]
        self.assertEqual(verdict, "ERROR")


if __name__ == "__main__":
    unittest.main()
