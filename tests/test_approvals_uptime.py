"""Fresh-boot regression tests for the F76 approvals uptime fix.

F76 (MEDIUM): ``_reconcile_marker_invalid_coalesced`` (R17 F71b
coalescing) in gov/approvals.py suppressed repeat
``reconciliation_marker_invalid`` audits within a 300s window using
``time.monotonic()``, with ``last_audit = 0.0`` as the "never
audited" sentinel. On a freshly-booted machine (uptime < 300s),
``now - 0.0 < 300.0`` is True, so the FIRST loud audit was wrongly
suppressed into the counter. The fix uses ``last_audit = None`` as
the never-audited sentinel and skips suppression when
``last_audit is None``. No behavior change on machines with uptime
> 300s.
"""

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.approvals import ApprovalQueue  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402


def _make_run_dir():
    run_dir = Path(tempfile.mkdtemp(prefix="gov-uptime-test-"))
    return run_dir


def _marker_invalid_audit_count(run_dir):
    n = 0
    for e in read_entries(run_dir / "actions.jsonl"):
        if isinstance(e, dict) and e.get(
                "event") == "reconciliation_marker_invalid":
            n += 1
    return n


class TestF71bFreshBootCoalesceSentinel(unittest.TestCase):
    def test_first_invalid_audit_loud_on_fresh_boot(self):
        """F76: a simulated fresh-boot clock must not suppress the
        first loud reconciliation_marker_invalid audit.

        Pre-fix, _reconcile_marker_invalid_coalesced used
        last_audit=0.0 as the "never audited" sentinel, so with
        time.monotonic() < 300 (fresh boot) the check
        now - 0.0 < 300 was True and the FIRST loud audit was
        wrongly folded into the suppressed counter -- the audit
        count went 0 when it should have been 1.
        """
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            queue = ApprovalQueue(run_dir, log)
            # Simulated fresh boot: machine uptime 42s < 300s window.
            with mock.patch("time.monotonic", return_value=42.0):
                queue._reconcile_marker_invalid_coalesced(
                    "mk-fresh-boot", "test error", None, None)
            self.assertEqual(
                _marker_invalid_audit_count(run_dir), 1,
                "first invalid verdict on a fresh boot must audit LOUD")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_repeat_still_coalesced_after_loud_first_audit(self):
        """After the loud first audit, repeats within the window stay
        coalesced (counter increments, no new audit): the F76 fix
        must not disable coalescing on a fresh boot.
        """
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            queue = ApprovalQueue(run_dir, log)
            with mock.patch("time.monotonic", return_value=42.0):
                queue._reconcile_marker_invalid_coalesced(
                    "mk-fresh-boot", "test error", None, None)
                cache = queue._read_reconcile_marker_cache()
                self.assertIsNotNone(
                    cache, "cache must be written after loud audit")
                self.assertAlmostEqual(cache["last_audit"], 42.0)
                self.assertEqual(cache["suppressed"], 0)
            with mock.patch("time.monotonic", return_value=43.0):
                queue._reconcile_marker_invalid_coalesced(
                    "mk-fresh-boot", "test error", None, cache)
            self.assertEqual(
                _marker_invalid_audit_count(run_dir), 1,
                "repeat within the window must stay coalesced")
            cache2 = queue._read_reconcile_marker_cache()
            self.assertIsNotNone(cache2)
            self.assertEqual(
                cache2["suppressed"], 1,
                "repeat must fold into the suppressed counter")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_first_invalid_audit_loud_on_mature_boot(self):
        """Control: on a machine with uptime > 300s the first invalid
        verdict also audits loud -- the fix must not change the
        mature-boot behavior (previously loud via now - 0.0 >= 300,
        now loud via last_audit is None).
        """
        run_dir = _make_run_dir()
        try:
            log = ActionLog(run_dir / "actions.jsonl")
            queue = ApprovalQueue(run_dir, log)
            # Simulated mature boot: machine uptime 10_000s > 300s.
            with mock.patch("time.monotonic", return_value=10000.0):
                queue._reconcile_marker_invalid_coalesced(
                    "mk-mature-boot", "test error", None, None)
            self.assertEqual(
                _marker_invalid_audit_count(run_dir), 1,
                "first invalid verdict on a mature boot must audit LOUD")
            cache = queue._read_reconcile_marker_cache()
            self.assertIsNotNone(cache)
            self.assertAlmostEqual(cache["last_audit"], 10000.0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
