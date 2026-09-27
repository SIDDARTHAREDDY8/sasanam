"""Unit tests for wave-140 coverage-gap reporting (gov/artifact_sweep).

Tests the pure comparison seam ``compare_coverage`` /
``report_coverage_gaps`` with hand-computed expectations — no
executor, no audit log, no filesystem crawling (declared roots are
resolved, never walked).
"""

import os
import tempfile
import unittest

from gov import artifact_sweep as sweep


def _mkroot():
    d = tempfile.mkdtemp(prefix="govcov-unit-")
    return d


class CompareCoverageTest(unittest.TestCase):
    def test_exact_match_covered(self):
        root = _mkroot()
        rows = sweep.compare_coverage([root], [root])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["declared_root"],
                         os.path.realpath(root))
        self.assertEqual(rows[0]["covering_root"],
                         os.path.realpath(root))
        self.assertTrue(rows[0]["exists"])

    def test_ancestor_root_covers_declared_subdir(self):
        root = _mkroot()
        sub = os.path.join(root, "sub")
        rows = sweep.compare_coverage([sub], [root])
        self.assertEqual(rows[0]["covering_root"],
                         os.path.realpath(root))

    def test_descendant_root_does_not_cover(self):
        root = _mkroot()
        sub = os.path.join(root, "sub")
        rows = sweep.compare_coverage([root], [sub])
        self.assertIsNone(rows[0]["covering_root"])

    def test_no_watch_root_is_gap(self):
        root = _mkroot()
        rows = sweep.compare_coverage([root], [])
        self.assertIsNone(rows[0]["covering_root"])

    def test_unrelated_root_is_gap(self):
        a, b = _mkroot(), _mkroot()
        rows = sweep.compare_coverage([b], [a])
        self.assertIsNone(rows[0]["covering_root"])

    def test_empty_inventory_silent(self):
        rows = sweep.compare_coverage([], [_mkroot()])
        self.assertEqual(rows, [])

    def test_multiple_declared_first_covering_root_wins(self):
        a, b = _mkroot(), _mkroot()
        sub = os.path.join(a, "sub")
        rows = sweep.compare_coverage([sub, b], [a, b])
        self.assertEqual(rows[0]["covering_root"],
                         os.path.realpath(a))
        self.assertEqual(rows[1]["covering_root"],
                         os.path.realpath(b))

    def test_nonexistent_declared_root_still_compared(self):
        # The inventory is declared, not discovered: a root that
        # does not exist yet is still a gap when unwatched (it can
        # be created during the run).
        ghost = os.path.join(tempfile.gettempdir(),
                             "govcov-ghost-no-such-dir")
        rows = sweep.compare_coverage([ghost], [])
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["covering_root"])
        self.assertFalse(rows[0]["exists"])

    def test_non_path_declared_entry_raises(self):
        with self.assertRaises(ValueError):
            sweep.compare_coverage([object()], [])

    def test_non_path_configured_entry_raises(self):
        with self.assertRaises(ValueError):
            sweep.compare_coverage([_mkroot()], [object()])

    def test_tuple_watch_roots_accepted(self):
        root = _mkroot()
        rows = sweep.compare_coverage([root], [(root, object())])
        self.assertEqual(rows[0]["covering_root"],
                         os.path.realpath(root))


class ReportCoverageGapsTest(unittest.TestCase):
    def test_gap_event_shape(self):
        a, b = _mkroot(), _mkroot()
        events = []
        report = sweep.report_coverage_gaps(
            [a, b], [a], audit=events.append, run_id="r1")
        self.assertEqual(report["gaps"], [os.path.realpath(b)])
        self.assertEqual(report["covered"], [os.path.realpath(a)])
        self.assertEqual(len(events), 2)  # 1 gap + 1 summary
        gap = events[0]
        self.assertEqual(gap["event"], sweep.COVERAGE_GAP_EVENT)
        self.assertEqual(gap["flag"], "coverage_gap")
        self.assertEqual(gap["declared_root"], os.path.realpath(b))
        self.assertIsNone(gap["covering_root"])
        self.assertEqual(gap["run_id"], "r1")
        self.assertIn("COVERAGE GAP", gap["reason"])
        summary = events[1]
        self.assertEqual(summary["event"], sweep.COVERAGE_COMPLETE_EVENT)
        self.assertEqual((summary["declared"], summary["covered"],
                          summary["gaps"]), (2, 1, 1))

    def test_empty_inventory_emits_nothing(self):
        events = []
        report = sweep.report_coverage_gaps(
            [], [_mkroot()], audit=events.append)
        self.assertEqual(report["gaps"], [])
        self.assertEqual(events, [])

    def test_no_audit_callable_returns_events(self):
        b = _mkroot()
        report = sweep.report_coverage_gaps([b], [])
        self.assertEqual(len(report["events"]), 2)
        self.assertEqual(report["events"][0]["event"],
                         sweep.COVERAGE_GAP_EVENT)


class ExecutorNeverRaisesTest(unittest.TestCase):
    """Wave-140 audit correction: run_artifact_sweep's "Never raises"
    contract covers the coverage report -- a malformed
    declared_inventory is audited as artifact_sweep_failed, never
    fatal to the caller."""

    def _executor(self, artifact_sweep):
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        run_dir = tempfile.mkdtemp(prefix="govcov-ex-")
        os.makedirs(os.path.join(run_dir, "sandbox"), exist_ok=True)
        policy = PolicyEngine(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "policies", "default.yaml"))
        log = ActionLog(os.path.join(run_dir, "actions.jsonl"))
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=os.path.join(run_dir, "egress_ledger.jsonl"),
            ungoverned_ack=("unit test: synthetic harness, "
                            "declared and chained"),
            artifact_sweep=artifact_sweep)
        return ex, run_dir

    def test_malformed_inventory_never_raises(self):
        ex, run_dir = self._executor(
            {"watch_roots": [], "declared_inventory": [{"no": "path"}]})
        findings = ex.run_artifact_sweep()  # must not raise
        self.assertEqual(findings, [])
        self.assertTrue(os.path.exists(
            os.path.join(run_dir, "actions.jsonl")))

    def test_malformed_inventory_audited_failed(self):
        from gov.log import read_entries
        ex, run_dir = self._executor(
            {"watch_roots": [], "declared_inventory": [{"no": "path"}]})
        ex.run_artifact_sweep()
        events = [e.get("event") for e in
                  read_entries(os.path.join(run_dir, "actions.jsonl"))]
        self.assertIn("artifact_sweep_failed", events)


if __name__ == "__main__":
    unittest.main()
