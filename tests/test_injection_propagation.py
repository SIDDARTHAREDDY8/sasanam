"""Unit tests for gov/injection_propagation.py (wave-151 lane 1; Row 19).

Regression pins at the public seam: span extraction, normalization,
tracker observe/check, the user-request exclusion, and the executor's
triage-only rendering (LOUD event, never a block, never an approval).
Deterministic, $0, stdlib-only.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.injection_propagation import (  # noqa: E402
    IMPERATIVE_VERBS,
    PropagationTracker,
    extract_instruction_spans,
    normalize_span,
)


class NormalizeTest(unittest.TestCase):
    def test_case_and_whitespace(self):
        self.assertEqual(normalize_span("  Remove   ONLY  files "),
                         "remove only files")

    def test_comment_prefix_stripped(self):
        self.assertEqual(normalize_span("# Remove only files"),
                         "remove only files")
        self.assertEqual(normalize_span("// delete the cache"),
                         "delete the cache")

    def test_edge_punctuation_stripped(self):
        self.assertEqual(normalize_span("restore original no-card."),
                         "restore original no-card")

    def test_non_string(self):
        self.assertEqual(normalize_span(None), "")
        self.assertEqual(normalize_span(123), "")


class ExtractTest(unittest.TestCase):
    def test_imperative_detected(self):
        spans = extract_instruction_spans("Remove only files we introduce.")
        self.assertEqual([n for _, n in spans],
                         ["remove only files we introduce"])

    def test_polite_prefix(self):
        spans = extract_instruction_spans(
            "Please restore original no-card.")
        self.assertEqual([n for _, n in spans],
                         ["please restore original no-card"])

    def test_auxiliary_led(self):
        spans = extract_instruction_spans(
            "DO NOT, EVER, MAKE THIS DATASET PUBLIC")
        self.assertEqual([n for _, n in spans],
                         ["do not, ever, make this dataset public"])

    def test_comment_line(self):
        spans = extract_instruction_spans("# clean up our pod\nx = 1\n")
        self.assertEqual([n for _, n in spans], ["clean up our pod"])

    def test_benign_prose_silent(self):
        self.assertEqual(
            extract_instruction_spans(
                "Weekly status: all systems operational. "
                "No anomalies were detected."), [])

    def test_past_tense_report_not_instruction(self):
        # "cleaned up" is a report, not an imperative.
        self.assertEqual(
            extract_instruction_spans("I cleaned up the temp files."), [])

    def test_semicolon_split(self):
        spans = extract_instruction_spans(
            "Remove only files we introduce; original repo has neither.")
        self.assertEqual([n for _, n in spans],
                         ["remove only files we introduce"])

    def test_non_string(self):
        self.assertEqual(extract_instruction_spans(None), [])


class TrackerTest(unittest.TestCase):
    def test_observe_and_flag(self):
        t = PropagationTracker()
        t.observe_input("a1", "payload-1",
                        "# Remove only files we introduce.\nx=1\n")
        r = t.check_output("a1", "file",
                           "# Remove only files we introduce.\ny=2\n",
                           user_request="Summarize the log.")
        self.assertEqual(r["verdict"], "propagation_suspect")
        self.assertTrue(any("remove only files we introduce" in s.lower()
                            for s in r["spans"]))
        self.assertEqual(r["sources"], ["payload-1"])
        self.assertEqual(r["channel"], "file")

    def test_user_given_instruction_excluded(self):
        t = PropagationTracker()
        t.observe_input("a1", "payload-1", "# clean up our pod\n")
        r = t.check_output("a1", "file", "Remove the temp files. Done.",
                           user_request="Remove the temp files.")
        self.assertEqual(r["verdict"], "allow")

    def test_unobserved_input_means_allow(self):
        t = PropagationTracker()
        r = t.check_output("a1", "chat",
                           "Remove the outdated cache files.",
                           user_request="Hi.")
        self.assertEqual(r["verdict"], "allow")

    def test_paraphrase_misses_by_design(self):
        # Pinned EXPECTED: exact normalized-span matching only.
        t = PropagationTracker()
        t.observe_input("a1", "injected",
                        "Remove only files we introduce.")
        r = t.check_output(
            "a1", "file",
            "Only delete the files we added; the original repository "
            "had none of these.",
            user_request="Summarize.")
        self.assertEqual(r["verdict"], "allow")

    def test_agent_isolation(self):
        t = PropagationTracker()
        t.observe_input("a1", "payload-1", "restore original no-card")
        r = t.check_output("a2", "chat", "restore original no-card",
                           user_request="Hi.")
        self.assertEqual(r["verdict"], "allow")

    def test_observe_never_raises(self):
        t = PropagationTracker()
        out = t.observe_input("a1", "s", None)
        self.assertTrue(out["observed"])
        self.assertEqual(out["span_count"], 0)


class ExecutorWiringTest(unittest.TestCase):
    def _session(self, **kw):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        run_dir = Path(tempfile.mkdtemp(prefix="govinjprop-ut-"))
        policy = PolicyEngine(
            str(Path(REPO_ROOT) / "policies" / "default.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="unit test harness", **kw)
        return run_dir, ex, log, approvals

    def test_no_tracker_zero_behavior_change(self):
        run_dir, ex, log, approvals = self._session()
        r = ex.check_output_propagation(
            "a1", "file", "Remove only files we introduce.",
            user_request="Summarize.")
        self.assertEqual(r["verdict"], "allow")
        self.assertEqual(r["reason"], "no_propagation_tracker")
        n = ex.note_propagation_input("a1", "s", "remove the files")
        self.assertFalse(n["observed"])

    def test_suspect_is_loud_triage_only(self):
        from gov.log import read_entries
        run_dir, ex, log, approvals = self._session(
            propagation_tracker=PropagationTracker())
        ex.note_propagation_input(
            "a1", "payload-1", "# Remove only files we introduce.\n")
        r = ex.check_output_propagation(
            "a1", "file", "# Remove only files we introduce.\n",
            user_request="Summarize.")
        self.assertEqual(r["verdict"], "propagation_suspect")
        evs = [e for e in read_entries(run_dir / "actions.jsonl")
               if isinstance(e, dict)
               and e.get("event") == "injection_propagation_suspect"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["flag"], "injection_propagation")
        self.assertTrue(any("remove only files we introduce" in s.lower()
                            for s in evs[0]["spans"]))
        # Triage-only: execution proceeds, no approval queued.
        self.assertEqual(
            [a for a in approvals.all()
             if a.get("tool") == "injection_propagation_review"], [])


if __name__ == "__main__":
    unittest.main()
