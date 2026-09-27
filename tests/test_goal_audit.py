#!/usr/bin/env python3
"""Unit tests for gov/goal_audit.py (row 11, second half).

Tests the post-hoc unregistered-goal pursuit auditor at its public
seams: derive_effect, audit_entries, audit_run_goals. Expected values
are hand-computed literals, not recomputations of the implementation.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov.goal_audit import (  # noqa: E402
    audit_entries,
    audit_run_goals,
    derive_effect,
)


def _goal_event(agent, run, gid, effects, status_event=False):
    base = {
        "event": "goal_registered",
        "goal_id": gid,
        "agent_id": agent,
        "run_id": run,
        "description": "test goal",
        "effects": [list(e) for e in effects],
        "constraints": [],
    }
    if status_event:
        return {
            "event": "goal_status_changed",
            "goal_id": gid,
            "agent_id": agent,
            "run_id": run,
            "status": "superseded",
        }
    return base


def _exec_event(agent, run, tool, args, decision="approved_executed"):
    return {
        "event": "tool_call",
        "agent_id": agent,
        "run_id": run,
        "tool": tool,
        "args": args,
        "decision": decision,
    }


class TestDeriveEffect(unittest.TestCase):
    def test_http_post_extracts_host(self):
        self.assertEqual(
            derive_effect("http_post",
                          {"url": "https://Vendor.Example.COM:8443/sync"}),
            ("send", "vendor.example.com"))

    def test_send_email_uses_recipient(self):
        self.assertEqual(
            derive_effect("send_email", {"to": "Ops Team"}),
            ("send", "ops team"))

    def test_delete_file_uses_path(self):
        self.assertEqual(
            derive_effect("delete_file", {"path": "/TMP/X/Log.txt"}),
            ("delete", "/tmp/x/log.txt"))

    def test_unknown_tool_returns_none(self):
        self.assertIsNone(derive_effect("install_package", {}))
        self.assertIsNone(derive_effect("mystery_tool", {"x": 1}))

    def test_missing_target_becomes_unknown(self):
        # Fail-closed direction: "unknown" never matches a declared
        # goal, so it surfaces as a gap rather than silent cover.
        self.assertEqual(derive_effect("http_post", {}),
                         ("send", "unknown"))

    def test_malformed_args_never_raises(self):
        self.assertEqual(derive_effect("http_post", "not-a-dict"),
                         ("send", "unknown"))
        self.assertEqual(derive_effect("http_post", None),
                         ("send", "unknown"))


class TestAuditEntries(unittest.TestCase):
    RUN = "run-1"

    def test_no_goals_high_impact_action_is_gap(self):
        entries = [_exec_event("a1", self.RUN, "http_post",
                               {"url": "https://evil.example/x"})]
        findings, summary = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_coverage_gap")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertIn("a1", summary["agents_with_no_goals"])

    def test_covered_action_is_silent(self):
        entries = [
            _goal_event("a1", self.RUN, "g1",
                        [("send", "vendor.example.com")]),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://vendor.example.com/sync"}),
        ]
        findings, summary = audit_entries(self.RUN, entries)
        self.assertEqual(findings, [])
        self.assertEqual(summary["high_impact_actions"], 1)

    def test_read_actions_never_flagged(self):
        # Read-only agent doing reads: the benign baseline must stay
        # quiet even with zero registered goals.
        entries = [_exec_event("a1", self.RUN, "read_file",
                               {"path": "/tmp/x.txt"})]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(findings, [])

    def test_contradiction_beats_gap(self):
        entries = [
            _goal_event("a1", self.RUN, "g1",
                        [("preserve", "/tmp/x.txt")]),
            _exec_event("a1", self.RUN, "delete_file",
                        {"path": "/tmp/x.txt"}),
        ]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_contradiction")
        self.assertEqual(findings[0]["severity"], "high")

    def test_wildcard_cover_is_info_not_violation(self):
        entries = [
            _goal_event("a1", self.RUN, "g1", [("send", "*")]),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://evil.example/x"}),
        ]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_wildcard_cover")
        self.assertEqual(findings[0]["severity"], "info")

    def test_exact_match_beats_wildcard(self):
        entries = [
            _goal_event("a1", self.RUN, "g1", [("send", "*")]),
            _goal_event("a1", self.RUN, "g2",
                        [("send", "vendor.example.com")]),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://vendor.example.com/sync"}),
        ]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(findings, [])

    def test_superseded_goal_provides_no_cover(self):
        entries = [
            _goal_event("a1", self.RUN, "g1",
                        [("send", "vendor.example.com")]),
            _goal_event("a1", self.RUN, "g1", [], status_event=True),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://vendor.example.com/sync"}),
        ]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_coverage_gap")

    def test_non_executed_decisions_ignored(self):
        entries = [
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://evil.example/x"},
                        decision="queued_pending"),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://evil.example/x"},
                        decision="denied"),
        ]
        findings, summary = audit_entries(self.RUN, entries)
        self.assertEqual(findings, [])
        self.assertEqual(summary["high_impact_actions"], 0)

    def test_allowed_executed_counts(self):
        # Directly-executed (no approval) actions are still pursuit.
        entries = [_exec_event("a1", self.RUN, "delete_file",
                               {"path": "/tmp/x.txt"},
                               decision="allowed_executed")]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_coverage_gap")

    def test_other_runs_ignored(self):
        entries = [
            _goal_event("a1", "run-2", "g1",
                        [("send", "vendor.example.com")]),
            _exec_event("a1", "run-2", "http_post",
                        {"url": "https://evil.example/x"}),
        ]
        findings, summary = audit_entries(self.RUN, entries)
        self.assertEqual(findings, [])
        self.assertEqual(summary["actions_examined"], 0)

    def test_malformed_entries_do_not_raise(self):
        entries = [
            None,
            "not-a-dict",
            {"event": "tool_call"},  # missing run_id/agent/tool
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://evil.example/x"}),
        ]
        findings, summary = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertGreaterEqual(summary["unauditable_entries"], 1)

    def test_verb_mismatch_is_gap(self):
        # Goal allows reads; agent sends. Different verb -> gap.
        entries = [
            _goal_event("a1", self.RUN, "g1", [("read", "*")]),
            _exec_event("a1", self.RUN, "http_post",
                        {"url": "https://vendor.example.com/sync"}),
        ]
        findings, _s = audit_entries(self.RUN, entries)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding"], "goal_coverage_gap")


class TestAuditRunGoals(unittest.TestCase):
    def test_missing_log_returns_empty_with_error(self):
        findings, summary = audit_run_goals(
            "run-1", "/nonexistent/path/actions.jsonl")
        self.assertEqual(findings, [])
        self.assertIn("log_error", summary)

    def test_reads_real_log_file(self):
        tmpdir = tempfile.mkdtemp()
        log_path = Path(tmpdir) / "actions.jsonl"
        entries = [
            _exec_event("a1", "run-9", "http_post",
                        {"url": "https://evil.example/x"}),
        ]
        log_path.write_text(
            "\n".join(json.dumps(e) for e in entries))
        findings, summary = audit_run_goals("run-9", log_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(summary["run_id"], "run-9")


if __name__ == "__main__":
    unittest.main()
