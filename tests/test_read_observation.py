"""Unit tests for wave-141 row-13 automatic read observation.

Covers ``ToolExecutor._rare_token_observe_on_read``: the hook fires
only on real governed ``read_file`` results (``source == "sandbox"``
with content), builds the documented ``read:auto:<rel>`` source ID,
never raises, never breaks the read, and composes idempotently with
the explicit ``note_read_output`` path (the tracker keys by
(agent_id, source_id)).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
# GOV_DEPLOYMENT_MODE=staging. No module-level env manipulation here.

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import rare_token as rt  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402

DOC = ("Zephyrcorp ZX-88142 Marlowe Finch QX-22901 "
       "Brigadier Oswald 480000")


def _executor(run_dir, tracker):
    policy = PolicyEngine("policies/default.yaml")
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      rare_token_tracker=tracker,
                      ungoverned_ack="read-observation-tests")
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    return ex


class TestAutoObserveHook(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="readobs-"))
        self.tracker = rt.RareTokenTracker()
        self.ex = _executor(self.tmp, self.tracker)
        (self.tmp / "sandbox" / "doc.txt").write_text(DOC, encoding="utf-8")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _docs(self, agent="a1"):
        return self.tracker._docs.get(agent, {})

    def test_real_read_observed_with_auto_source_id(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")
        docs = self._docs()
        self.assertEqual(list(docs), ["read:auto:doc.txt"])
        self.assertTrue(len(docs["read:auto:doc.txt"]) >= 1)

    def test_non_read_tool_ignored(self):
        self.ex._rare_token_observe_on_read(
            "write_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")
        self.assertEqual(self._docs(), {})

    def test_simulated_source_never_observed(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "simulated",
             "content": "[synthetic file contents]"}, "a1")
        self.assertEqual(self._docs(), {})

    def test_missing_source_treated_as_not_real(self):
        # Mirrors the lineage guard: anything that is not
        # source == "sandbox" is not real bytes.
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"content": DOC}, "a1")
        self.assertEqual(self._docs(), {})

    def test_refused_read_observes_nothing(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "/etc/passwd"},
            {"refused": True, "note": "denied"}, "a1")
        self.assertEqual(self._docs(), {})

    def test_empty_content_observes_nothing(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": ""}, "a1")
        self.assertEqual(self._docs(), {})

    def test_no_tracker_is_noop(self):
        ex = _executor(self.tmp, None)
        # Must not raise.
        ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")

    def test_missing_path_is_noop(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {},
            {"source": "sandbox", "content": DOC}, "a1")
        self.assertEqual(self._docs(), {})

    def test_tracker_failure_never_breaks_hook(self):
        class Boom(rt.RareTokenTracker):
            def observe_read(self, agent_id, source_id, text):
                raise RuntimeError("ledger down")
        ex = _executor(self.tmp, Boom())
        # Must not raise: the read already succeeded; the auto path
        # is best-effort.
        ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")

    def test_explicit_replaces_auto_same_source_id(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")
        res = self.ex.note_read_output("a1", "read:auto:doc.txt", DOC)
        self.assertTrue(res["observed"])
        docs = self._docs()
        self.assertEqual(list(docs), ["read:auto:doc.txt"])

    def test_explicit_different_id_is_different_source(self):
        self.ex._rare_token_observe_on_read(
            "read_file", {"path": "doc.txt"},
            {"source": "sandbox", "content": DOC}, "a1")
        self.ex.note_read_output("a1", "harness-doc-7", DOC)
        docs = self._docs()
        self.assertEqual(sorted(docs),
                         ["harness-doc-7", "read:auto:doc.txt"])

    def test_auto_observation_drives_carryover(self):
        ident = self.ex.mint_identity("a1", "coder", "user-1")
        r = self.ex.call(ident, "read_file", path="doc.txt")
        self.assertEqual(r.get("status"), "executed")
        self.assertEqual(list(self._docs("a1")), ["read:auto:doc.txt"])
        eg = self.tracker.check_egress(
            "a1", "send_email",
            {"to": "ops@synthetic.local", "body": DOC},
            payload_text=DOC)
        self.assertEqual(eg["verdict"], "require_approval")

    def test_subdirectory_path_in_source_id(self):
        (self.tmp / "sandbox" / "sub").mkdir(exist_ok=True)
        (self.tmp / "sandbox" / "sub" / "deep.txt").write_text(
            DOC, encoding="utf-8")
        ident = self.ex.mint_identity("a1", "coder", "user-1")
        self.ex.call(ident, "read_file", path="sub/deep.txt")
        self.assertEqual(list(self._docs("a1")),
                         ["read:auto:sub/deep.txt"])


if __name__ == "__main__":
    unittest.main()
