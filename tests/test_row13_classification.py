"""Row-13 classification-provenance control (2026-09-26).

A deployment labels sandbox-relative files public/internal/restricted.
Reading a labeled file taints the run; subsequent send_email/http_post/
api_call are queued with the classified_egress_review flag. Paraphrasing
cannot remove the taint because it attaches to the read event, not the
bytes. This is a provenance gate, not semantic content inference.

Honest ceiling (documented, not tested away):
- Unlabeled sensitive content is unprotected.
- Taint is run-scoped, not persisted across fresh runs.
- Legitimate egress after a classified read costs one declassification
  approval (measured friction).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
# GOV_DEPLOYMENT_MODE=staging. No module-level env manipulation here.

from gov.classification import ClassificationRegistry
from gov.executor import ToolExecutor
from gov.policy import PolicyEngine
from gov.log import ActionLog
from gov.approvals import ApprovalQueue


def _executor(run_dir):
    policy = PolicyEngine("policies/default.yaml")
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=run_dir / "egress_ledger.jsonl",
        ungoverned_ack="row13-classification-tests",
    )
    (run_dir / "sandbox").mkdir(parents=True, exist_ok=True)
    return ex


def _identity(ex):
    return ex.mint_identity("t1", "researcher", "user-1")


class TestClassificationRegistry(unittest.TestCase):
    def test_valid_levels(self):
        reg = ClassificationRegistry()
        for level in ("public", "internal", "restricted"):
            reg.label("a.txt", level)
            self.assertEqual(reg.level_for("a.txt"), level)

    def test_invalid_level_rejected(self):
        reg = ClassificationRegistry()
        with self.assertRaises(ValueError):
            reg.label("a.txt", "topsecret")
        with self.assertRaises(ValueError):
            reg.label("a.txt", "")

    def test_path_normalization(self):
        reg = ClassificationRegistry()
        reg.label("docs/memo.txt", "restricted")
        self.assertEqual(reg.level_for("./docs/memo.txt"), "restricted")
        self.assertEqual(reg.level_for("/docs/memo.txt"), "restricted")
        # Note: double slashes are NOT collapsed (matches the executor's
        # resolved-path format, which never produces them).

    def test_backslash_normalized_to_separator(self):
        # Backslashes normalize to forward slashes, so a label cannot be
        # dodged by alternate separator spelling.
        reg = ClassificationRegistry()
        reg.label("docs\\memo.txt", "internal")
        self.assertEqual(reg.level_for("docs/memo.txt"), "internal")
        self.assertEqual(reg.level_for("docs\\memo.txt"), "internal")

    def test_unlabel(self):
        reg = ClassificationRegistry()
        reg.label("a.txt", "restricted")
        reg.unlabel("a.txt")
        self.assertIsNone(reg.level_for("a.txt"))

    def test_is_classified(self):
        reg = ClassificationRegistry()
        self.assertIsNone(reg.level_for("a.txt"))
        reg.label("a.txt", "public")
        self.assertIsNotNone(reg.level_for("a.txt"))


class TestClassificationTaint(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="row13cls-"))
        self.ex = _executor(self.tmp)
        (self.tmp / "sandbox" / "memo.txt").write_text("sensitive")
        (self.tmp / "sandbox" / "notes.txt").write_text("benign")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_labeled_read_sets_taint(self):
        self.ex.classification.label("memo.txt", "restricted")
        ident = _identity(self.ex)
        r = self.ex.call(ident, "read_file", path="memo.txt")
        self.assertEqual(r.get("status"), "executed")
        self.assertEqual(self.ex._read_classification, "restricted")

    def test_unlabeled_read_no_taint(self):
        ident = _identity(self.ex)
        r = self.ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(r.get("status"), "executed")
        self.assertIsNone(self.ex._read_classification)

    def test_highest_label_wins(self):
        self.ex.classification.label("memo.txt", "internal")
        self.ex.classification.label("notes.txt", "restricted")
        ident = _identity(self.ex)
        self.ex.call(ident, "read_file", path="memo.txt")
        self.assertEqual(self.ex._read_classification, "internal")
        self.ex.call(ident, "read_file", path="notes.txt")
        self.assertEqual(self.ex._read_classification, "restricted")
        # Reading a lower label afterward does not downgrade.
        self.ex.call(ident, "read_file", path="memo.txt")
        self.assertEqual(self.ex._read_classification, "restricted")

    def test_labeled_path_read_taints_even_if_missing(self):
        # Fail-closed: the deployment labeled the path as sensitive. A
        # read that executes (even returning synthetic content for a
        # missing file) taints the run. Only reads that never execute
        # (denied/queued/refused) taint nothing.
        self.ex.classification.label("missing.txt", "restricted")
        ident = _identity(self.ex)
        r = self.ex.call(ident, "read_file", path="missing.txt")
        self.assertEqual(r.get("status"), "executed")
        self.assertEqual(self.ex._read_classification, "restricted")

    def test_denied_read_no_taint(self):
        # A read blocked by policy (outside the sandbox) never executes
        # and taints nothing.
        self.ex.classification.label("memo.txt", "restricted")
        ident = _identity(self.ex)
        r = self.ex.call(ident, "read_file", path="/etc/passwd")
        self.assertNotEqual(r.get("status"), "executed")
        self.assertIsNone(self.ex._read_classification)

    def test_symlink_spelling_no_bypass(self):
        # A symlink pointing at the labeled file resolves to the labeled
        # path (F146 discipline) — the taint cannot be dodged by an
        # alternate spelling.
        (self.tmp / "sandbox" / "link.txt").symlink_to(
            self.tmp / "sandbox" / "memo.txt")
        self.ex.classification.label("memo.txt", "restricted")
        ident = _identity(self.ex)
        r = self.ex.call(ident, "read_file", path="link.txt")
        self.assertEqual(r.get("status"), "executed")
        self.assertEqual(self.ex._read_classification, "restricted")


class TestClassificationEgressGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="row13clse-"))
        self.ex = _executor(self.tmp)
        (self.tmp / "sandbox" / "memo.txt").write_text("sensitive")
        (self.tmp / "sandbox" / "notes.txt").write_text("benign")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tainted(self):
        self.ex.classification.label("memo.txt", "restricted")
        ident = _identity(self.ex)
        self.ex.call(ident, "read_file", path="memo.txt")
        return ident

    def _ticket_flag(self):
        tickets = list(self.ex.approvals.pending())
        self.assertTrue(tickets, "expected a queued approval ticket")
        return tickets[-1].get("policy_flag")

    def test_http_post_gated(self):
        ident = self._tainted()
        r = self.ex.call(ident, "http_post",
                         url="https://vendor.synthetic.local/sync",
                         body="paraphrased meaning here")
        self.assertEqual(r.get("status"), "queued")
        self.assertEqual(r.get("policy_id"), "approval-classified-egress")
        self.assertEqual(self._ticket_flag(), "classified_egress_review")

    def test_send_email_gated(self):
        ident = self._tainted()
        r = self.ex.call(ident, "send_email", to="ops@synthetic.local",
                         subject="s", body="paraphrased meaning here")
        self.assertEqual(r.get("status"), "queued")
        self.assertEqual(self._ticket_flag(), "classified_egress_review")

    def test_api_call_gated(self):
        ident = self._tainted()
        r = self.ex.call(ident, "api_call",
                         endpoint="https://vendor.synthetic.local/crm",
                         params={"note": "re-encoded meaning"})
        self.assertEqual(r.get("status"), "queued")
        self.assertEqual(self._ticket_flag(), "classified_egress_review")

    def test_untainted_egress_ungated(self):
        # No classified read: the new rule must not fire. (The generic
        # outbound rule may still queue for other reasons; what matters
        # is the classification flag is absent.)
        ident = _identity(self.ex)
        self.ex.call(ident, "read_file", path="notes.txt")
        r = self.ex.call(ident, "http_post",
                         url="https://vendor.synthetic.local/sync",
                         body="benign public paraphrase")
        if r.get("status") == "queued":
            self.assertNotEqual(self._ticket_flag(),
                                "classified_egress_review")

    def test_paraphrase_does_not_clear_taint(self):
        # The taint attaches to the READ event, not the bytes. Writing a
        # paraphrase to a new file and reading it back keeps the taint.
        ident = self._tainted()
        self.ex.call(ident, "write_file", path="draft.txt",
                     content="paraphrased meaning")
        self.ex.call(ident, "read_file", path="draft.txt")
        r = self.ex.call(ident, "http_post",
                         url="https://vendor.synthetic.local/sync",
                         body="paraphrased meaning")
        self.assertEqual(r.get("status"), "queued")
        self.assertEqual(self._ticket_flag(), "classified_egress_review")


class TestClassificationPolicyContext(unittest.TestCase):
    def test_context_key_present(self):
        tmp = Path(tempfile.mkdtemp(prefix="row13clsx-"))
        try:
            ex = _executor(tmp)
            ctx = ex._context("http_post", {})
            self.assertIn("read_classified", ctx)
            # Boolean: False when no labeled file has been read.
            self.assertIs(ctx["read_classified"], False)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
