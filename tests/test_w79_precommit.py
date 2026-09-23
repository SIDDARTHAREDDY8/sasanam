"""Wave-79: pre-commit validation for irreversible actions.

Covers gov/precommit.py (preview -> bound approval -> commit, mismatch
and replay refusal, the frozen registry, the wave-75 governed mutation
path) and the executor opt-in gate.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gov import precommit as pc
from gov.policy import PolicyEngine
from harness import make_run, plant_file


def _applied_record_for(mutation, approvers=("human-a", "human-b")):
    """A synthetic *applied* policy_change provenance record binding the
    exact mutation (the shape apply_governed_change verifies)."""
    digest = pc._mutation_digest(mutation)
    return {
        "prov": {
            "record_type": "policy_change",
            "policy": {
                "status": "applied",
                "diff_summary": ("reclassify tool: irreversible-registry:"
                                 + digest),
            },
            "approvals": [
                {"approval_id": "a-%d" % i, "decision": "approve",
                 "decided_by": a, "decided_at": "2026-09-22T00:00:00Z"}
                for i, a in enumerate(approvers)
            ],
            "authorship_ref": "authorship-token-ref-hex",
        }
    }


class TestProtocol(unittest.TestCase):
    def test_happy_path(self):
        gate = pc.PrecommitGate()
        preview = gate.preview("delete_file", {"path": "data/x.txt"})
        self.assertEqual(preview["tool"], "delete_file")
        approval = gate.approve(preview["preview_id"], "human-op")
        executed = []
        out = gate.commit(approval["approval_id"], "delete_file",
                          {"path": "data/x.txt"},
                          lambda: executed.append(True))
        self.assertTrue(executed)
        self.assertIsNone(out)

    def test_preview_refused_for_reversible_tool(self):
        gate = pc.PrecommitGate()
        with self.assertRaises(pc.PrecommitError):
            gate.preview("read_file", {"path": "data/x.txt"})

    def test_approve_unknown_preview_refused(self):
        gate = pc.PrecommitGate()
        with self.assertRaises(pc.PrecommitError):
            gate.approve("pcp-999", "human-op")

    def test_approved_preview_a_executed_b_refused(self):
        gate = pc.PrecommitGate()
        preview = gate.preview("delete_file", {"path": "data/a.txt"})
        approval = gate.approve(preview["preview_id"], "human-op")
        executed = []
        with self.assertRaises(pc.PrecommitRefused):
            gate.commit(approval["approval_id"], "delete_file",
                        {"path": "data/DIFFERENT.txt"},
                        lambda: executed.append(True))
        self.assertFalse(executed)

    def test_approval_replay_refused(self):
        gate = pc.PrecommitGate()
        preview = gate.preview("send_email",
                               {"to": "a@x.com", "body": "hi"})
        approval = gate.approve(preview["preview_id"], "human-op")
        gate.commit(approval["approval_id"], "send_email",
                    {"to": "a@x.com", "body": "hi"},
                    lambda: None)
        with self.assertRaises(pc.PrecommitRefused):
            gate.commit(approval["approval_id"], "send_email",
                        {"to": "a@x.com", "body": "hi"},
                        lambda: None)

    def test_wrong_tool_refused(self):
        gate = pc.PrecommitGate()
        preview = gate.preview("delete_file", {"path": "data/x.txt"})
        approval = gate.approve(preview["preview_id"], "human-op")
        with self.assertRaises(pc.PrecommitRefused):
            gate.commit(approval["approval_id"], "http_post",
                        {"path": "data/x.txt"}, lambda: None)

    def test_unknown_approval_refused(self):
        gate = pc.PrecommitGate()
        with self.assertRaises(pc.PrecommitRefused):
            gate.commit("pca-999", "delete_file",
                        {"path": "data/x.txt"}, lambda: None)

    def test_preview_summary_redacts_payload(self):
        gate = pc.PrecommitGate()
        preview = gate.preview(
            "send_email",
            {"to": "a@x.com", "subject": "s", "body": "SECRET-BODY"})
        self.assertNotIn("SECRET-BODY", repr(preview["summary"]))
        self.assertIn("body_sha256_prefix", preview["summary"])


class TestRegistry(unittest.TestCase):
    def test_irreversible_set(self):
        for tool in ("delete_file", "send_email", "http_post",
                     "install_package"):
            self.assertTrue(pc.is_irreversible(tool))
        for tool in ("read_file", "write_file", "api_call"):
            self.assertFalse(pc.is_irreversible(tool))

    def test_no_public_mutator(self):
        self.assertFalse(hasattr(pc, "add_tool"))
        self.assertFalse(hasattr(pc, "remove_tool"))
        self.assertFalse(hasattr(pc, "set_registry"))

    def test_governed_change_happy_path(self):
        saved = dict(pc._IRREVERSIBLE)
        self.addCleanup(self._restore, saved)
        mutation = {"add": {"api_call": {"class": "external-effect",
                                         "preview": "dry-run",
                                         "why": "test reclassification"}},
                    "remove": []}
        record = _applied_record_for(mutation)
        result = pc.apply_governed_change(mutation, record)
        self.assertTrue(pc.is_irreversible("api_call"))
        self.assertEqual(result["authorized_by"], ["human-a", "human-b"])

    def test_governed_change_forged_status_refused(self):
        saved = dict(pc._IRREVERSIBLE)
        self.addCleanup(self._restore, saved)
        mutation = {"add": {}, "remove": ["send_email"]}
        record = _applied_record_for(mutation)
        record["prov"]["policy"]["status"] = "proposed"
        with self.assertRaises(pc.PrecommitRefused):
            pc.apply_governed_change(mutation, record)
        self.assertTrue(pc.is_irreversible("send_email"))

    def test_governed_change_unbound_summary_refused(self):
        saved = dict(pc._IRREVERSIBLE)
        self.addCleanup(self._restore, saved)
        mutation = {"add": {}, "remove": ["send_email"]}
        record = _applied_record_for({"add": {}, "remove": []})
        with self.assertRaises(pc.PrecommitRefused):
            pc.apply_governed_change(mutation, record)
        self.assertTrue(pc.is_irreversible("send_email"))

    def test_governed_change_no_approvals_refused(self):
        saved = dict(pc._IRREVERSIBLE)
        self.addCleanup(self._restore, saved)
        mutation = {"add": {}, "remove": ["send_email"]}
        record = _applied_record_for(mutation, approvers=())
        with self.assertRaises(pc.PrecommitRefused):
            pc.apply_governed_change(mutation, record)
        self.assertTrue(pc.is_irreversible("send_email"))

    def test_governed_change_not_a_record_refused(self):
        with self.assertRaises(pc.PrecommitRefused):
            pc.apply_governed_change({"add": {}, "remove": []},
                                     {"not": "a record"})

    def test_validate_mutation_rejects_unknown_class(self):
        with self.assertRaises(pc.PrecommitError):
            pc.validate_mutation(
                {"add": {"x": {"class": "whatever", "preview": "diff",
                               "why": "y"}},
                 "remove": []})

    def test_validate_mutation_rejects_removing_absent_tool(self):
        with self.assertRaises(pc.PrecommitError):
            pc.validate_mutation({"add": {}, "remove": ["read_file"]})

    def _restore(self, saved):
        pc._IRREVERSIBLE.clear()
        pc._IRREVERSIBLE.update(saved)


class TestExecutorGate(unittest.TestCase):
    def _ctx_with_gate(self):
        gate = pc.PrecommitGate()
        return make_run(precommit_gate=gate), gate

    def test_irreversible_allow_without_approval_denied(self):
        ctx, gate = self._ctx_with_gate()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(ctx, "data/x.txt", "bye")
        r = ctx["executor"].call(ident, "delete_file", path="data/x.txt")
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "precommit-required")
        entries = ctx["read_log"]()
        denied = [e for e in entries
                  if e.get("policy_id") == "precommit-required"]
        self.assertTrue(denied)
        self.assertEqual(denied[-1]["decision"], "denied")
        self.assertEqual(denied[-1]["policy_version"], "2")

    def test_irreversible_allow_with_bound_approval_executes(self):
        ctx, gate = self._ctx_with_gate()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(ctx, "data/x.txt", "bye")
        preview = gate.preview("delete_file", {"path": "data/x.txt"})
        approval = gate.approve(preview["preview_id"], "human-op")
        r = ctx["executor"].call(
            ident, "delete_file", path="data/x.txt",
            precommit_approval_id=approval["approval_id"])
        self.assertEqual(r["status"], "executed")

    def test_bound_approval_for_other_args_denied(self):
        ctx, gate = self._ctx_with_gate()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(ctx, "data/x.txt", "bye")
        plant_file(ctx, "data/y.txt", "bye")
        preview = gate.preview("delete_file", {"path": "data/x.txt"})
        approval = gate.approve(preview["preview_id"], "human-op")
        r = ctx["executor"].call(
            ident, "delete_file", path="data/y.txt",
            precommit_approval_id=approval["approval_id"])
        self.assertEqual(r["status"], "denied")
        self.assertEqual(r["policy_id"], "precommit-required")

    def test_reversible_tool_unaffected_by_gate(self):
        ctx, gate = self._ctx_with_gate()
        ident = ctx["mint_identity"]("triage-1", "triage", "ops-org")
        plant_file(ctx, "data/n.txt", "hello")
        r = ctx["executor"].call(ident, "read_file", path="data/n.txt")
        self.assertEqual(r["status"], "executed")

    def test_gate_off_by_default(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("coder-1", "coder", "dev-org")
        plant_file(ctx, "data/x.txt", "bye")
        r = ctx["executor"].call(ident, "delete_file", path="data/x.txt")
        self.assertEqual(r["status"], "executed")


if __name__ == "__main__":
    unittest.main()
