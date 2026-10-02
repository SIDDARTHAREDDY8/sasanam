"""Unit tests for gov/approval_policy.py (wave-254 lane 2).

Declarative approval rules: compile fail-closed, first-match-wins
evaluation, auditable auto-approve, explicit-opt-in disapproval,
read-only simulation. Synthetic/local only.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import approval_policy as ap  # noqa: E402
from gov import decision_codes as dc  # noqa: E402


AUTO_RULES = {
    "version": 1,
    "rules": [
        {"id": "low-risk-reads",
         "when": {"and": [
             {"field": "tool", "op": "eq", "value": "fs.read"},
             {"field": "risk_score", "op": "lt", "value": 0.3},
         ]},
         "action": "auto-approve"},
        {"id": "catch-all",
         "when": {"field": "tool", "op": "exists"},
         "action": "require-approval"},
    ],
}


class FakeQueue(object):
    def __init__(self):
        self.calls = []

    def queue(self, action, decision, **kwargs):
        self.calls.append((action, decision))
        return "approval-1"


class CompileTests(unittest.TestCase):
    def test_version_required(self):
        with self.assertRaises(ap.ApprovalPolicyError) as ctx:
            ap.compile_rules({"rules": []})
        self.assertEqual(ctx.exception.code,
                         "approval-policy-malformed")

    def test_empty_rules_refused(self):
        with self.assertRaises(ap.ApprovalPolicyError):
            ap.compile_rules({"version": 1, "rules": []})

    def test_unknown_rule_key_refused(self):
        bad = {"version": 1, "rules": [
            {"id": "x", "when": {"field": "t", "op": "exists"},
             "action": "require-approval", "typo-key": 1}]}
        with self.assertRaises(ap.ApprovalPolicyError):
            ap.compile_rules(bad)

    def test_duplicate_id_refused(self):
        bad = {"version": 1, "rules": [
            {"id": "dup", "when": {"field": "t", "op": "exists"},
             "action": "require-approval"},
            {"id": "dup", "when": {"field": "t", "op": "exists"},
             "action": "require-approval"}]}
        with self.assertRaises(ap.ApprovalPolicyError):
            ap.compile_rules(bad)

    def test_disapproval_flag_on_wrong_action_refused(self):
        bad = {"version": 1, "rules": [
            {"id": "x", "when": {"field": "t", "op": "exists"},
             "action": "auto-approve", "disapproval": True}]}
        with self.assertRaises(ap.ApprovalPolicyError):
            ap.compile_rules(bad)

    def test_in_op_needs_list(self):
        bad = {"version": 1, "rules": [
            {"id": "x",
             "when": {"field": "t", "op": "in", "value": "nope"},
             "action": "require-approval"}]}
        with self.assertRaises(ap.ApprovalPolicyError):
            ap.compile_rules(bad)

    def test_error_carries_machine_code(self):
        try:
            ap.compile_rules({"version": 1, "rules": []})
        except ap.ApprovalPolicyError as exc:
            self.assertEqual(exc.code, "approval-policy-malformed")
            self.assertIn("approval-policy-malformed", str(exc))
        else:
            self.fail("expected ApprovalPolicyError")


class EvaluateTests(unittest.TestCase):
    def setUp(self):
        self.rs = ap.compile_rules(AUTO_RULES)

    def test_first_match_wins(self):
        out = self.rs.evaluate({"tool": "fs.read",
                                "risk_score": 0.1})
        self.assertEqual(out.action, "auto-approve")
        self.assertEqual(out.rule_id, "low-risk-reads")
        self.assertTrue(out.matched)

    def test_no_match_defaults_require_approval(self):
        out = self.rs.evaluate({"other": 1})
        self.assertEqual(out.action, "require-approval")
        self.assertIsNone(out.rule_id)
        self.assertFalse(out.matched)

    def test_type_mismatch_is_non_match(self):
        out = self.rs.evaluate({"tool": "fs.read",
                                "risk_score": "high"})
        self.assertEqual(out.action, "require-approval")

    def test_non_dict_request_refused(self):
        with self.assertRaises(ap.ApprovalPolicyError):
            self.rs.evaluate(["not", "a", "dict"])


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.rs = ap.compile_rules(AUTO_RULES)

    def test_require_approval_hits_queue_seam(self):
        queue = FakeQueue()
        result = ap.route(
            self.rs, {"tool": "shell.exec"}, queue=queue,
            audit_sink=lambda e: None,
            queue_action={"tool": "shell.exec"},
            queue_decision={"flag": "t"})
        self.assertTrue(result["queued"])
        self.assertEqual(result["approval_id"], "approval-1")
        self.assertEqual(len(queue.calls), 1)

    def test_require_approval_needs_action_and_decision(self):
        with self.assertRaises(ap.ApprovalPolicyError) as ctx:
            ap.route(self.rs, {"tool": "shell.exec"},
                     queue=FakeQueue())
        self.assertEqual(ctx.exception.code,
                         "approval-policy-malformed")

    def test_auto_approve_entry_is_json_stable(self):
        import json
        sunk = []
        result = ap.route(
            self.rs, {"tool": "fs.read", "risk_score": 0.1},
            queue=FakeQueue(), audit_sink=sunk.append)
        # The audited entry must survive a JSON round-trip (it is
        # evidence, not an in-memory artifact).
        json.dumps(sunk[0], sort_keys=True)
        self.assertEqual(result["entry"]["request_digest"],
                         sunk[0]["request_digest"])

    def test_simulate_request_digest_matches_route(self):
        sunk = []
        routed = ap.route(
            self.rs, {"tool": "fs.read", "risk_score": 0.1},
            queue=FakeQueue(), audit_sink=sunk.append)
        preview = ap.simulate(
            self.rs, [{"tool": "fs.read", "risk_score": 0.1}])[0]
        self.assertEqual(preview["request_digest"],
                         routed["entry"]["request_digest"])
        self.assertEqual(preview["action"], "auto-approve")


class TaxonomyTests(unittest.TestCase):
    def test_taxonomy_pin(self):
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        self.assertEqual(len(dc.TAXONOMY), 1563)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*)

    def test_new_codes_resolve(self):
        for code in ("approval-policy-malformed",
                     "approval-policy-no-audit-sink",
                     "approval-policy-seam-unavailable",
                     "approval-policy-disapproval-defaulted",
                     "approval-policy-audit-failed"):
            rec = dc.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "approval-policy")

    def test_no_duplicates(self):
        self.assertEqual(len(set(dc.TAXONOMY.keys())),
                         len(dc.TAXONOMY))  # Wave-258 merge: pin -> 1080.


if __name__ == "__main__":
    unittest.main()
