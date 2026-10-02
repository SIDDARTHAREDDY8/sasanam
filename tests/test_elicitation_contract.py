"""Unit tests for the tri-state elicitation contract (wave-278 lane 5).

Covers ``gov/elicitation_contract.py`` in isolation (schema/rationale
validation, secret shapes, request building) plus a thin pin of the
``ApprovalQueue.elicit_decision`` seam. The full behavioral battery
lives in ``evals/w278_approvalv2_probes.py``; these tests pin the
contract primitives so regressions surface at the smallest scope.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# tests/__init__ provisions an explicit test key on import.
from gov import elicitation_contract as ec
from gov.approvals import sanitize_preview_text


SCHEMA = {
    "type": "object",
    "properties": {
        "reason": {"type": "string"},
        "category": {"enum": ["safety", "policy", "other"]},
        "count": {"type": "number"},
        "flag": {"type": "boolean"},
    },
    "required": ["reason"],
}


class TestValidateFlatSchema(unittest.TestCase):
    def test_accepts_flat(self):
        norm = ec.validate_flat_schema(SCHEMA)
        self.assertEqual(norm["required"], ["reason"])
        self.assertEqual(norm["properties"]["count"], {"type": "number"})

    def test_rejects_nested_object(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"detail": {"type": "object",
                                          "properties": {}}},
            })

    def test_rejects_nested_array(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"tags": {"type": "array",
                                        "items": {"type": "string"}}},
            })

    def test_rejects_nested_properties_key(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"x": {"type": "string",
                                     "properties": {"y": {}}}},
            })

    def test_rejects_unknown_type(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"x": {"type": "integer"}},
            })

    def test_rejects_empty_properties(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({"type": "object", "properties": {}})

    def test_rejects_required_not_declared(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["zzz"],
            })

    def test_rejects_non_dict(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema(["reason"])

    def test_enum_must_be_flat_nonempty(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"c": {"enum": []}},
            })
        with self.assertRaises(ec.ElicitationError):
            ec.validate_flat_schema({
                "type": "object",
                "properties": {"c": {"enum": [{"nested": 1}]}},
            })

    def test_default_schema_is_flat(self):
        # Pin: the default schema the queue uses must itself pass.
        norm = ec.validate_flat_schema(ec.DEFAULT_RATIONALE_SCHEMA)
        self.assertIn("reason", norm["required"])


class TestValidateRationale(unittest.TestCase):
    def setUp(self):
        self.schema = ec.validate_flat_schema(SCHEMA)

    def test_valid(self):
        ec.validate_rationale(
            {"reason": "phishing", "category": "safety",
             "count": 2, "flag": True},
            self.schema)

    def test_missing_required(self):
        with self.assertRaises(ec.ElicitationError) as ctx:
            ec.validate_rationale({"category": "safety"}, self.schema)
        self.assertIn("reason", str(ctx.exception))

    def test_wrong_string_type(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": 123}, self.schema)

    def test_bool_is_not_number(self):
        # bool is an int subclass: must not pass as "number".
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": "x", "count": True},
                                  self.schema)

    def test_number_is_not_boolean(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": "x", "flag": 1}, self.schema)

    def test_undeclared_property_refused(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": "x", "zzz": 1}, self.schema)

    def test_enum_violation(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": "x", "category": "nope"},
                                  self.schema)

    def test_enum_type_strict(self):
        # True must not match an enum holding 1.
        schema = ec.validate_flat_schema({
            "type": "object",
            "properties": {"n": {"enum": [1, 2]}},
        })
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"n": True}, schema)
        ec.validate_rationale({"n": 1}, schema)

    def test_non_dict_refused(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale("just a string", self.schema)

    def test_nested_value_refused(self):
        with self.assertRaises(ec.ElicitationError):
            ec.validate_rationale({"reason": {"text": "x"}}, self.schema)


class TestCredentialShapes(unittest.TestCase):
    def test_assignment_shapes_hit(self):
        for text in ("api_key=sk-live-123", "password: hunter2",
                     "secret = abc", "token=xyz", "passwd=hunter2",
                     "Bearer abcdefghijklmnop"):
            self.assertTrue(ec.credential_material_present(text),
                            text)

    def test_ordinary_prose_misses(self):
        # Conservative: no assignment shape, no hit. A false positive
        # here would fail closed on legitimate declines.
        for text in ("the secret is out", "token expires soon",
                     "no password needed", "this looks like phishing",
                     "api key management is hard"):
            self.assertFalse(ec.credential_material_present(text),
                             text)

    def test_non_string_safe(self):
        self.assertFalse(ec.credential_material_present(None))


class TestBuildRequest(unittest.TestCase):
    def test_identity_and_summary_from_record(self):
        record = {"id": "a1", "agent_id": "agent-9", "role": "support",
                  "preview": "send_email to x",
                  "elicitation_attempts": 1}
        req = ec.build_elicitation_request(record)
        self.assertEqual(req.requester_identity,
                         {"agent_id": "agent-9", "role": "support"})
        self.assertEqual(req.action_summary,
                         sanitize_preview_text("send_email to x"))
        self.assertEqual(req.reprompts_remaining,
                         ec.MAX_ELICITATIONS - 1)
        self.assertEqual(req.approval_id, "a1")
        self.assertTrue(req.request_id.startswith("elic-"))

    def test_immutable(self):
        record = {"id": "a1", "agent_id": "a", "role": "r",
                  "preview": "p"}
        req = ec.build_elicitation_request(record)
        with self.assertRaises(AttributeError):
            req.approval_id = "zzz"

    def test_nested_schema_rejected_at_build(self):
        record = {"id": "a1", "agent_id": "a", "role": "r",
                  "preview": "p"}
        with self.assertRaises(ec.ElicitationError):
            ec.build_elicitation_request(
                record,
                rationale_schema={
                    "type": "object",
                    "properties": {"d": {"type": "object"}},
                })

    def test_render_deterministic(self):
        r1 = ec.render_rationale(
            "decline", {"b": 2, "a": "x"})
        r2 = ec.render_rationale(
            "decline", {"a": "x", "b": 2})
        self.assertEqual(r1, r2)
        self.assertIn("decline", r1)


class TestElicitDecisionSeam(unittest.TestCase):
    """Thin pins of the ApprovalQueue.elicit_decision seam (the full
    behavioral battery is evals/w278_approvalv2_probes.py)."""

    def _run_with_approval(self):
        from harness import make_run
        run = make_run()
        ident = run["executor"].mint_identity("agent-1", "support",
                                             "agent-1")
        res = run["executor"].call(
            ident, "send_email", to="v@synthetic.local",
            subject="hi", body="hi")
        self.assertEqual(res["status"], "queued")
        return run, res["approval_id"]

    def test_unknown_id_refused_and_logged(self):
        run, _ = self._run_with_approval()
        with self.assertRaises(ValueError):
            run["approvals"].elicit_decision("no-such-id", "accept")
        self.assertTrue(any(
            e.get("event") == "elicitation_refused"
            for e in run["read_log"]()))

    def test_invalid_response_refused(self):
        run, aid = self._run_with_approval()
        with self.assertRaises(ValueError):
            run["approvals"].elicit_decision(aid, "maybe")
        self.assertEqual(
            run["approvals"].get(aid)["status"], "pending")

    def test_accept_without_rationale_approves(self):
        run, aid = self._run_with_approval()
        rec, entry = run["approvals"].elicit_decision(aid, "accept")
        self.assertEqual(rec["status"], "approved")
        self.assertEqual(entry["event"], "approval_decision")
        self.assertIn("no additional rationale", entry["reason"])

    def test_max_elicitations_constant(self):
        self.assertEqual(ec.MAX_ELICITATIONS, 3)
        self.assertEqual(ec.ELICITATION_RESPONSES,
                         ("accept", "decline", "cancel"))


if __name__ == "__main__":
    unittest.main()
