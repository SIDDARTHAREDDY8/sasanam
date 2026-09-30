"""Unit tests for gov/attestation_column.py (wave-238 lane C).

The tests assert the AQTA ACTION-v1 section 8 conformance rule against
the public seam only: every audit-record field carries a closed-
vocabulary attestation class, caller-asserted fields are never readable
as issuer-verified, and the decision outcome is never readable as proof
of execution.
"""

import unittest

from gov import attestation_column as ac


def _record(**over):
    rec = {
        "outcome": "ALLOWED",
        "policy_applied": "policy/v1",
        "timestamp": "2026-09-30T14:00:00Z",
        "org_id": "org-1",
        "session_id": "sess-1",
        "action_id": "act-1",
        "tool": "read_file",
        "args_hash": "ab" * 32,
        "agent": "assistant-42",
    }
    rec.update(over)
    return rec


class VocabularyTest(unittest.TestCase):
    def test_four_classes_closed(self):
        self.assertEqual(ac.ATTESTATION_CLASSES, frozenset((
            "issuer-attested",
            "issuer-assigned",
            "caller-declared-issuer-observed",
            "caller-asserted-recorded-only",
        )))

    def test_known_fields_mapped(self):
        self.assertEqual(ac.FIELD_CLASS["outcome"], "issuer-attested")
        self.assertEqual(ac.FIELD_CLASS["policy_applied"], "issuer-attested")
        self.assertEqual(ac.FIELD_CLASS["timestamp"], "issuer-attested")
        self.assertEqual(ac.FIELD_CLASS["effect_digest"], "issuer-attested")
        self.assertEqual(ac.FIELD_CLASS["org_id"], "issuer-assigned")
        self.assertEqual(ac.FIELD_CLASS["session_id"], "issuer-assigned")
        self.assertEqual(ac.FIELD_CLASS["action_id"], "issuer-assigned")
        self.assertEqual(ac.FIELD_CLASS["tool"], "caller-declared-issuer-observed")
        self.assertEqual(ac.FIELD_CLASS["args_hash"], "caller-declared-issuer-observed")
        self.assertEqual(ac.FIELD_CLASS["agent"], "caller-asserted-recorded-only")

    def test_agent_is_caller_asserted_not_verified_shape(self):
        # The agent identity is recorded-only: the one field the spec
        # conformance rule exists to stop being presented as verified.
        self.assertEqual(
            ac.FIELD_CLASS["agent"], "caller-asserted-recorded-only")


class EmitTest(unittest.TestCase):
    def test_emit_labels_every_field(self):
        out = ac.emit(_record())
        for field, cls in ac.FIELD_CLASS.items():
            if field == "effect_digest":
                continue  # optional
            self.assertEqual(out["fields"][field]["class"], cls)

    def test_emit_preserves_record_bytes(self):
        rec = _record()
        out = ac.emit(rec)
        self.assertEqual(out["record"], rec)
        self.assertIsNot(out["record"], rec)

    def test_emit_refuses_unlabeled_field(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.emit(_record(bonus_field="x"))
        self.assertEqual(cm.exception.code, "attestation-class-unlabeled")

    def test_emit_refuses_non_dict(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.emit(["outcome"])
        self.assertEqual(cm.exception.code, "attestation-record-malformed")

    def test_emit_refuses_non_string_value(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.emit(_record(agent=42))
        self.assertEqual(cm.exception.code, "attestation-record-malformed")


class VerifiedPresentationTest(unittest.TestCase):
    def test_caller_asserted_agent_cannot_be_verified(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_verified(_record(), "agent")
        self.assertEqual(cm.exception.code, "attestation-class-inflation")

    def test_caller_declared_tool_cannot_be_verified(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_verified(_record(), "tool")
        self.assertEqual(cm.exception.code, "attestation-class-inflation")

    def test_issuer_attested_field_can_be_verified(self):
        got = ac.present_as_verified(_record(), "outcome")
        self.assertEqual(got["value"], "ALLOWED")
        self.assertEqual(got["class"], "issuer-attested")

    def test_issuer_assigned_field_can_be_verified(self):
        got = ac.present_as_verified(_record(), "session_id")
        self.assertEqual(got["value"], "sess-1")
        self.assertEqual(got["class"], "issuer-assigned")

    def test_inflation_detail_names_class_without_tamper_language(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_verified(_record(), "agent")
        detail = cm.exception.detail.lower()
        self.assertIn("agent", detail)
        self.assertIn("caller-asserted", detail)
        self.assertNotIn("tampered", detail)

    def test_missing_field_is_malformed(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_verified(_record(), "absent")
        self.assertEqual(cm.exception.code, "attestation-record-malformed")

    def test_unlabeled_field_cannot_be_verified(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_verified({"mystery": "x"}, "mystery")
        self.assertEqual(cm.exception.code, "attestation-class-unlabeled")


class DecisionOutcomeTest(unittest.TestCase):
    def test_outcome_read_as_decision(self):
        got = ac.present_as_decision({"outcome": "ALLOWED"})
        self.assertEqual(got, {"decision": "ALLOWED",
                               "class": "issuer-attested"})

    def test_outcome_not_readable_as_proof_of_execution(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_proof_of_execution({"outcome": "ALLOWED"})
        self.assertEqual(cm.exception.code, "attestation-outcome-misread")
        self.assertIn("decision only", cm.exception.detail)

    def test_effect_digest_is_proof_of_execution(self):
        rec = {"outcome": "ALLOWED", "effect_digest": "cd" * 32}
        got = ac.present_as_proof_of_execution(rec)
        self.assertEqual(got["class"], "issuer-attested")
        self.assertEqual(got["effect_digest"], "cd" * 32)

    def test_empty_effect_digest_refuses(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_proof_of_execution(
                {"outcome": "ALLOWED", "effect_digest": ""})
        self.assertEqual(cm.exception.code, "attestation-outcome-misread")

    def test_non_dict_is_malformed(self):
        with self.assertRaises(ac.AttestationColumnError) as cm:
            ac.present_as_decision(None)
        self.assertEqual(cm.exception.code, "attestation-record-malformed")


class ErrorShapeTest(unittest.TestCase):
    def test_str_carries_code_then_detail(self):
        exc = ac.AttestationColumnError("attestation-class-inflation", "d")
        self.assertEqual(str(exc), "attestation-class-inflation: d")
        self.assertEqual(exc.code, "attestation-class-inflation")

    def test_detail_optional(self):
        exc = ac.AttestationColumnError("attestation-record-malformed")
        self.assertEqual(str(exc), "attestation-record-malformed")


if __name__ == "__main__":
    unittest.main()
