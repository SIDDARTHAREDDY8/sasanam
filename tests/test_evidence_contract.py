#!/usr/bin/env python3
"""Unit tests for seal-time evidence contracts (gov/evidence_contract.py).

Wave-279 (sealer-as-authority, Chainloop PR #3465 steal): the sealer
validates the artifact body against the invocation class's evidence
contract at seal time, and the assembler pre-check uses the SAME
validator -- one implementation, no drift.

Conventions: staging default; fixed fixtures; refusal lattice asserts
``ContractRefused.code`` is exactly ``evbundle-contract-refused``;
the lane-local taxonomy pin is asserted on raw source literals, never
``len(dict)`` (wave-260).
"""

import os
import re
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import evidence_contract as c  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

APPROVAL = "a" * 32
INTENT = "d" * 64

LANE_PIN = 1820  # Wave-279 lane 2: 1493 + evbundle-contract-refused; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*)


def _count_code_literals():
    # Same quoted-literal convention as the w278 pin battery: only
    # registrations match (the two "code": <expr> emit sites do not).
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    return len(re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src))


class ContractLoadingTest(unittest.TestCase):
    def test_three_classes_shipped(self):
        self.assertEqual(sorted(c.list_classes()),
                         ["approval_decision", "redteam_probe",
                          "tool_execution"])

    def test_contracts_cached_and_stable(self):
        a = c.load_contract(invocation_class="tool_execution")
        b = c.load_contract(invocation_class="tool_execution")
        self.assertIs(a, b)
        self.assertEqual(a["invocation_class"], "tool_execution")
        self.assertEqual(a["revision"], 1)

    def test_unknown_class_refused_with_code(self):
        with self.assertRaises(c.ContractRefused) as ctx:
            c.load_contract(invocation_class="nope_not_a_class")
        self.assertEqual(ctx.exception.code, "evbundle-contract-refused")
        self.assertTrue(any(v["reason"] == "unknown-invocation-class"
                            for v in ctx.exception.violations))


class ResolveClassTest(unittest.TestCase):
    def test_body_declaration_resolves(self):
        self.assertEqual(
            c.resolve_class(artifact_body={"invocation_class": "tool_execution"}),
            "tool_execution")

    def test_kwarg_wins_over_body(self):
        self.assertEqual(
            c.resolve_class(artifact_body={"invocation_class": "tool_execution"},
                            invocation_class="approval_decision"),
            "approval_decision")

    def test_absent_class_is_legacy_none(self):
        self.assertIsNone(c.resolve_class(artifact_body={"decision": "deny"}))

    def test_empty_class_refused(self):
        with self.assertRaises(c.ContractRefused) as ctx:
            c.resolve_class(artifact_body={"invocation_class": "  "})
        self.assertEqual(ctx.exception.code, "evbundle-contract-refused")


class ValidateArtifactTest(unittest.TestCase):
    def _tool_body(self, **over):
        body = {"invocation_class": "tool_execution",
                "approval_id": APPROVAL, "intent_digest": INTENT,
                "tool_output_digest": "e" * 64, "decision": "approve",
                "policy_version": "policy.v42"}
        body.update(over)
        return body

    def test_compliant_body_no_violations(self):
        self.assertEqual(c.validate_artifact(artifact_body=self._tool_body()), [])

    def test_each_material_missing_is_violation(self):
        for field in ("approval_id", "intent_digest", "tool_output_digest",
                      "decision", "policy_version"):
            body = self._tool_body()
            del body[field]
            vs = c.validate_artifact(artifact_body=body)
            self.assertEqual(len(vs), 1, field)
            self.assertEqual(vs[0]["material"], field)

    def test_empty_string_fails_required_string(self):
        vs = c.validate_artifact(artifact_body=self._tool_body(approval_id=""))
        self.assertTrue(any(v["reason"] == "required-string-absent"
                            for v in vs))

    def test_non_hex_digest_fails(self):
        vs = c.validate_artifact(
            artifact_body=self._tool_body(tool_output_digest="not-hex"))
        self.assertTrue(any(v["reason"] == "digest64-malformed"
                            for v in vs))

    def test_uppercase_digest_fails(self):
        vs = c.validate_artifact(
            artifact_body=self._tool_body(intent_digest="D" * 64))
        self.assertTrue(any(v["reason"] == "digest64-malformed"
                            for v in vs))

    def test_out_of_vocabulary_decision_fails(self):
        vs = c.validate_artifact(artifact_body=self._tool_body(decision="maybe"))
        self.assertTrue(any(v["reason"] == "out-of-vocabulary"
                            for v in vs))

    def test_all_three_vocab_values_pass(self):
        for d in ("approve", "decline", "cancel"):
            self.assertEqual(c.validate_artifact(artifact_body=self._tool_body(
                decision=d)), [], d)

    def test_unknown_class_raises_coded(self):
        with self.assertRaises(c.ContractRefused) as ctx:
            c.validate_artifact(artifact_body={"invocation_class": "nope"})
        self.assertEqual(ctx.exception.code, "evbundle-contract-refused")

    def test_legacy_unclassed_body_passes(self):
        self.assertEqual(c.validate_artifact(artifact_body={"decision": "deny"}), [])

    def test_non_dict_body_with_kwarg_class_is_coded_refusal(self):
        # Spec-review fix (wave-279 lane 2): the kwarg path must not
        # AttributeError on .get -- non-mapping bodies are coded.
        for bad in (None, ["not", "a", "dict"], "nope"):
            with self.assertRaises(c.ContractRefused) as ctx:
                c.validate_artifact(artifact_body=bad,
                                    invocation_class="tool_execution")
            self.assertEqual(ctx.exception.code,
                             "evbundle-contract-refused")
            self.assertTrue(any(v["reason"] == "body-not-a-mapping"
                                for v in ctx.exception.violations))

    def test_validate_or_raise_non_dict_kwarg(self):
        with self.assertRaises(c.ContractRefused) as ctx:
            c.validate_or_raise(artifact_body=None,
                                invocation_class="redteam_probe")
        self.assertEqual(ctx.exception.code, "evbundle-contract-refused")

    def test_extra_fields_ignored(self):
        body = self._tool_body(extra="anything")
        self.assertEqual(c.validate_artifact(artifact_body=body), [])

    def test_approval_decision_class(self):
        good = {"invocation_class": "approval_decision",
                "approval_id": APPROVAL, "decision": "approve",
                "decider": "alice", "rationale": "looks fine"}
        self.assertEqual(c.validate_artifact(artifact_body=good), [])
        bad = dict(good, rationale="")
        self.assertTrue(c.validate_artifact(artifact_body=bad))

    def test_redteam_probe_class(self):
        good = {"invocation_class": "redteam_probe", "probe_id": "p1",
                "battery_digest": "f" * 64, "expected": "BREAK",
                "actual": "HELD"}
        self.assertEqual(c.validate_artifact(artifact_body=good), [])
        bad = dict(good, actual="PASS")
        vs = c.validate_artifact(artifact_body=bad)
        self.assertTrue(any(v["reason"] == "out-of-vocabulary"
                            for v in vs))

    def test_validate_or_raise(self):
        self.assertIs(c.validate_or_raise(artifact_body=self._tool_body()), True)
        with self.assertRaises(c.ContractRefused) as ctx:
            c.validate_or_raise(artifact_body={"invocation_class": "tool_execution"})
        self.assertEqual(ctx.exception.code, "evbundle-contract-refused")
        self.assertEqual(len(ctx.exception.violations), 5)


class PrecheckTest(unittest.TestCase):
    def test_precheck_shape(self):
        out = c.precheck_artifact(artifact_body={"invocation_class": "tool_execution"})
        self.assertFalse(out["ok"])
        self.assertEqual(out["invocation_class"], "tool_execution")
        self.assertTrue(out["violations"])

    def test_precheck_legacy_ok(self):
        out = c.precheck_artifact(artifact_body={"decision": "deny"})
        self.assertTrue(out["ok"])
        self.assertIsNone(out["invocation_class"])
        self.assertEqual(out["violations"], [])

    def test_precheck_unknown_class_not_ok(self):
        out = c.precheck_artifact(artifact_body={"invocation_class": "nope"})
        self.assertFalse(out["ok"])

    def test_precheck_is_non_raising(self):
        # None body: resolve_class raises, precheck must not.
        out = c.precheck_artifact(artifact_body=None)
        self.assertFalse(out["ok"])

    def test_precheck_non_dict_with_kwarg_stays_non_raising(self):
        # Spec-review fix: the kwarg path must not raise either, and
        # must report the kwarg class honestly.
        out = c.precheck_artifact(artifact_body=None, invocation_class="tool_execution")
        self.assertFalse(out["ok"])
        self.assertEqual(out["invocation_class"], "tool_execution")
        self.assertTrue(any(v["reason"] == "body-not-a-mapping"
                            for v in out["violations"]))


class TaxonomyPinTest(unittest.TestCase):
    def test_lane_pin_on_raw_literals(self):
        # Wave-279 lane 2 pin: base 1493 + evbundle-contract-refused.
        self.assertEqual(_count_code_literals(), LANE_PIN)
        self.assertIn("evbundle-contract-refused", TAXONOMY)
        entry = TAXONOMY["evbundle-contract-refused"]
        self.assertEqual(entry["domain"], "evbundle")
        self.assertEqual(entry["severity"], "medium")


if __name__ == "__main__":
    unittest.main()
