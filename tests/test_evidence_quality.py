"""Unit tests for gov/evidence_quality.py (wave-256 lane 3).

Pins the public-seam contracts: closed expectation vocabulary,
fail-closed evaluation, validation-result shape, quality gate in
front of the compliance emitter, taxonomy codes, immutability.
"""

import copy
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes  # noqa: E402
from gov import evidence_quality as eq  # noqa: E402

# Wave-256 lane 3: re-pointed to 1040 (1040 + 4 evidence-quality),
# additive only.


class TestTaxonomy(unittest.TestCase):
    def test_pin(self):
        self.assertEqual(len(decision_codes.TAXONOMY), 1976)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)

    def test_pin_unique(self):
        self.assertEqual(len(set(decision_codes.TAXONOMY)), 1976)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1857 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1857 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)

    def test_codes_resolve(self):
        for code in ("evidence-quality-evidence-malformed",
                     "evidence-quality-gate-failed",
                     "evidence-quality-malformed",
                     "evidence-quality-unknown-expectation"):
            rec = decision_codes.code_for(code)
            self.assertEqual(rec["code"], code)
            self.assertEqual(rec["domain"], "evidence-quality")


def _mono(n=3):
    return [{"seq": i + 1} for i in range(n)]


def _exp(exp_type, **kwargs):
    return {"expectation_type": exp_type, "kwargs": kwargs}


class TestValidateExpectation(unittest.TestCase):
    def test_unknown_type_refuses(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.validate_expectation(
                {"expectation_type": "expect_nope", "kwargs": {}})
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-unknown-expectation")

    def test_malformed_shapes_refuse(self):
        for bad in (None, "x", {"kwargs": {}},
                    {"expectation_type": 42}):
            with self.assertRaises(eq.EvidenceQualityError) as ctx:
                eq.validate_expectation(bad)
            self.assertIn(ctx.exception.code,
                          ("evidence-quality-malformed",
                           "evidence-quality-unknown-expectation"))

    def test_unknown_kwarg_refuses(self):
        # A typo'd kwarg must never silently change the check.
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.validate_expectation(
                _exp("expect_evidence_monotonic",
                     sequence_fiel="seq"))
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-malformed")

    def test_required_kwargs_enforced(self):
        with self.assertRaises(eq.EvidenceQualityError):
            eq.validate_expectation(
                _exp("expect_bundle_complete"))  # no artifacts
        with self.assertRaises(eq.EvidenceQualityError):
            eq.validate_expectation(
                _exp("expect_fields_present"))  # no required_fields

    def test_normalized_deep_copy(self):
        src = _exp("expect_evidence_monotonic")
        out = eq.validate_expectation(src)
        self.assertEqual(out["kwargs"]["sequence_field"], "seq")
        self.assertTrue(out["kwargs"]["strict"])
        out["kwargs"]["strict"] = False
        self.assertTrue(
            eq.validate_expectation(src)["kwargs"]["strict"])


class TestEvaluate(unittest.TestCase):
    def test_empty_expectations_refused(self):
        # A vacuous gate must never pass.
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.evaluate([], _mono())
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-malformed")

    def test_monotonic_clean(self):
        res = eq.evaluate([_exp("expect_evidence_monotonic")],
                          _mono())
        self.assertTrue(res["success"])
        self.assertEqual(len(res["results"]), 1)
        self.assertIsNone(res["results"][0]["exception_info"])

    def test_result_shape(self):
        res = eq.evaluate([_exp("expect_evidence_monotonic")],
                          _mono())
        stats = res["statistics"]
        self.assertEqual(stats["evaluated_expectations"], 1)
        self.assertEqual(stats["successful_expectations"], 1)
        self.assertEqual(stats["unsuccessful_expectations"], 0)
        self.assertIn("evaluated_at", res["meta"])
        self.assertEqual(res["meta"]["module"],
                         "gov/evidence_quality.py")

    def test_malformed_evidence_refuses(self):
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.evaluate([_exp("expect_evidence_monotonic")],
                        "not-a-list")
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-evidence-malformed")

    def test_does_not_mutate_inputs(self):
        exps = [_exp("expect_evidence_monotonic")]
        items = _mono()
        e0, i0 = copy.deepcopy(exps), copy.deepcopy(items)
        eq.evaluate(exps, items)
        self.assertEqual(exps, e0)
        self.assertEqual(items, i0)

    def test_chain_roundtrip(self):
        import hashlib
        import json
        items, prev = [], None
        for i in range(3):
            body = {"seq": i + 1}
            digest = hashlib.sha256(
                json.dumps(body, sort_keys=True,
                           separators=(",", ":")).encode()).hexdigest()
            items.append(dict(body, digest=digest,
                              prev_digest=prev))
            prev = digest
        res = eq.evaluate([_exp("expect_chain_intact")], items)
        self.assertTrue(res["success"])

    def test_bundle_complete_clean(self):
        bundle = {"items": [{"artifact_ref": "a1"}]}
        res = eq.evaluate(
            [_exp("expect_bundle_complete",
                  artifacts={"a1": {}})], bundle)
        self.assertTrue(res["success"])


class TestQualityGate(unittest.TestCase):
    def _source(self):
        return {
            "id": "SAS-EQ-T",
            "title": "t",
            "description": "d",
            "mappings": [
                {"kind": "code",
                 "ref": "evidence-quality-gate-failed",
                 "rationale": "r"},
            ],
        }

    def test_gate_refuses_on_failure(self):
        items = _mono()
        items[1]["seq"] = 1
        with self.assertRaises(eq.EvidenceQualityError) as ctx:
            eq.emit_with_quality_gate(
                self._source(), "json",
                [_exp("expect_evidence_monotonic")], items)
        self.assertEqual(ctx.exception.code,
                         "evidence-quality-gate-failed")
        self.assertIn("expect_evidence_monotonic",
                      str(ctx.exception))

    def test_gate_emits_on_clean(self):
        out = eq.emit_with_quality_gate(
            self._source(), "json",
            [_exp("expect_evidence_monotonic")], _mono())
        self.assertIn("SAS-EQ-T", out)


if __name__ == "__main__":
    unittest.main()
