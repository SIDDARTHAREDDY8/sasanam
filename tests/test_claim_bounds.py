"""Unit tests for gov/claim_bounds.py (wave-209 lane A).

The red-first battery (evals/claim_bounds_probes.py) covers the
public seams break-first; these unit tests pin the schema rules.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import claim_bounds as cb


def _good():
    return {"proves": ["a-proven-thing"],
            "does_not_prove": ["a-not-proven-thing"],
            "verifier_assumptions": ["an-assumption"],
            "scope_limits": ["a-scope-limit"]}


class ValidateBoundsTest(unittest.TestCase):
    def test_accepts_well_formed(self):
        norm = cb.validate_bounds(_good())
        self.assertEqual(norm["proves"], ["a-proven-thing"])

    def test_missing_field_named(self):
        for field in cb.REQUIRED_FIELDS:
            bad = _good()
            del bad[field]
            with self.assertRaises(cb.ClaimBoundsError) as cm:
                cb.validate_bounds(bad)
            self.assertIn(field, str(cm.exception))

    def test_not_a_dict(self):
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_bounds(["proves"])

    def test_unknown_field_refused(self):
        bad = _good()
        bad["proves_extra"] = ["x"]
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.validate_bounds(bad)
        self.assertIn("proves_extra", str(cm.exception))

    def test_empty_does_not_prove_refused(self):
        bad = _good()
        bad["does_not_prove"] = []
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.validate_bounds(bad)
        self.assertIn("does_not_prove", str(cm.exception))

    def test_empty_proves_refused(self):
        bad = _good()
        bad["proves"] = []
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_bounds(bad)

    def test_non_string_token_refused(self):
        bad = _good()
        bad["proves"] = ["ok", 42]
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_bounds(bad)

    def test_incoherent_token_named(self):
        bad = _good()
        bad["does_not_prove"] = ["a-proven-thing"]
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.validate_bounds(bad)
        self.assertIn("a-proven-thing", str(cm.exception))

    def test_duplicate_token_refused(self):
        bad = _good()
        bad["proves"] = ["a-proven-thing", "a-proven-thing"]
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_bounds(bad)

    def test_returns_copy(self):
        bounds = _good()
        norm = cb.validate_bounds(bounds)
        norm["proves"].append("mutated")
        self.assertEqual(bounds["proves"], ["a-proven-thing"])


class OverlapTest(unittest.TestCase):
    def test_covered_accepted(self):
        cb.claims_within_bounds("here", ["a", "b"], ["a", "b", "c"])

    def test_empty_claims_accepted(self):
        cb.claims_within_bounds("here", [], ["a"])

    def test_stray_named(self):
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.claims_within_bounds("here", ["zzz"], ["a"])
        self.assertIn("zzz", str(cm.exception))

    def test_non_list_claims_refused(self):
        with self.assertRaises(cb.ClaimBoundsError):
            cb.claims_within_bounds("here", "a", ["a"])


class AssignmentTest(unittest.TestCase):
    def test_exact_set_enforced(self):
        proves = ["p1", "p2"]
        ok = {"s1": ["p1"], "s2": ["p2"]}
        cb.validate_claim_assignment(ok, ["s1", "s2"], proves)
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_claim_assignment({"s1": ["p1"]}, ["s1", "s2"],
                                         proves)
        with self.assertRaises(cb.ClaimBoundsError):
            cb.validate_claim_assignment(
                {"s1": ["p1"], "s2": ["p2"], "s3": ["p1"]},
                ["s1", "s2"], proves)

    def test_stray_token_named(self):
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.validate_claim_assignment({"s1": ["nope"]}, ["s1"], ["p1"])
        self.assertIn("nope", str(cm.exception))


class DefaultsTest(unittest.TestCase):
    def test_default_bounds_validate(self):
        bounds = cb.default_bundle_bounds()
        self.assertTrue(bounds["does_not_prove"])

    def test_default_assignment_agrees(self):
        sections = ["bundle_meta", "log_slice", "policy", "decisions",
                    "approvals", "citations", "benchmark",
                    "kms_attestation", "retention_manifest", "discovery"]
        bounds = cb.default_bundle_bounds()
        assign = cb.default_claim_assignment(
            sections, bounds["proves"], discovery_present=True)
        cb.validate_claim_assignment(assign, sections, bounds["proves"])
        assign2 = cb.default_claim_assignment(
            sections, bounds["proves"], discovery_present=False)
        self.assertEqual(assign2["discovery"],
                         ["discovery-absence-recorded"])

    def test_unknown_section_refused(self):
        bounds = cb.default_bundle_bounds()
        with self.assertRaises(cb.ClaimBoundsError) as cm:
            cb.default_claim_assignment(["mystery"], bounds["proves"],
                                        discovery_present=True)
        self.assertIn("mystery", str(cm.exception))


class BridgeTest(unittest.TestCase):
    def test_vc_bridge(self):
        canon = cb.from_vc_bounds({"proves": ["vp"],
                                   "doesNotProve": ["vdnp"]})
        self.assertEqual(canon["proves"], ["vp"])
        self.assertEqual(canon["does_not_prove"], ["vdnp"])
        self.assertTrue(canon["verifier_assumptions"])
        self.assertTrue(canon["scope_limits"])

    def test_vc_bridge_empty_dnp_refused(self):
        with self.assertRaises(cb.ClaimBoundsError):
            cb.from_vc_bounds({"proves": ["vp"], "doesNotProve": []})

    def test_vc_bridge_not_dict(self):
        with self.assertRaises(cb.ClaimBoundsError):
            cb.from_vc_bounds("nope")


if __name__ == "__main__":
    unittest.main()
