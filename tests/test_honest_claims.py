"""Red-first unit tests for gov/honest_claims.py (wave-233 lane C).

Public seams only: RESERVED_CLAIM_TOKENS membership,
find_reserved_claim scan semantics, assert_no_reserved_claims
refusal shape, and the no-bypass invariant. Deterministic, $0.
"""

import inspect
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import honest_claims as hc


class TestVocabulary(unittest.TestCase):
    def test_vocabulary_is_closed(self):
        self.assertIsInstance(hc.RESERVED_CLAIM_TOKENS, frozenset)

    def test_expected_tokens_present(self):
        for tok in ("proves-execution", "proves-human-understanding",
                    "non-repudiation", "tamper-proof", "formally-verified"):
            self.assertIn(tok, hc.RESERVED_CLAIM_TOKENS)

    def test_integrity_claim_not_reserved(self):
        # "tamper-evident" is an integrity claim evidence CAN prove;
        # it must never be refused.
        self.assertNotIn("tamper-evident", hc.RESERVED_CLAIM_TOKENS)


class TestScanSemantics(unittest.TestCase):
    def test_exact_token_found(self):
        self.assertEqual(
            hc.find_reserved_claim({"c": "guaranteed tamper-proof"}),
            "tamper-proof")

    def test_variant_normalized(self):
        self.assertEqual(hc.find_reserved_claim("Tamper_Proof x"),
                         "tamper-proof")
        self.assertEqual(hc.find_reserved_claim("PROVES EXECUTION x"),
                         "proves-execution")

    def test_clean_artifact_none(self):
        self.assertIsNone(hc.find_reserved_claim(
            {"v": 1, "claims": ["bundle-digest-integrity"]}))
        self.assertIsNone(hc.find_reserved_claim("nothing to see"))

    def test_keys_never_scanned(self):
        # A receipt's own "non_repudiation" KEY must not trip the scan.
        self.assertIsNone(
            hc.find_reserved_claim({"non_repudiation": False, "v": 1}))

    def test_does_not_prove_exempt(self):
        self.assertIsNone(hc.find_reserved_claim({
            "claim_bounds": {"proves": ["bundle-digest-integrity"],
                             "does_not_prove": ["non-repudiation"]}}))

    def test_nested_lists_scanned(self):
        self.assertEqual(
            hc.find_reserved_claim(["ok", ["formally-verified ok"]]),
            "formally-verified")

    def test_bytes_decoded(self):
        self.assertEqual(hc.find_reserved_claim(b"tamper-proof x"),
                         "tamper-proof")

    def test_non_string_scalars_ignored(self):
        self.assertIsNone(hc.find_reserved_claim(42))
        self.assertIsNone(hc.find_reserved_claim(None))


class TestRefusal(unittest.TestCase):
    def test_refusal_names_exact_token(self):
        with self.assertRaises(hc.HonestClaimError) as ctx:
            hc.assert_no_reserved_claims("formally-verified by us")
        self.assertEqual(ctx.exception.token, "formally-verified")
        self.assertEqual(ctx.exception.code,
                         "honest-claim-reserved-token")

    def test_refusal_code_registered(self):
        from gov import decision_codes as dc
        self.assertIn("honest-claim-reserved-token", dc.TAXONOMY)
        entry = dc.TAXONOMY["honest-claim-reserved-token"]
        self.assertEqual(entry["domain"], "honest_claims")

    def test_clean_artifact_passes(self):
        self.assertIsNone(hc.assert_no_reserved_claims({"a": "b"}))

    def test_no_bypass_keyword(self):
        params = list(inspect.signature(
            hc.assert_no_reserved_claims).parameters)
        self.assertEqual(params, ["artifact"])


if __name__ == "__main__":
    unittest.main()
