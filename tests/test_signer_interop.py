#!/usr/bin/env python3
"""Unit tests for the wave-243 cosign sign-side negative interop pin
(gov/signer_interop.py: W243-1, BUILD).

Seams: the upstream-bug mimic (loud P-521/SHA-256 digest-length
failure, exact Go crypto/ecdsa text; P-256 control success), the
Sasanam wrapper (always pairs digest with signer opts; refuses the
downshift loudly), and the taxonomy mapping of the two new refusal
codes. The mimic is a deliberate tripwire: it flips when upstream
fixes the keys.go:163 hardcode -- see gov/signer_interop.py for the
upstream state pin (2026-09-30).
"""

import hashlib
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import signer_interop as sx  # noqa: E402
from gov import decision_codes as dc  # noqa: E402

PAYLOAD = b"w243-1 unit pin payload"
DIGEST64 = hashlib.sha512(PAYLOAD).digest()
DIGEST32 = hashlib.sha256(PAYLOAD).digest()
GO_TEXT = "unexpected length of digest for hash function specified"


class TestMimicTripwire(unittest.TestCase):
    def test_p521_hardcode_fails_loud(self):
        mimic = sx.MimicSignerVerifierKeypair(curve="P-521")
        self.assertEqual(mimic.hardcoded_hash, "sha256")
        with self.assertRaises(sx.SignerInteropError) as ctx:
            mimic.sign_with_digest(DIGEST64)
        self.assertIn(GO_TEXT, str(ctx.exception))
        self.assertEqual(ctx.exception.digest_len, 64)
        self.assertEqual(ctx.exception.expected_len, 32)

    def test_p521_legacy_silently_downshifts(self):
        # The dangerous path: succeeds with sha256 on P-521, no error.
        mimic = sx.MimicSignerVerifierKeypair(curve="P-521")
        sig = mimic.sign_legacy(PAYLOAD)
        self.assertEqual(mimic.legacy_digest_hash, "sha256")
        self.assertTrue(mimic.verify_legacy(PAYLOAD, sig))

    def test_p256_control_signs(self):
        mimic = sx.MimicSignerVerifierKeypair(curve="P-256")
        sig = mimic.sign_with_digest(DIGEST32)
        self.assertTrue(mimic.verify_with_digest(DIGEST32, sig))

    def test_mimic_roundtrip_p521(self):
        # Length-exact digest on P-521 signs (the length gate is the
        # only gate the mimic enforces).
        mimic = sx.MimicSignerVerifierKeypair(curve="P-521")
        sig = mimic.sign_with_digest(DIGEST32)
        self.assertTrue(mimic.verify_with_digest(DIGEST32, sig))

    def test_upstream_status_pinned(self):
        self.assertIn("closed-unmerged", sx.UPSTREAM_STATUS["#5029"])
        self.assertIn("#5074", sx.UPSTREAM_STATUS)
        self.assertIn("keys.go:163", sx.UPSTREAM_BUG_LOCATION)


class TestWrapperPairsDigestWithOpts(unittest.TestCase):
    def test_p521_sha512_happy_path(self):
        rec = sx.sign_payload_paired(PAYLOAD, hash_name="sha512",
                                     curve="P-521")
        self.assertEqual((rec["curve"], rec["hash"]), ("P-521", "sha512"))
        self.assertEqual(len(bytes.fromhex(rec["digest_hex"])), 64)
        self.assertTrue(sx.verify_record(rec))

    def test_p521_sha256_refused_loud(self):
        with self.assertRaises(sx.SignerInteropError) as ctx:
            sx.sign_payload_paired(PAYLOAD, hash_name="sha256",
                                   curve="P-521")
        self.assertEqual(ctx.exception.code,
                         "signer-hash-downshift-refused")

    def test_p256_sha256_control_signs(self):
        rec = sx.sign_payload_paired(PAYLOAD, hash_name="sha256",
                                     curve="P-256")
        self.assertTrue(sx.verify_record(rec))

    def test_digest_length_mismatch_loud(self):
        with self.assertRaises(sx.SignerInteropError) as ctx:
            sx.sign_digest_paired(DIGEST64, hash_name="sha256",
                                  curve="P-521")
        self.assertEqual(ctx.exception.code,
                         "signer-digest-length-mismatch")
        self.assertIn(GO_TEXT, str(ctx.exception))

    def test_exact_length_wrong_pairing_refused(self):
        # 32 bytes is exactly sha256's size: the length gate passes,
        # the pairing gate refuses the bug shape.
        with self.assertRaises(sx.SignerInteropError) as ctx:
            sx.sign_digest_paired(DIGEST32, hash_name="sha256",
                                  curve="P-521")
        self.assertEqual(ctx.exception.code,
                         "signer-hash-downshift-refused")

    def test_digest_path_happy(self):
        rec = sx.sign_digest_paired(DIGEST64, hash_name="sha512",
                                    curve="P-521")
        self.assertTrue(sx.verify_record(rec))

    def test_verify_record_rejects_tamper(self):
        rec = sx.sign_payload_paired(PAYLOAD, hash_name="sha512",
                                     curve="P-521")
        bad = dict(rec)
        bad["digest_hex"] = DIGEST64.hex().replace("a", "b", 1)\
            if "a" in DIGEST64.hex() else "00" + DIGEST64.hex()[2:]
        self.assertFalse(sx.verify_record(bad))
        bad2 = dict(rec)
        bad2["sig_der_hex"] = "00" * 10
        self.assertFalse(sx.verify_record(bad2))

    def test_verify_record_never_raises(self):
        self.assertFalse(sx.verify_record({}))
        self.assertFalse(sx.verify_record({"curve": "P-521"}))
        self.assertFalse(sx.verify_record(None))

    def test_unknown_hash_is_programmer_error(self):
        with self.assertRaises(ValueError):
            sx.sign_digest_paired(DIGEST64, hash_name="sha999",
                                  curve="P-521")


class TestTaxonomyMapping(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in ("signer-digest-length-mismatch",
                     "signer-hash-downshift-refused"):
            rec = dc.code_for(code)
            self.assertEqual(rec["domain"], "signer-interop")
            self.assertEqual(rec["code"], code)

    def test_taxonomy_count(self):
        # Wave-243 lane A: re-pointed 788 -> 790 (2 new codes).
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1299)  # Wave-268 merge: pin -> 1299.
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
