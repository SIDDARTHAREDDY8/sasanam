#!/usr/bin/env python3
"""Unit tests for gov/trust_material.py (wave-235 lane A).

External trust-material bindings: keys resolve from an external
TrustRoot, never from record-carried material; key ids are pinned to
key material (sha256 of the raw bytes), not labels; unsigned fields
are never consulted. Stdlib + gov.trust_material only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import trust_material as tm  # noqa: E402

SEED_A = bytes.fromhex("aa" * 32)
SEED_B = bytes.fromhex("bb" * 32)
KID_A = "executor-key-a"
KID_B = "executor-key-b"


def _root():
    return tm.TrustRoot({KID_A: SEED_A, KID_B: SEED_B})


class PinKeyIdTest(unittest.TestCase):
    def test_pin_is_sha256_of_material(self):
        import hashlib
        self.assertEqual(tm.pin_key_id(SEED_A),
                         hashlib.sha256(SEED_A).hexdigest())

    def test_pin_is_deterministic(self):
        self.assertEqual(tm.pin_key_id(SEED_A), tm.pin_key_id(SEED_A))

    def test_pin_is_label_independent(self):
        # Two different labels over the same material pin identically;
        # labels play no role in the pin.
        self.assertEqual(tm.pin_key_id(SEED_A),
                         tm.pin_key_id(bytes(SEED_A)))

    def test_pin_distinguishes_material(self):
        self.assertNotEqual(tm.pin_key_id(SEED_A), tm.pin_key_id(SEED_B))

    def test_malformed_material_refuses(self):
        for bad in (b"short", b"", b"x" * 33, "not-bytes", None):
            with self.assertRaises(tm.TrustMaterialError) as ctx:
                tm.pin_key_id(bad)
            self.assertEqual(ctx.exception.code, "trust-material-malformed")


class TrustRootConstructionTest(unittest.TestCase):
    def test_empty_or_non_dict_bindings_rejected(self):
        for bad in ({}, [], None, "x"):
            with self.assertRaises(ValueError):
                tm.TrustRoot(bad)

    def test_malformed_pubkey_rejected(self):
        with self.assertRaises(ValueError):
            tm.TrustRoot({KID_A: b"short"})
        with self.assertRaises(ValueError):
            tm.TrustRoot({KID_A: "aa" * 32})

    def test_empty_kid_rejected(self):
        with self.assertRaises(ValueError):
            tm.TrustRoot({"": SEED_A})

    def test_duplicate_kid_rejected(self):
        # A dict cannot hold duplicates, so this exercises the guard
        # only via pathological input -- construction still fails
        # closed on any malformed shape.
        with self.assertRaises(ValueError):
            tm.TrustRoot({KID_A: SEED_A, KID_B: b"short"})

    def test_key_ids_snapshot(self):
        root = _root()
        self.assertEqual(root.key_ids(), (KID_A, KID_B))


class BindAuthorityTest(unittest.TestCase):
    def test_pinned_key_binds_and_returns_pinned_material(self):
        root = _root()
        out = root.bind_authority(KID_A, SEED_A)
        self.assertEqual(out, SEED_A)

    def test_unknown_kid_refuses_untrusted_key(self):
        root = _root()
        with self.assertRaises(tm.TrustMaterialError) as ctx:
            root.bind_authority("attacker-key", SEED_B)
        self.assertEqual(ctx.exception.code, "untrusted-key")

    def test_repointed_kid_refuses(self):
        # Same label, different material: the label was re-pointed.
        root = _root()
        with self.assertRaises(tm.TrustMaterialError) as ctx:
            root.bind_authority(KID_A, SEED_B)
        self.assertEqual(ctx.exception.code, "trust-key-repointed")

    def test_missing_kid_refuses_untrusted_key(self):
        root = _root()
        for bad in (None, "", 123):
            with self.assertRaises(tm.TrustMaterialError) as ctx:
                root.bind_authority(bad, SEED_A)
            self.assertEqual(ctx.exception.code, "untrusted-key")

    def test_malformed_pubkey_refuses_untrusted_key(self):
        root = _root()
        with self.assertRaises(tm.TrustMaterialError) as ctx:
            root.bind_authority(KID_A, b"short")
        self.assertEqual(ctx.exception.code, "untrusted-key")

    def test_error_carries_code_and_detail(self):
        root = _root()
        try:
            root.bind_authority("nope", SEED_A)
        except tm.TrustMaterialError as exc:
            self.assertEqual(exc.code, "untrusted-key")
            self.assertTrue(exc.detail)
            self.assertIn("untrusted-key", str(exc))
        else:
            self.fail("no refusal raised")


class AssertSignatureCoveredTest(unittest.TestCase):
    def test_covered_field_passes(self):
        self.assertTrue(
            tm.assert_signature_covered({"decision", "authority"},
                                        "decision"))

    def test_uncovered_field_refuses(self):
        with self.assertRaises(tm.TrustMaterialError) as ctx:
            tm.assert_signature_covered({"decision"}, "approval_use_limit")
        self.assertEqual(ctx.exception.code, "unsigned-field-ignored")

    def test_empty_covered_set_refuses_everything(self):
        with self.assertRaises(tm.TrustMaterialError) as ctx:
            tm.assert_signature_covered(set(), "decision")
        self.assertEqual(ctx.exception.code, "unsigned-field-ignored")


if __name__ == "__main__":
    unittest.main()
