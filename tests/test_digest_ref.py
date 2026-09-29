"""Unit tests for gov/digest_ref.py (wave-199: digest-first-class identity).

Break-first discipline: these tests pin the PUBLIC contract --
construction-time tag refusal and structural identity at the seams --
not tautological internals. Red evidence for this lane was captured on
pristine 1efce86 (bare str identity at every seam); these tests are the
green side on the fixed tree.
"""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov.digest_ref import DigestRef, DigestRefError

H = "ab" * 32  # 64 hex chars
H_UPPER = H.upper()
REPO = "sasanam/evidence"


class TestDigestRefParse(unittest.TestCase):
    def test_parse_valid(self):
        r = DigestRef.parse(REPO + "@sha256:" + H)
        self.assertEqual(r.repo, REPO)
        self.assertEqual(r.algorithm, "sha256")
        self.assertEqual(r.hex, H)
        self.assertEqual(r.digest, "sha256:" + H)
        self.assertEqual(r.reference, REPO + "@sha256:" + H)
        self.assertEqual(str(r), r.reference)

    def test_parse_registry_with_port_and_path(self):
        r = DigestRef.parse("registry.local:5000/ns/img@sha256:" + H)
        self.assertEqual(r.repo, "registry.local:5000/ns/img")
        self.assertEqual(r.reference,
                         "registry.local:5000/ns/img@sha256:" + H)

    def test_parse_uppercase_hex_canonicalizes_lowercase(self):
        r = DigestRef.parse(REPO + "@sha256:" + H_UPPER)
        self.assertEqual(r.hex, H)
        self.assertEqual(r.digest, "sha256:" + H)

    def test_parse_refuses_tag(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse(REPO + ":latest")

    def test_parse_refuses_bare_tag(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse("latest")

    def test_parse_refuses_digest_only(self):
        # Digest-only identities come through from_hex, never parse:
        # parse requires repo@digest, so a bare digest here is a shape
        # error, not an identity.
        with self.assertRaises(DigestRefError):
            DigestRef.parse("sha256:" + H)

    def test_parse_refuses_short_hex(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse(REPO + "@sha256:" + "ab" * 31)

    def test_parse_refuses_non_hex(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse(REPO + "@sha256:" + "zz" * 32)

    def test_parse_refuses_unknown_algorithm(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse(REPO + "@sha512:" + H)

    def test_parse_refuses_whitespace(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse("  " + REPO + "@sha256:" + H + "  ")

    def test_parse_refuses_empty(self):
        with self.assertRaises(DigestRefError):
            DigestRef.parse("")

    def test_parse_non_string_raises_type_error(self):
        for bad in (None, 123, b"sasanam/evidence@sha256:" + H.encode()):
            with self.assertRaises(TypeError):
                DigestRef.parse(bad)

    def test_digest_ref_error_is_value_error(self):
        self.assertTrue(issubclass(DigestRefError, ValueError))


class TestDigestRefFromHex(unittest.TestCase):
    def test_from_hex_plain(self):
        d = DigestRef.from_hex(H)
        self.assertIsNone(d.repo)
        self.assertEqual(d.hex, H)
        self.assertEqual(d.digest, "sha256:" + H)
        self.assertEqual(d.reference, "sha256:" + H)

    def test_from_hex_prefixed(self):
        d = DigestRef.from_hex("sha256:" + H)
        self.assertEqual(d.digest, "sha256:" + H)

    def test_from_hex_uppercase_canonicalizes(self):
        d = DigestRef.from_hex(H_UPPER)
        self.assertEqual(d.hex, H)

    def test_from_hex_idempotent(self):
        d = DigestRef.from_hex(H)
        self.assertIs(DigestRef.from_hex(d), d)

    def test_from_hex_refuses_tag_shaped(self):
        with self.assertRaises(DigestRefError):
            DigestRef.from_hex(REPO + ":latest")

    def test_from_hex_refuses_repo_digest(self):
        with self.assertRaises(DigestRefError):
            DigestRef.from_hex(REPO + "@sha256:" + H)

    def test_from_hex_refuses_short(self):
        with self.assertRaises(DigestRefError):
            DigestRef.from_hex("ab" * 31)

    def test_from_hex_non_string_raises_type_error(self):
        with self.assertRaises(TypeError):
            DigestRef.from_hex(None)


class TestDigestRefValueSemantics(unittest.TestCase):
    def test_equality_and_hash(self):
        a = DigestRef.parse(REPO + "@sha256:" + H)
        b = DigestRef.parse(REPO + "@sha256:" + H_UPPER)
        c = DigestRef.from_hex(H)
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        # Repo is part of identity: digest-only != repo-bound.
        self.assertNotEqual(a, c)
        self.assertEqual(len({a, b, c}), 2)

    def test_equality_never_matches_str(self):
        a = DigestRef.parse(REPO + "@sha256:" + H)
        self.assertFalse(a == "sha256:" + H)
        self.assertFalse(a == REPO + "@sha256:" + H)
        self.assertTrue(a != "sha256:" + H)

    def test_immutable(self):
        a = DigestRef.parse(REPO + "@sha256:" + H)
        with self.assertRaises(AttributeError):
            a.repo = "other"
        b = copy.copy(a)
        self.assertEqual(a, b)

    def test_repr(self):
        a = DigestRef.parse(REPO + "@sha256:" + H)
        self.assertEqual(repr(a), "DigestRef(%r)" % (REPO + "@sha256:" + H,))


if __name__ == "__main__":
    unittest.main()
