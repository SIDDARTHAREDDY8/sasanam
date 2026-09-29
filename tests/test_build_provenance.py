#!/usr/bin/env python3
"""Wave-202 lane B: unit tests for gov.build_provenance (public seams).

Hermetic: fixed Ed25519 seeds, no network. The tests/__init__ harness
provisions the audit-log HMAC key process-wide.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from gov import build_provenance as bp
from gov.signing import Ed25519Signer, Ed25519Verifier


def _signers():
    s1 = Ed25519Signer(bytes([1]) * 32)
    s2 = Ed25519Signer(bytes([2]) * 32)
    return s1, Ed25519Verifier(s1.public_key, s1.key_id), \
        s2, Ed25519Verifier(s2.public_key, s2.key_id)


def _stmt(artifact="aa" * 32):
    return bp.ProvenanceStatement(
        builder="ci-builder-1",
        recipe="repo@sha256:" + "ab" * 32,
        inputs=[
            bp.ProvenanceInput(name="src.tar.gz", digest_hex="aa" * 32,
                               deterministic=True),
            bp.ProvenanceInput(name="entropy.bin", digest_hex="bb" * 32,
                               deterministic=False),
        ],
        artifact_hex=artifact,
        built_at=1700000000,
    )


class ProvenanceStatementTests(unittest.TestCase):
    def test_recipe_must_be_digest_pinned(self):
        with self.assertRaises(bp.ProvenanceError):
            bp.ProvenanceStatement(
                builder="b", recipe="repo:latest", inputs=[
                    bp.ProvenanceInput(name="i", digest_hex="aa" * 32,
                                       deterministic=True)],
                artifact_hex="aa" * 32, built_at=1)

    def test_empty_inputs_refused(self):
        with self.assertRaises(bp.ProvenanceError):
            bp.ProvenanceStatement(
                builder="b", recipe="repo@sha256:" + "ab" * 32, inputs=[],
                artifact_hex="aa" * 32, built_at=1)

    def test_deterministic_must_be_bool(self):
        with self.assertRaises(bp.ProvenanceError):
            bp.ProvenanceInput(name="i", digest_hex="aa" * 32,
                               deterministic="yes")

    def test_bad_digest_refused(self):
        with self.assertRaises(bp.ProvenanceError):
            bp.ProvenanceInput(name="i", digest_hex="nothex",
                               deterministic=True)


class SealVerifyTests(unittest.TestCase):
    def test_round_trip(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        stmt = bp.verify_sealed_statement(
            sealed, expected_artifact_hex="aa" * 32, verifier=v1)
        self.assertEqual(stmt.builder, "ci-builder-1")
        self.assertEqual(len(stmt.inputs), 2)

    def test_wrong_artifact_refused(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        with self.assertRaises(bp.ProvenanceError):
            bp.verify_sealed_statement(
                sealed, expected_artifact_hex="cc" * 32, verifier=v1)

    def test_wrong_key_refused(self):
        s1, _, _, v2 = _signers()
        sealed = _stmt().seal(s1)
        with self.assertRaises(bp.ProvenanceError):
            bp.verify_sealed_statement(
                sealed, expected_artifact_hex="aa" * 32, verifier=v2)

    def test_tampered_body_refused(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        doc = dict(sealed["statement"])
        doc["builder"] = "evil"
        sealed2 = {"statement": doc, "signature": sealed["signature"],
                   "key_id": sealed["key_id"]}
        with self.assertRaises(bp.ProvenanceError):
            bp.verify_sealed_statement(
                sealed2, expected_artifact_hex="aa" * 32, verifier=v1)

    def test_extra_field_refused(self):
        s1, _, _, _ = _signers()
        sealed = _stmt().seal(s1)
        doc = dict(sealed["statement"])
        doc["rogue"] = 1
        sealed2 = {"statement": doc, "signature": sealed["signature"],
                   "key_id": sealed["key_id"]}
        with self.assertRaises(bp.ProvenanceError):
            bp.parse_statement(sealed2)

    def test_statement_digest_stable(self):
        s1, _, _, _ = _signers()
        sealed = _stmt().seal(s1)
        self.assertEqual(bp.statement_digest(sealed),
                         bp.statement_digest(sealed))

    def test_statement_digest_changes_with_body(self):
        s1, _, _, _ = _signers()
        d1 = bp.statement_digest(_stmt("aa" * 32).seal(s1))
        d2 = bp.statement_digest(_stmt("bb" * 32).seal(s1))
        self.assertNotEqual(d1, d2)


class ReproducibilityTests(unittest.TestCase):
    def test_honest_rebuild_verifies(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        out = bp.verify_reproducibility(
            sealed, rebuilder=lambda n: {"src.tar.gz": "aa" * 32}[n],
            verifier=v1, expected_artifact_hex="aa" * 32)
        self.assertEqual(out["checked"], ["src.tar.gz"])
        self.assertEqual(out["unchecked"], ["entropy.bin"])

    def test_repro_lie_refused(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        with self.assertRaises(bp.ProvenanceError):
            bp.verify_reproducibility(
                sealed, rebuilder=lambda n: "cc" * 32,
                verifier=v1, expected_artifact_hex="aa" * 32)

    def test_nondeterministic_not_rederived(self):
        s1, v1, _, _ = _signers()
        sealed = _stmt().seal(s1)
        calls = []
        def rebuilder(name):
            calls.append(name)
            return "aa" * 32
        bp.verify_reproducibility(
            sealed, rebuilder=rebuilder, verifier=v1,
            expected_artifact_hex="aa" * 32)
        self.assertEqual(calls, ["src.tar.gz"])

    def test_repro_requires_expected_digest_param(self):
        # The artifact binding must not be read from the statement itself:
        # verify_reproducibility's signature requires the caller's digest.
        import inspect
        params = inspect.signature(bp.verify_reproducibility).parameters
        self.assertIn("expected_artifact_hex", params)


if __name__ == "__main__":
    unittest.main()
