#!/usr/bin/env python3
"""Unit tests for gov/display_attest.py (wave-222 lane A).

Spec-vector literals are fixed known-good values (generated once from
the module, pasted here): the tests pin the digest formats, the
built-in policy identity, and the refusal codes against drift.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import display_attest as da  # noqa: E402
from gov import render_commit as rc  # noqa: E402


# Spec-vector literals (independent known-good values).
V1_DIGEST = ("sha256:8abdb228dc744855fa4892e1528a9a136622d383e5bf44385ba9"
             "ccb182ea1c4a")
RENDER_BYTES = b"APPROVAL appr-0001\naction: write_file\n"
RENDER_DIGEST = ("sha256:4cb8c4f1aad52db30d23f4ba113a8381b27f5661eec706afc5"
                 "c78bb8dfb18be3")
ARTIFACT_BYTES = b"fixture-artifact-bytes"
ARTIFACT_DIGEST = "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest()


def _attest(renderer_id="", commitment=None):
    return da.attest_display(ARTIFACT_DIGEST, da.APPROVAL_DISPLAY_V1_DIGEST,
                             renderer_id, RENDER_BYTES,
                             rendering_commitment=commitment)


class TestPolicyIdentity(unittest.TestCase):
    def test_builtin_digest_literal(self):
        # The built-in policy digest is a stable well-known constant.
        self.assertEqual(da.APPROVAL_DISPLAY_V1_DIGEST, V1_DIGEST)

    def test_builtin_policy_id(self):
        self.assertEqual(da.APPROVAL_DISPLAY_V1, "approval-display-v1")


class TestAttest(unittest.TestCase):
    def test_fields_and_digest_literal(self):
        att = _attest()
        self.assertEqual(set(att),
                         {"artifact_digest", "render_policy_digest",
                          "renderer_id", "render_bytes_digest",
                          "attested_at"})
        # render_bytes_digest is sha256 over the EXACT view-time bytes.
        self.assertEqual(att["render_bytes_digest"], RENDER_DIGEST)
        self.assertEqual(
            att["render_bytes_digest"],
            "sha256:" + hashlib.sha256(RENDER_BYTES).hexdigest())

    def test_render_bytes_not_mutated(self):
        blob = bytearray(RENDER_BYTES)
        da.attest_display(ARTIFACT_DIGEST, da.APPROVAL_DISPLAY_V1_DIGEST,
                          "", bytes(blob))
        self.assertEqual(bytes(blob), RENDER_BYTES)

    def test_authoring_misuse(self):
        with self.assertRaises(TypeError):
            da.attest_display(ARTIFACT_DIGEST,
                              da.APPROVAL_DISPLAY_V1_DIGEST, "",
                              "not bytes")
        with self.assertRaises(ValueError):
            da.attest_display("", da.APPROVAL_DISPLAY_V1_DIGEST, "",
                              RENDER_BYTES)
        with self.assertRaises(ValueError):
            da.attest_display(ARTIFACT_DIGEST, "",
                              "", RENDER_BYTES)
        with self.assertRaises(TypeError):
            da.attest_display(ARTIFACT_DIGEST,
                              da.APPROVAL_DISPLAY_V1_DIGEST, None,
                              RENDER_BYTES)

    def test_attest_with_foreign_commitment_refused(self):
        foreign = rc.commit(b"other bytes", ARTIFACT_DIGEST,
                            renderer_id="queue-view")
        with self.assertRaises(rc.RenderingCommitmentError) as ctx:
            da.attest_display(ARTIFACT_DIGEST,
                              da.APPROVAL_DISPLAY_V1_DIGEST,
                              "queue-view", RENDER_BYTES,
                              rendering_commitment=foreign)
        self.assertEqual(ctx.exception.code, "rendering-commitment-broken")


class TestVerify(unittest.TestCase):
    def test_malformed_attestation_refused(self):
        with self.assertRaises(da.RederivationFailedError) as ctx:
            da.verify_attestation({"nope": 1}, b"bytes")
        self.assertEqual(ctx.exception.code, "display-rederivation-failed")

    def test_nonbytes_artifact(self):
        with self.assertRaises(TypeError):
            da.verify_attestation(_attest(), "not bytes")

    def test_unknown_policy(self):
        att = dict(_attest())
        att["render_policy_digest"] = "sha256:" + "ff" * 32
        with self.assertRaises(da.PolicyUnknownError) as ctx:
            da.verify_attestation(att, ARTIFACT_BYTES)
        self.assertEqual(ctx.exception.code, "display-policy-unknown")

    def test_renderer_without_commitment(self):
        att = _attest(renderer_id="queue-view")
        with self.assertRaises(da.NoRenderCommitmentError) as ctx:
            da.verify_attestation(att, b"bytes")
        self.assertEqual(ctx.exception.code, "display-no-render-commitment")


class TestRegistration(unittest.TestCase):
    def test_nondeterministic_refused(self):
        import time
        with self.assertRaises(ValueError):
            da.register_render_policy(
                "flaky", "sha256:" + "cd" * 32,
                lambda b: b"x" + str(time.time_ns()).encode("ascii"))

    def test_nonbytes_return_refused(self):
        with self.assertRaises(ValueError):
            da.register_render_policy("bad", "sha256:" + "ce" * 32,
                                      lambda b: "not bytes")

    def test_pin_confusion_refused(self):
        digest = "sha256:" + "cf" * 32
        da.register_render_policy("p1", digest, lambda b: b"one")
        try:
            with self.assertRaises(ValueError):
                da.register_render_policy("p2", digest, lambda b: b"two")
        finally:
            da.unregister_render_policy(digest)

    def test_idempotent_reregister(self):
        fn = lambda b: b"same"  # noqa: E731
        digest = "sha256:" + "d0" * 32
        da.register_render_policy("p", digest, fn)
        try:
            self.assertTrue(da.register_render_policy("p", digest, fn))
        finally:
            da.unregister_render_policy(digest)

    def test_unregister_missing(self):
        self.assertFalse(
            da.unregister_render_policy("sha256:" + "d1" * 32))


class TestRederive(unittest.TestCase):
    def test_unknown_policy(self):
        with self.assertRaises(da.PolicyUnknownError):
            da.rederive(b"bytes", "sha256:" + "ff" * 32)

    def test_nonbytes(self):
        with self.assertRaises(TypeError):
            da.rederive("nope", da.APPROVAL_DISPLAY_V1_DIGEST)


if __name__ == "__main__":
    unittest.main()
