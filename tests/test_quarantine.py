#!/usr/bin/env python3
"""Unit tests for gov/quarantine.py at the public seams.

Independent spec-vector literals; behavior asserted through the
public interface, never internals.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys  # noqa: E402
sys.path.insert(0, REPO)

from gov import quarantine as qr  # noqa: E402
from gov import admission as adm  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402


def _keypair():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _digest_of(payload):
    return hashlib.sha256(payload).hexdigest()


def _policy(digest, pub, bundle_format="evidence-bundle/v1"):
    return adm.AdmissionPolicy(digest, pub, bundle_format)


def _sign(seed, digest):
    return _ed.sign(seed, adm.signing_bytes(digest))


class TestStage(unittest.TestCase):
    def test_stage_binds_verified_digest(self):
        q = qr.Quarantine()
        payload = b"unit-stage-bytes"
        staged = q.stage(payload, _digest_of(payload))
        self.assertEqual(staged.digest, _digest_of(payload))
        self.assertIn(staged.digest, q.quarantined_digests())
        self.assertFalse(q.in_trusted_store(staged.digest))

    def test_stage_rejects_mismatch(self):
        q = qr.Quarantine()
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.stage(b"bytes-a", "ab" * 32)
        self.assertEqual(ctx.exception.code, "quarantine-digest-mismatch")

    def test_stage_rejects_non_bytes(self):
        q = qr.Quarantine()
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.stage("not-bytes", "ab" * 32)
        self.assertEqual(ctx.exception.code, "quarantine-malformed")

    def test_stage_rejects_non_hex_digest(self):
        q = qr.Quarantine()
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.stage(b"bytes", "not-a-digest")
        self.assertEqual(ctx.exception.code, "quarantine-malformed")


class TestAdmit(unittest.TestCase):
    def test_admit_moves_to_trust_only_on_success(self):
        payload = b"unit-admit-bytes"
        digest = _digest_of(payload)
        seed, pub = _keypair()
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        record = q.admit(staged, _policy(digest, pub),
                         bundle_format="evidence-bundle/v1",
                         signature=_sign(seed, digest))
        self.assertTrue(record["admissible"])
        self.assertTrue(q.in_trusted_store(digest))
        self.assertEqual(q.trusted_payload(digest), payload)

    def test_admit_failure_keeps_out(self):
        payload = b"unit-refused-bytes"
        digest = _digest_of(payload)
        seed, pub = _keypair()
        other_seed, _ = _keypair()
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        with self.assertRaises(adm.AdmissionError) as ctx:
            q.admit(staged, _policy(digest, pub),
                     bundle_format="evidence-bundle/v1",
                     signature=_sign(other_seed, digest))
        self.assertEqual(ctx.exception.code, "admission-issuer-untrusted")
        self.assertFalse(q.in_trusted_store(digest))

    def test_admit_refuses_envelope_override(self):
        payload = b"unit-override-bytes"
        digest = _digest_of(payload)
        seed, pub = _keypair()
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.admit(staged, _policy(digest, pub),
                     bundle_format="evidence-bundle/v1",
                     signature=_sign(seed, digest),
                     payload_digest="00" * 32)
        self.assertEqual(ctx.exception.code,
                         "quarantine-envelope-override-refused")
        self.assertFalse(q.in_trusted_store(digest))

    def test_admit_refuses_policy_without_admissible_record(self):
        payload = b"unit-contract"
        digest = _digest_of(payload)
        q = qr.Quarantine()
        staged = q.stage(payload, digest)

        class _SilentPolicy(object):
            def admit(self, envelope, **kwargs):
                return {"admissible": False}

        with self.assertRaises(qr.QuarantineError) as ctx:
            q.admit(staged, _SilentPolicy(),
                     bundle_format="evidence-bundle/v1")
        self.assertEqual(ctx.exception.code,
                         "quarantine-policy-contract-refused")
        self.assertFalse(q.in_trusted_store(digest))

    def test_admit_refuses_unknown_policy(self):
        payload = b"unit-bad-policy"
        digest = _digest_of(payload)
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.admit(staged, object(), bundle_format="evidence-bundle/v1")
        self.assertEqual(ctx.exception.code, "quarantine-malformed")


class TestRejectAndBypass(unittest.TestCase):
    def test_reject_carries_reason(self):
        payload = b"unit-reject-bytes"
        digest = _digest_of(payload)
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.reject(staged, "known-bad source")
        self.assertEqual(ctx.exception.code, "quarantine-rejected")
        self.assertIn("known-bad source", str(ctx.exception))
        self.assertNotIn(digest, q.quarantined_digests())

    def test_reject_needs_reason(self):
        payload = b"unit-reject-noreason"
        q = qr.Quarantine()
        staged = q.stage(payload, _digest_of(payload))
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.reject(staged, "")
        self.assertEqual(ctx.exception.code, "quarantine-malformed")

    def test_admit_to_trust_always_refuses(self):
        q = qr.Quarantine()
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.admit_to_trust({"payload": b"x"}, None)
        self.assertEqual(ctx.exception.code, "quarantine-bypass-refused")


class TestHandleDiscipline(unittest.TestCase):
    def test_double_admit_refused(self):
        payload = b"unit-once"
        digest = _digest_of(payload)
        seed, pub = _keypair()
        q = qr.Quarantine()
        staged = q.stage(payload, digest)
        q.admit(staged, _policy(digest, pub), bundle_format="evidence-bundle/v1",
                signature=_sign(seed, digest))
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.admit(staged, _policy(digest, pub), bundle_format="evidence-bundle/v1",
                     signature=_sign(seed, digest))
        self.assertEqual(ctx.exception.code, "quarantine-unknown-staged")

    def test_foreign_handle_refused(self):
        payload = b"unit-foreign"
        digest = _digest_of(payload)
        seed, pub = _keypair()
        q1, q2 = qr.Quarantine(), qr.Quarantine()
        foreign = q2.stage(payload, digest)
        with self.assertRaises(qr.QuarantineError) as ctx:
            q1.admit(foreign, _policy(digest, pub),
                     bundle_format="evidence-bundle/v1",
                     signature=_sign(seed, digest))
        self.assertEqual(ctx.exception.code, "quarantine-unknown-staged")

    def test_trusted_payload_refuses_unadmitted(self):
        q = qr.Quarantine()
        with self.assertRaises(qr.QuarantineError) as ctx:
            q.trusted_payload("ab" * 32)
        self.assertEqual(ctx.exception.code, "quarantine-not-admitted")


if __name__ == "__main__":
    unittest.main(verbosity=2)
