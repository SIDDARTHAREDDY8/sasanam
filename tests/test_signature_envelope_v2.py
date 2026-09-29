#!/usr/bin/env python3
"""Wave-202 lane B: unit tests for gov.signature_envelope_v2 (public seams).

Hermetic: fixed Ed25519 seeds, no network. The tests/__init__ harness
provisions the audit-log HMAC key process-wide.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from gov import signature_envelope_v2 as env
from gov.signing import Ed25519Signer, Ed25519Verifier


def _signers():
    s1 = Ed25519Signer(bytes([1]) * 32)
    s2 = Ed25519Signer(bytes([2]) * 32)
    return s1, Ed25519Verifier(s1.public_key, s1.key_id), \
        s2, Ed25519Verifier(s2.public_key, s2.key_id)


def _seal(signer, payload="aa" * 32, comments=("release 1.0",),
          provenance="bb" * 32):
    return env.seal(payload_hex=payload, signer=signer,
                    trusted_comments=list(comments),
                    provenance_digest=provenance)


class SealOpenTests(unittest.TestCase):
    def test_round_trip(self):
        s1, v1, _, _ = _signers()
        e = _seal(s1)
        opened = env.open_envelope(e, expected_payload_hex="aa" * 32,
                                   verifier=v1,
                                   expected_provenance_digest="bb" * 32)
        self.assertEqual(opened["trusted_comments"], ["release 1.0"])
        self.assertEqual(opened["key_id"], s1.key_id)

    def test_empty_comments_refused_at_seal(self):
        s1, _, _, _ = _signers()
        with self.assertRaises(env.EnvelopeError):
            env.seal(payload_hex="aa" * 32, signer=s1,
                     trusted_comments=[], provenance_digest="bb" * 32)

    def test_comment_tamper_breaks_signature(self):
        s1, v1, _, _ = _signers()
        e = _seal(s1)
        e2 = dict(e)
        e2["trusted_comments"] = ["release 1.0 (backdoored)"]
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e2, expected_payload_hex="aa" * 32,
                              verifier=v1,
                              expected_provenance_digest="bb" * 32)

    def test_wrong_key_refused(self):
        s1, _, _, v2 = _signers()
        e = _seal(s1)
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e, expected_payload_hex="aa" * 32,
                              verifier=v2,
                              expected_provenance_digest="bb" * 32)

    def test_payload_binding(self):
        s1, v1, _, _ = _signers()
        e = _seal(s1, payload="aa" * 32)
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e, expected_payload_hex="cc" * 32,
                              verifier=v1,
                              expected_provenance_digest="bb" * 32)

    def test_provenance_stripping_refused(self):
        # An envelope sealed WITH provenance cannot be opened as
        # provenance-free: no silent downgrade.
        s1, v1, _, _ = _signers()
        e = _seal(s1, provenance="bb" * 32)
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e, expected_payload_hex="aa" * 32,
                              verifier=v1, expected_provenance_digest=None)

    def test_provenance_free_envelope_round_trip(self):
        s1, v1, _, _ = _signers()
        e = env.seal(payload_hex="aa" * 32, signer=s1,
                     trusted_comments=["ad-hoc build"],
                     provenance_digest=None)
        opened = env.open_envelope(e, expected_payload_hex="aa" * 32,
                                   verifier=v1,
                                   expected_provenance_digest=None)
        self.assertIsNone(opened["provenance_digest"])

    def test_provenance_required_by_default(self):
        # The caller must name the expected provenance digest (or None);
        # the API has no silent default.
        s1, v1, _, _ = _signers()
        e = _seal(s1)
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e, expected_payload_hex="aa" * 32,
                              verifier=v1)

    def test_extra_field_refused(self):
        s1, _, _, _ = _signers()
        e = _seal(s1)
        e2 = dict(e)
        e2["rogue"] = 1
        with self.assertRaises(env.EnvelopeError):
            env.parse_envelope(e2)

    def test_missing_field_refused(self):
        s1, _, _, _ = _signers()
        e = _seal(s1)
        e2 = dict(e)
        del e2["signature"]
        with self.assertRaises(env.EnvelopeError):
            env.parse_envelope(e2)

    def test_version_refused(self):
        s1, _, _, _ = _signers()
        e = _seal(s1)
        e2 = dict(e)
        e2["format"] = "sasanam-envelope/v3"
        with self.assertRaises(env.EnvelopeError):
            env.parse_envelope(e2)

    def test_edited_provenance_digest_breaks_signature(self):
        s1, v1, _, _ = _signers()
        e = _seal(s1, provenance="bb" * 32)
        e2 = dict(e)
        e2["provenance_digest"] = "cc" * 32
        with self.assertRaises(env.EnvelopeError):
            env.open_envelope(e2, expected_payload_hex="aa" * 32,
                              verifier=v1,
                              expected_provenance_digest="cc" * 32)

    def test_payload_digest_of(self):
        self.assertEqual(len(env.payload_digest_of(b"data")), 64)
        with self.assertRaises(env.EnvelopeError):
            env.payload_digest_of("not-bytes")


if __name__ == "__main__":
    unittest.main()
