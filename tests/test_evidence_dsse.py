"""Unit tests for gov.evidence_dsse (wave-309 lane E).

The DSSE export envelope for the offline evidence bundle: an additive wire
format so third-party verifiers (cosign, ``gh attestation verify``) can
consume evidence without the engine. The low-level PAE/threshold machinery
lives in gov.dsse_envelope (tested in tests/test_dsse_envelope.py); these
tests pin the evidence-bundle seam:

- payloadType is bound to ``application/vnd.in-toto+json`` (type-confusion
  refused);
- the signature is over the spec PAE of the bundle bytes (independent
  hand-built check, not tautological);
- the verifier's same-bytes discipline: it returns the exact bytes it
  verified, never the caller's expected bytes, and authentication precedes
  binding;
- (t, n) threshold signing over distinct keys;
- keyid is an unauthenticated hint (unknown keyid falls back to try-all);
- the operator anchor-key seam supplies the signer (fail-closed when
  unconfigured).
"""

import base64
import copy
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import dsse_envelope as _dsse
from gov import ed25519 as _ed25519
from gov import evidence_dsse
from gov.signing import Ed25519Signer, Ed25519Verifier

PT = evidence_dsse.EVIDENCE_DSSE_PAYLOAD_TYPE
BUNDLE = b'{"_type":"evidence-bundle","window":"2026-10-03","tip":"ab"*16}'


def _signers(n, base=11):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


class TestPayloadType(unittest.TestCase):
    def test_payload_type_is_in_toto(self):
        # The in-toto statement media type: step 2 of the build order
        # re-envelopes the bundle as an in-toto Statement; the DSSE layer
        # already binds the type now so the signature cannot be
        # transplanted onto a different payload type later.
        self.assertEqual(PT, "application/vnd.in-toto+json")

    def test_seal_stamps_payload_type(self):
        s1 = _signers(1)[0]
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1])
        self.assertEqual(env["payloadType"], PT)


class TestSpecPAE(unittest.TestCase):
    def test_signature_is_over_spec_pae(self):
        # Independent source of truth: the DSSE spec PAE formula,
        # hand-built here — NOT via dsse_envelope.pae — so this test can
        # disagree with the implementation.
        s1 = _signers(1, base=7)[0]
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1])
        sig = bytes.fromhex(env["signatures"][0]["sig"])
        t = PT.encode("utf-8")
        pae_bytes = (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t
                     + b" " + str(len(BUNDLE)).encode("ascii") + b" "
                     + BUNDLE)
        self.assertTrue(_ed25519.verify(s1.public_key, pae_bytes, sig))

    def test_payload_is_raw_bundle_bytes(self):
        # No canonicalization, no re-encoding: the envelope carries the
        # exact bundle bytes (DSSE signs raw serialized bytes).
        s1 = _signers(1)[0]
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1])
        self.assertEqual(base64.b64decode(env["payload"]), BUNDLE)


class TestRoundTrip(unittest.TestCase):
    def test_round_trip(self):
        signers = _signers(1)
        verifiers = _verifiers(signers)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        got = evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers)
        self.assertEqual(got, BUNDLE)
        self.assertIsInstance(got, bytes)

    def test_seal_refuses_empty_bundle(self):
        s1 = _signers(1)[0]
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.seal_evidence_bundle(b"", [s1])

    def test_seal_refuses_non_bytes(self):
        s1 = _signers(1)[0]
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.seal_evidence_bundle("not-bytes", [s1])

    def test_seal_requires_signer(self):
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.seal_evidence_bundle(BUNDLE, [])

    def test_verify_requires_verifier(self):
        s1 = _signers(1)[0]
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1])
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(env, BUNDLE, [])

    def test_verify_refuses_non_bytes_expected(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(env, "not-bytes",
                                               _verifiers(signers))


class TestTypeConfusion(unittest.TestCase):
    def test_wrong_payload_type_refused(self):
        # An envelope sealed for a different payload type is not an
        # evidence envelope, even with a valid signature.
        signers = _signers(1)
        env = _dsse.seal(BUNDLE, "application/json", signers)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(env, BUNDLE,
                                               _verifiers(signers))
        self.assertIn("payloadType", ctx.exception.reason)

    def test_flipped_payload_type_breaks_signature(self):
        # Changing payloadType after sealing breaks the PAE signature:
        # the type is inside the signed bytes.
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        bad["payloadType"] = "application/json"
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                               _verifiers(signers))


class TestTamper(unittest.TestCase):
    def test_payload_bit_flip_refused(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        raw = bytearray(base64.b64decode(bad["payload"]))
        raw[0] ^= 0x01
        bad["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                               _verifiers(signers))
        self.assertIn("threshold", ctx.exception.reason)

    def test_signature_hex_flip_refused(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        sig = bad["signatures"][0]["sig"]
        bad["signatures"][0]["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                               _verifiers(signers))
        self.assertIn("threshold", ctx.exception.reason)

    def test_unknown_envelope_field_refused(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        bad["extra"] = "nope"
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                               _verifiers(signers))


class TestThreshold(unittest.TestCase):
    def test_two_of_three(self):
        signers = _signers(3, base=21)
        verifiers = _verifiers(signers)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        got = evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers,
                                                 threshold=2)
        self.assertEqual(got, BUNDLE)

    def test_one_of_three_fails_threshold_two(self):
        s1 = _signers(1, base=31)[0]
        verifiers = _verifiers(_signers(3, base=21))
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1])
        # s1 is not among the trusted verifiers at all: threshold cannot
        # be met even at 1.
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers,
                                               threshold=2)
        self.assertIn("threshold", ctx.exception.reason)

    def test_threshold_two_with_two_of_three_signers(self):
        signers = _signers(3, base=41)
        verifiers = _verifiers(signers)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers[:2])
        got = evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers,
                                                 threshold=2)
        self.assertEqual(got, BUNDLE)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers,
                                               threshold=3)

    def test_duplicate_signer_counts_once(self):
        s1 = _signers(1, base=51)[0]
        verifiers = _verifiers([s1])
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [s1, s1])
        self.assertEqual(len(env["signatures"]), 2)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers,
                                               threshold=2)
        self.assertIn("threshold", ctx.exception.reason)

    def test_threshold_zero_refused(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(env, BUNDLE,
                                               _verifiers(signers),
                                               threshold=0)

    def test_threshold_bool_refused(self):
        signers = _signers(1)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(env, BUNDLE,
                                               _verifiers(signers),
                                               threshold=True)


class TestKeyidHint(unittest.TestCase):
    def test_unknown_keyid_falls_back_to_try_all(self):
        # keyid is an unauthenticated hint: it narrows the search, never
        # decides. An entry whose keyid matches no trusted verifier is
        # tried against every verifier — stripping the keyid is already
        # accepted, so the fallback grants an attacker nothing new.
        signers = _signers(1, base=61)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        bad["signatures"][0]["keyid"] = "not-a-known-key"
        got = evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                                 _verifiers(signers))
        self.assertEqual(got, BUNDLE)

    def test_keyid_less_signature_verifies(self):
        signers = _signers(1, base=71)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        del bad["signatures"][0]["keyid"]
        got = evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                                 _verifiers(signers))
        self.assertEqual(got, BUNDLE)

    def test_wrong_key_still_refused_with_hint_fallback(self):
        # The fallback does not weaken authentication: a signature from
        # an untrusted key verifies against no trusted verifier.
        stranger = _signers(1, base=81)[0]
        trusted = _verifiers(_signers(1, base=91))
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [stranger])
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(env, BUNDLE, trusted)
        self.assertIn("threshold", ctx.exception.reason)


class TestSameBytesDiscipline(unittest.TestCase):
    """The critical verifier rule (DSSE spec): the SAME serialized body
    that is verified is the one handed to the application. The verifier
    parses once, verifies over the parsed bytes, binds against the
    caller's expected bytes, and returns the verified bytes — it never
    re-parses, never re-serializes, and never substitutes the caller's
    expected bytes for the verified ones."""

    def test_returns_verified_bytes_not_expected_bytes(self):
        # A valid envelope for *different* bytes: the verifier must
        # return the bytes it actually verified (evil), never the bytes
        # the caller hoped for (BUNDLE).
        signers = _signers(1, base=101)
        evil = b'{"_type":"evidence-bundle","window":"forged"}'
        env_evil = evidence_dsse.seal_evidence_bundle(evil, signers)
        got = evidence_dsse.verify_dsse_envelope(env_evil, evil,
                                                 _verifiers(signers))
        self.assertEqual(got, evil)
        # ... and it is byte-identical to the envelope's own payload:
        self.assertEqual(got, base64.b64decode(env_evil["payload"]))

    def test_authentication_precedes_binding(self):
        # The signature is valid (for evil), so refusal must come from
        # the payload-binding path — not the signature path. A verifier
        # that checked the signature over the *expected* bytes instead
        # of the envelope bytes would fail here on the threshold path.
        signers = _signers(1, base=111)
        evil = b'{"_type":"evidence-bundle","window":"forged"}'
        env_evil = evidence_dsse.seal_evidence_bundle(evil, signers)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_dsse.verify_dsse_envelope(env_evil, BUNDLE,
                                               _verifiers(signers))
        self.assertIn("binding", ctx.exception.reason)

    def test_tampered_envelope_yields_no_payload(self):
        # No code path returns payload bytes from an envelope whose
        # signatures do not verify: tampering yields an exception, never
        # bytes.
        signers = _signers(1, base=121)
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, signers)
        bad = copy.deepcopy(env)
        raw = bytearray(base64.b64decode(bad["payload"]))
        raw[-1] ^= 0x01
        bad["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_dsse.verify_dsse_envelope(bad, BUNDLE,
                                               _verifiers(signers))


class TestAnchorKey(unittest.TestCase):
    def test_explicit_seed_builds_signer(self):
        seed_hex = "ab" * 32
        signer = evidence_dsse.signer_from_anchor_key(explicit=seed_hex)
        self.assertEqual(signer.public_key,
                         _ed25519.publickey(bytes.fromhex(seed_hex)))
        # ... and the signer round-trips through the envelope:
        verifiers = [Ed25519Verifier(signer.public_key, signer.key_id)]
        env = evidence_dsse.seal_evidence_bundle(BUNDLE, [signer])
        got = evidence_dsse.verify_dsse_envelope(env, BUNDLE, verifiers)
        self.assertEqual(got, BUNDLE)

    def test_unconfigured_key_is_fail_closed(self):
        from gov import anchorer as ancho_rer
        saved = {n: os.environ.get(n)
                 for n in ("GOV_ANCHOR_KEY", "GOV_ANCHOR_KEY_FILE")}
        for n in saved:
            os.environ.pop(n, None)
        try:
            with self.assertRaises(ancho_rer.NoAnchorKeyError):
                evidence_dsse.signer_from_anchor_key()
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v


if __name__ == "__main__":
    unittest.main()