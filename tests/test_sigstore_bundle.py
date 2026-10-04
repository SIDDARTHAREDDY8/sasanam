"""Unit tests for gov/sigstore_bundle.py (wave-321 lane 1).

Covers the keyed-bundle seal/verify contract: form-(1) wire shape, hint
derivation, one-signature enforcement, PAE coverage, the bool contract
(verify returns False -- `is False` -- on forgery, never raises), and the
evidence subject binding. Deterministic (fixed seeds); stdlib only.
"""

import base64
import copy
import hashlib
import unittest

from gov import sigstore_bundle as SB
from gov import evidence_intoto as _intoto
from gov.signing import Ed25519Signer

_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])
_SIGNER_A = Ed25519Signer(_SEED_A)
_SIGNER_B = Ed25519Signer(_SEED_B)
_PUB_A = _SIGNER_A.public_key
_PUB_B = _SIGNER_B.public_key

_EVIDENCE = b'{"decision": "deny", "seq": 7}'


def _payload():
    st = _intoto.build_statement(_EVIDENCE, {"lane": "w321-sigstore"})
    return _intoto.statement_bytes(st)


class TestKeyHint(unittest.TestCase):
    def test_hint_is_hex_sha256_of_der_spki(self):
        der = SB.spki_der_ed25519(_PUB_A)
        self.assertTrue(der.startswith(bytes.fromhex("302a300506032b6570032100")))
        self.assertEqual(len(der), 12 + 32)
        self.assertEqual(SB.key_hint(_PUB_A), hashlib.sha256(der).hexdigest())

    def test_hint_rejects_bad_key(self):
        with self.assertRaises(SB.KeyedBundleError):
            SB.key_hint(b"short")


class TestSeal(unittest.TestCase):
    def test_wire_shape(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        self.assertEqual(bundle["mediaType"], SB.SIGSTORE_BUNDLE_MEDIA_TYPE)
        self.assertEqual(set(bundle["verificationMaterial"]["publicKey"]),
                         {"hint"})
        env = bundle["dsseEnvelope"]
        self.assertEqual(env["payloadType"], SB.SASANAM_PAYLOAD_TYPE)
        self.assertEqual(len(env["signatures"]), 1)
        self.assertEqual(env["signatures"][0]["keyid"], "")
        # base64 sig decodes to 64 bytes.
        sig = base64.b64decode(env["signatures"][0]["sig"])
        self.assertEqual(len(sig), 64)

    def test_fanout(self):
        bundles = SB.seal_keyed_bundle_fanout(
            _payload(), [_SIGNER_A, _SIGNER_B])
        self.assertEqual(len(bundles), 2)
        for b in bundles:
            self.assertEqual(len(b["dsseEnvelope"]["signatures"]), 1)

    def test_fanout_refuses_empty(self):
        with self.assertRaises(SB.KeyedBundleError):
            SB.seal_keyed_bundle_fanout(_payload(), [])

    def test_seal_refuses_empty_payload(self):
        with self.assertRaises(SB.KeyedBundleError):
            SB.seal_keyed_bundle(b"", _SIGNER_A)


class TestOpen(unittest.TestCase):
    def test_roundtrip(self):
        payload = _payload()
        bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
        self.assertEqual(SB.open_keyed_bundle(bundle, _PUB_A), payload)

    def test_forged_signature_raises_coded(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        bad = copy.deepcopy(bundle)
        raw = bytearray(base64.b64decode(bad["dsseEnvelope"]["signatures"][0]["sig"]))
        raw[0] ^= 1
        bad["dsseEnvelope"]["signatures"][0]["sig"] = \
            base64.b64encode(bytes(raw)).decode("ascii")
        with self.assertRaises(SB.KeyedBundleError) as ctx:
            SB.open_keyed_bundle(bad, _PUB_A)
        self.assertEqual(ctx.exception.code, "sigstore-keyed-signature-invalid")

    def test_verify_returns_false_not_raises_on_forgery(self):
        # Wave-243 rule: bool-returning verify must return False, never
        # raise, on a forged bundle. Assert `is False`, not truthiness.
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        bad = copy.deepcopy(bundle)
        raw = bytearray(base64.b64decode(bad["dsseEnvelope"]["signatures"][0]["sig"]))
        raw[0] ^= 1
        bad["dsseEnvelope"]["signatures"][0]["sig"] = \
            base64.b64encode(bytes(raw)).decode("ascii")
        self.assertIs(SB.verify_keyed_bundle(bad, _PUB_A), False)

    def test_verify_true_on_good_bundle(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        self.assertIs(SB.verify_keyed_bundle(bundle, _PUB_A), True)

    def test_wrong_key_refused(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        self.assertIs(SB.verify_keyed_bundle(bundle, _PUB_B), False)
        with self.assertRaises(SB.KeyedBundleError):
            SB.open_keyed_bundle(bundle, _PUB_B)

    def test_multi_signature_refused(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        bad = copy.deepcopy(bundle)
        bad["dsseEnvelope"]["signatures"].append(
            bad["dsseEnvelope"]["signatures"][0])
        with self.assertRaises(SB.KeyedBundleError) as ctx:
            SB.open_keyed_bundle(bad, _PUB_A)
        self.assertEqual(ctx.exception.code, "sigstore-keyed-multi-signature")

    def test_non_pae_signature_refused(self):
        # Valid Ed25519 over the raw payload (not PAE) must NOT verify.
        payload = _payload()
        bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
        bad = copy.deepcopy(bundle)
        bad["dsseEnvelope"]["signatures"][0]["sig"] = \
            base64.b64encode(_SIGNER_A.sign(payload)).decode("ascii")
        self.assertIs(SB.verify_keyed_bundle(bad, _PUB_A), False)

    def test_message_signature_oneof_refused(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        bad = copy.deepcopy(bundle)
        bad["messageSignature"] = {"signature": base64.b64encode(b"1" * 64).decode("ascii")}
        with self.assertRaises(SB.KeyedBundleError) as ctx:
            SB.open_keyed_bundle(bad, _PUB_A)
        self.assertEqual(ctx.exception.code,
                         "sigstore-keyed-message-signature-unexpected")
        self.assertIs(SB.verify_keyed_bundle(bad, _PUB_A), False)


class TestEvidenceBinding(unittest.TestCase):
    def test_subject_binds_evidence_digest(self):
        payload = _payload()
        bundle = SB.seal_keyed_bundle(payload, _SIGNER_A)
        digest = hashlib.sha256(_EVIDENCE).hexdigest()
        got_payload, stmt = SB.open_keyed_evidence_bundle(
            bundle, _PUB_A, digest)
        self.assertEqual(got_payload, payload)
        self.assertIsInstance(stmt, dict)

    def test_wrong_digest_refused_coded(self):
        bundle = SB.seal_keyed_bundle(_payload(), _SIGNER_A)
        with self.assertRaises(SB.KeyedBundleError) as ctx:
            SB.open_keyed_evidence_bundle(bundle, _PUB_A, "00" * 32)
        self.assertEqual(ctx.exception.code, "sigstore-keyed-subject-mismatch")


if __name__ == "__main__":
    unittest.main()
