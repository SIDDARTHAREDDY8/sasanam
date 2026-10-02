"""Unit tests for gov/bundle_envelope.py (wave-284 lane 6, sops STEAL).

Covers the RFC 7748 X25519 vectors, HKDF/AEAD properties, the seal/open
round-trip, the tamper matrix, recipient policy validation, and the
re-keying ceremony. Deterministic; secrets only for key/nonce material.
"""

import copy
import json
import os
import secrets
import sys
import unittest

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import bundle_envelope as be  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402


class TestX25519Vectors(unittest.TestCase):
    # RFC 7748 section 6.1 (fetched from rfc-editor.org at build time).
    A_PRIV = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    A_PUB = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    B_PRIV = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    B_PUB = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    SHARED = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    def test_pub_a(self):
        self.assertEqual(be.x25519_pub(self.A_PRIV), self.A_PUB)

    def test_pub_b(self):
        self.assertEqual(be.x25519_pub(self.B_PRIV), self.B_PUB)

    def test_shared_both_directions(self):
        self.assertEqual(be.x25519(self.A_PRIV, self.B_PUB), self.SHARED)
        self.assertEqual(be.x25519(self.B_PRIV, self.A_PUB), self.SHARED)

    def test_rfc7748_section52_vectors(self):
        # Section 5.2 single vectors (the function clamps the scalar).
        s1 = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u1 = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        o1 = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        s2 = bytes.fromhex(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        u2 = bytes.fromhex(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        o2 = bytes.fromhex(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        self.assertEqual(be.x25519(s1, u1), o1)
        self.assertEqual(be.x25519(s2, u2), o2)

    def test_rfc7748_section52_iterated(self):
        # One iteration of the section 5.2 iterated test.
        k = u = bytes.fromhex(
            "0900000000000000000000000000000000000000000000000000000000000000")
        self.assertEqual(
            be.x25519(k, u),
            bytes.fromhex(
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"))

    def test_zero_pubkey_refused(self):
        with self.assertRaises(be.EnvelopeError) as cm:
            be.x25519(secrets.token_bytes(32), b"\x00" * 32)
        self.assertEqual(cm.exception.code, "envelope-seal-refused")

    def test_bad_lengths_refused(self):
        with self.assertRaises(be.EnvelopeError):
            be.x25519(b"short", self.A_PUB)


class TestHkdfAead(unittest.TestCase):
    def test_hkdf_deterministic_and_distinct(self):
        k1 = be.hkdf(b"ikm", b"salt", b"info-a")
        k2 = be.hkdf(b"ikm", b"salt", b"info-a")
        k3 = be.hkdf(b"ikm", b"salt", b"info-b")
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)
        self.assertEqual(len(k1), 32)

    def test_aead_roundtrip(self):
        key = secrets.token_bytes(32)
        nonce, ct, tag = be.aead_seal(key, b"aad", b"hello")
        self.assertEqual(be.aead_open(key, b"aad", nonce, ct, tag), b"hello")

    def test_aead_tamper_matrix(self):
        key = secrets.token_bytes(32)
        nonce, ct, tag = be.aead_seal(key, b"aad", b"hello world")
        cases = [
            ("ct", bytes(b ^ 0xFF for b in ct[:1]) + ct[1:], tag, b"aad"),
            ("tag", ct, bytes(b ^ 0x01 for b in tag[:1]) + tag[1:], b"aad"),
            ("aad", ct, tag, b"other-aad"),
            ("nonce", ct, tag, b"aad"),
        ]
        for name, c, t, a in cases:
            n = nonce if name != "nonce" else secrets.token_bytes(24)
            with self.assertRaises(be.EnvelopeError) as cm:
                be.aead_open(key, a, n, c, t)
            self.assertEqual(cm.exception.code, "envelope-mac-failed",
                             name)

    def test_aead_wrong_key(self):
        key = secrets.token_bytes(32)
        nonce, ct, tag = be.aead_seal(key, b"aad", b"x")
        with self.assertRaises(be.EnvelopeError) as cm:
            be.aead_open(secrets.token_bytes(32), b"aad", nonce, ct, tag)
        self.assertEqual(cm.exception.code, "envelope-mac-failed")


def _seal_two(tmp_policy=None):
    seed = _ed.generate_seed()
    privs = {}
    recips = []
    for i in range(2):
        priv = secrets.token_bytes(32)
        rid = "auditor-%d" % i
        privs[rid] = priv
        recips.append({"id": rid, "type": "offline",
                       "x25519_pub": be.x25519_pub(priv).hex()})
    policy = be.make_recipient_policy(recips) if tmp_policy is None \
        else tmp_policy
    env = be.seal_envelope(b'{"seq":1}', bundle_id="b-1", policy=policy,
                           signer_seed=seed)
    return env, privs, policy, seed


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        be.set_emit(None)

    def test_roundtrip_both_recipients(self):
        env, privs, policy, seed = _seal_two()
        pub = _ed.publickey(seed)
        for rid, priv in privs.items():
            self.assertEqual(
                be.open_envelope(env, recipient_id=rid, x25519_priv=priv,
                                 trusted_signer_pubs=[pub],
                                 expected_bundle_id="b-1"),
                b'{"seq":1}')

    def test_envelope_error_carries_code(self):
        env, privs, policy, seed = _seal_two()
        with self.assertRaises(be.EnvelopeError) as cm:
            be.open_envelope(env, recipient_id="nobody",
                             x25519_priv=next(iter(privs.values())),
                             trusted_signer_pubs=[_ed.publickey(seed)],
                             expected_bundle_id="b-1")
        self.assertEqual(cm.exception.code, "envelope-recipient-unknown")

    def test_tampered_sig_refused(self):
        env, privs, policy, seed = _seal_two()
        bad = copy.deepcopy(env)
        bad["sigs"][0]["sig"] = "00" * 64
        rid = next(iter(privs))
        with self.assertRaises(be.EnvelopeError) as cm:
            be.open_envelope(bad, recipient_id=rid, x25519_priv=privs[rid],
                             trusted_signer_pubs=[_ed.publickey(seed)],
                             expected_bundle_id="b-1")
        self.assertEqual(cm.exception.code, "envelope-signature-invalid")

    def test_tampered_bundle_id_refused(self):
        env, privs, policy, seed = _seal_two()
        bad = copy.deepcopy(env)
        bad["bundle_id"] = "b-evil"
        rid = next(iter(privs))
        # The sig covers bundle_id, so authorship fails first.
        with self.assertRaises(be.EnvelopeError) as cm:
            be.open_envelope(bad, recipient_id=rid, x25519_priv=privs[rid],
                             trusted_signer_pubs=[_ed.publickey(seed)],
                             expected_bundle_id="b-evil")
        self.assertEqual(cm.exception.code, "envelope-signature-invalid")

    def test_policy_validation(self):
        priv = secrets.token_bytes(32)
        good = be.make_recipient_policy(
            [{"id": "a", "type": "offline",
              "x25519_pub": be.x25519_pub(priv).hex()}])
        self.assertIn("policy_digest", good)
        with self.assertRaises(be.EnvelopeError) as cm:
            be.make_recipient_policy([])
        self.assertEqual(cm.exception.code, "recipient-policy-invalid")

    def test_rotate_changes_key_preserves_plaintext(self):
        env, privs, policy, seed = _seal_two()
        rid = next(iter(privs))
        new_env = be.rotate_envelope(env, recipient_id=rid,
                                     x25519_priv=privs[rid],
                                     policy=policy, signer_seed=seed)
        pub = _ed.publickey(seed)
        self.assertEqual(
            be.open_envelope(new_env, recipient_id=rid,
                             x25519_priv=privs[rid],
                             trusted_signer_pubs=[pub],
                             expected_bundle_id="b-1"),
            b'{"seq":1}')
        old_key = be._unwrap_data_key(
            next(w for w in env["wraps"] if w["recipient_id"] == rid),
            privs[rid], None, env["bundle_sha256"])
        new_key = be._unwrap_data_key(
            next(w for w in new_env["wraps"] if w["recipient_id"] == rid),
            privs[rid], None, new_env["bundle_sha256"])
        self.assertNotEqual(old_key, new_key)

    def test_updatekeys_revokes(self):
        env, privs, policy, seed = _seal_two()
        rids = list(privs)
        kept, dropped = rids[0], rids[1]
        new_policy = be.make_recipient_policy(
            [{"id": kept, "type": "offline",
              "x25519_pub": be.x25519_pub(privs[kept]).hex()}])
        new_env = be.update_wraps(env, recipient_id=kept,
                                  x25519_priv=privs[kept],
                                  new_policy=new_policy, signer_seed=seed)
        self.assertFalse(any(w["recipient_id"] == dropped
                             for w in new_env["wraps"]))
        with self.assertRaises(be.EnvelopeError) as cm:
            be.open_envelope(new_env, recipient_id=dropped,
                             x25519_priv=privs[dropped],
                             trusted_signer_pubs=[_ed.publickey(seed)],
                             expected_bundle_id="b-1")
        self.assertEqual(cm.exception.code, "envelope-recipient-unknown")

    def test_updatekeys_keeps_same_data_key(self):
        # S6: updatekeys re-wraps the SAME data key (rotate semantics
        # would be a silent regression here).
        env, privs, policy, seed = _seal_two()
        rids = list(privs)
        kept = rids[0]
        new_policy = be.make_recipient_policy(
            [{"id": kept, "type": "offline",
              "x25519_pub": be.x25519_pub(privs[kept]).hex()}])
        new_env = be.update_wraps(env, recipient_id=kept,
                                  x25519_priv=privs[kept],
                                  new_policy=new_policy, signer_seed=seed)
        old_key = be._unwrap_data_key(
            next(w for w in env["wraps"] if w["recipient_id"] == kept),
            privs[kept], None, env["bundle_sha256"])
        new_key = be._unwrap_data_key(
            next(w for w in new_env["wraps"] if w["recipient_id"] == kept),
            privs[kept], None, new_env["bundle_sha256"])
        self.assertEqual(old_key, new_key)

    def test_policy_digest_verified_at_use(self):
        # S1: a policy edited after registration is refused at seal.
        env, privs, policy, seed = _seal_two()
        tampered = copy.deepcopy(policy)
        tampered["min_recipients"] = 2
        with self.assertRaises(be.EnvelopeError) as cm:
            be.seal_envelope(b'{"seq":2}', bundle_id="b-2",
                             policy=tampered, signer_seed=seed)
        self.assertEqual(cm.exception.code, "recipient-policy-invalid")
        digestless = {k: v for k, v in policy.items()
                      if k != "policy_digest"}
        with self.assertRaises(be.EnvelopeError) as cm:
            be.seal_envelope(b'{"seq":2}', bundle_id="b-2",
                             policy=digestless, signer_seed=seed)
        self.assertEqual(cm.exception.code, "recipient-policy-invalid")

    def test_bundle_scope_enforced(self):
        # S4: out-of-scope bundle ids are refused at seal time.
        seed = secrets.token_bytes(32)
        priv = secrets.token_bytes(32)
        policy = be.make_recipient_policy(
            [{"id": "a", "type": "offline",
              "x25519_pub": be.x25519_pub(priv).hex()}],
            bundle_scope="evidence/")
        env = be.seal_envelope(b'{"seq":2}', bundle_id="evidence/2026-10",
                               policy=policy, signer_seed=seed)
        self.assertEqual(env["bundle_id"], "evidence/2026-10")
        with self.assertRaises(be.EnvelopeError) as cm:
            be.seal_envelope(b'{"seq":2}', bundle_id="other/1",
                             policy=policy, signer_seed=seed)
        self.assertEqual(cm.exception.code, "recipient-policy-invalid")

    def test_audit_events_carry_no_key_material(self):
        events = []
        be.set_emit(events.append)
        try:
            env, privs, policy, seed = _seal_two()
            rid = next(iter(privs))
            be.rotate_envelope(env, recipient_id=rid,
                               x25519_priv=privs[rid],
                               policy=policy, signer_seed=seed)
        finally:
            be.set_emit(None)
        blob = json.dumps(events)
        self.assertNotIn(privs[rid].hex(), blob)
        kinds = {e["event"] for e in events}
        self.assertIn("envelope-rotated", kinds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
