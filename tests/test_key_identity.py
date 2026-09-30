#!/usr/bin/env python3
"""Unit tests for gov/key_identity.py: registered-key resolution with a
hybrid-signature mandate check.

Independent spec-vector literals (no calls into the module under test
to derive expectations): refusal codes are asserted as literal
strings, digests as literals recomputed from stdlib hashlib over
fixed test keys.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import alg_registry as alg  # noqa: E402
from gov import key_identity as ki  # noqa: E402
from gov import revocation as rev  # noqa: E402

ED = "ed25519-rfc8032"

# Fixed test keys (arbitrary non-secret vectors; secrets are generated
# fresh per test, these bytes are only identity fixtures).
PUB_A = b"wave227-test-pubkey-alpha-0001"
PUB_B = b"wave227-test-pubkey-beta--0002"
DIGEST_A_SHA256 = hashlib.sha256(PUB_A).hexdigest()


def _code_of(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return getattr(exc, "code", None)
    return None


def _fresh_ed():
    areg = alg.default_registry()
    seed, pub = areg.keygen(ED)
    return areg, seed, pub


class TestRegisteredKeyBuild(unittest.TestCase):
    def test_build_binds_digest_from_pubkey(self):
        key = ki.RegisteredKey.build("ka", ED, "sha256", PUB_A)
        rec = key.record()
        self.assertEqual(rec["pubkey_digest"], DIGEST_A_SHA256)
        self.assertEqual(rec["key_type"], ED)
        self.assertEqual(rec["digest_alg"], "sha256")
        self.assertEqual(rec["status"], "active")
        self.assertIsNone(rec["hybrid_of"])

    def test_build_rejects_unregistered_key_type(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "kb", "rsa-4096", "sha256", PUB_A)),
            "key-identity-unregistered")

    def test_build_rejects_unregistered_digest_alg(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "kc", ED, "md5", PUB_A)),
            "key-identity-unregistered")

    def test_build_rejects_empty_pubkey(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "kd", ED, "sha256", b"")),
            "key-identity-malformed")

    def test_build_rejects_bad_status(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "ke", ED, "sha256", PUB_A, status="suspended")),
            "key-identity-malformed")

    def test_build_rejects_self_leg(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "kf", ED, "sha256", PUB_A, hybrid_of=("kf", "other"))),
            "key-identity-malformed")

    def test_build_rejects_duplicate_legs(self):
        self.assertEqual(
            _code_of(lambda: ki.RegisteredKey.build(
                "kg", ED, "sha256", PUB_A, hybrid_of=("a", "a"))),
            "key-identity-malformed")

    def test_record_is_a_copy(self):
        key = ki.RegisteredKey.build("kh", ED, "sha256", PUB_A)
        rec = key.record()
        rec["key_id"] = "tampered"
        self.assertEqual(key.record()["key_id"], "kh")


class TestRegistryResolve(unittest.TestCase):
    def test_resolve_unknown_refuses(self):
        self.assertEqual(
            _code_of(lambda: ki.KeyRegistry().resolve("nope")),
            "key-identity-unknown")

    def test_resolve_retired_refuses(self):
        kreg = ki.KeyRegistry()
        kreg.register(ki.RegisteredKey.build(
            "kr", ED, "sha256", PUB_A, status="retired"))
        self.assertEqual(
            _code_of(lambda: kreg.resolve("kr")), "key-identity-revoked")

    def test_resolve_revoked_in_registry_refuses(self):
        areg = alg.default_registry()
        seed, pub = areg.keygen(ED)
        digest = hashlib.sha256(pub).hexdigest()
        rlist = rev.RevocationList()
        rlist.revoke(digest, issuer_id="ca", seed=os.urandom(32))
        kreg = ki.KeyRegistry(revocation_registry=rlist)
        kreg.register(ki.RegisteredKey.build("kv", ED, "sha256", pub))
        self.assertEqual(
            _code_of(lambda: kreg.resolve("kv")), "key-identity-revoked")

    def test_resolve_without_registry_is_nominal(self):
        kreg = ki.KeyRegistry()
        kreg.register(ki.RegisteredKey.build("kn", ED, "sha256", PUB_A))
        got = kreg.resolve("kn")
        self.assertEqual(got["key_id"], "kn")
        self.assertEqual(got["pubkey_digest"], DIGEST_A_SHA256)

    def test_register_rejects_non_record(self):
        self.assertEqual(
            _code_of(lambda: ki.KeyRegistry().register({"key_id": "x"})),
            "key-identity-malformed")

    def test_resolve_returns_copy(self):
        kreg = ki.KeyRegistry()
        kreg.register(ki.RegisteredKey.build("kcopy", ED, "sha256", PUB_A))
        got = kreg.resolve("kcopy")
        got["key_id"] = "tampered"
        self.assertEqual(kreg.resolve("kcopy")["key_id"], "kcopy")


class TestHybrid(unittest.TestCase):
    def _two_leg_registry(self):
        areg, seed_a, pub_a = _fresh_ed()
        seed_b, pub_b = areg.keygen(ED)
        kreg = ki.KeyRegistry()
        kreg.register(ki.RegisteredKey.build("leg-a", ED, "sha256", pub_a))
        kreg.register(ki.RegisteredKey.build("leg-b", ED, "sha256", pub_b))
        kreg.register(ki.RegisteredKey.build(
            "hyb", ED, "sha256", pub_a, hybrid_of=("leg-a", "leg-b")))
        return kreg, areg, seed_a, pub_a, seed_b, pub_b

    def test_hybrid_both_legs_verify(self):
        kreg, areg, seed_a, pub_a, seed_b, pub_b = self._two_leg_registry()
        msg = b"hybrid unit message"
        self.assertTrue(kreg.verify_hybrid(
            "hyb", msg, areg.sign(ED, msg, seed_a),
            areg.sign(ED, msg, seed_b), pub_a, pub_b))

    def test_hybrid_wrong_message_fails_leg(self):
        kreg, areg, seed_a, pub_a, seed_b, pub_b = self._two_leg_registry()
        msg = b"hybrid unit message"
        sig_b = areg.sign(ED, b"different message", seed_b)
        self.assertEqual(
            _code_of(lambda: kreg.verify_hybrid(
                "hyb", msg, areg.sign(ED, msg, seed_a), sig_b,
                pub_a, pub_b)),
            "hybrid-leg-failed")

    def test_hybrid_on_non_hybrid_key_refuses(self):
        kreg, areg, seed_a, pub_a, seed_b, pub_b = self._two_leg_registry()
        msg = b"m"
        self.assertEqual(
            _code_of(lambda: kreg.verify_hybrid(
                "leg-a", msg, b"s1", b"s2", pub_a, pub_b)),
            "hybrid-leg-invalid")

    def test_hybrid_unknown_key_refuses(self):
        kreg = ki.KeyRegistry()
        self.assertEqual(
            _code_of(lambda: kreg.verify_hybrid(
                "ghost", b"m", b"s1", b"s2", PUB_A, PUB_B)),
            "key-identity-unknown")

    def test_hybrid_revoked_leg_refuses_before_signatures(self):
        areg, seed_a, pub_a = _fresh_ed()
        seed_b, pub_b = areg.keygen(ED)
        # Revoke leg-b's digest only: the hybrid record itself (bound to
        # pub_a) stays nominal, so the refusal must name the dead leg.
        digest_b = hashlib.sha256(pub_b).hexdigest()
        rlist = rev.RevocationList()
        rlist.revoke(digest_b, issuer_id="ca", seed=os.urandom(32))
        kreg = ki.KeyRegistry(revocation_registry=rlist)
        kreg.register(ki.RegisteredKey.build("leg-a", ED, "sha256", pub_a))
        kreg.register(ki.RegisteredKey.build("leg-b", ED, "sha256", pub_b))
        kreg.register(ki.RegisteredKey.build(
            "hyb", ED, "sha256", pub_a, hybrid_of=("leg-a", "leg-b")))
        self.assertEqual(
            _code_of(lambda: kreg.verify_hybrid(
                "hyb", b"m", b"s1", b"s2", pub_a, pub_b)),
            "hybrid-leg-invalid")


if __name__ == "__main__":
    unittest.main()
