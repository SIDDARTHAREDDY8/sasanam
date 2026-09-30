#!/usr/bin/env python3
"""Unit tests for gov/kms_signer.py, gov/kms_signer_loopback.py, and
the additive signer-backend wiring in gov/alg_registry.py.

Spec vectors are independent literals (fixed seeds / fixed keys),
not recomputed through the code under test.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import alg_registry as ar  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov import kms_signer as ks  # noqa: E402
from gov import kms_signer_loopback as kl  # noqa: E402


class KeyRefTests(unittest.TestCase):
    def test_preserves_fields(self):
        ref = ks.KeyRef(provider="vault", key_id="signing-key-1",
                        algorithm="ed25519-rfc8032")
        self.assertEqual(ref.provider, "vault")
        self.assertEqual(ref.key_id, "signing-key-1")
        self.assertEqual(ref.algorithm, "ed25519-rfc8032")

    def test_malformed_refused(self):
        for kwargs in (dict(provider="", key_id="k", algorithm="ed25519-rfc8032"),
                       dict(provider="  ", key_id="k", algorithm="ed25519-rfc8032"),
                       dict(provider="vault", key_id="", algorithm="ed25519-rfc8032"),
                       dict(provider="vault", key_id="k", algorithm=""),
                       dict(provider="vault", key_id="k", algorithm=None),
                       dict(provider=None, key_id="k", algorithm="ed25519-rfc8032")):
            with self.assertRaises(ks.KmsSignerError, msg=str(kwargs)):
                ks.KeyRef(**kwargs)
            try:
                ks.KeyRef(**kwargs)
            except ks.KmsSignerError as exc:
                self.assertEqual(exc.code, "kms-signer-keyref-invalid")

    def test_equality_and_hash(self):
        a = ks.KeyRef("vault", "k1", "ed25519-rfc8032")
        b = ks.KeyRef("vault", "k1", "ed25519-rfc8032")
        c = ks.KeyRef("vault", "k2", "ed25519-rfc8032")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, "not-a-keyref")

    def test_error_codes_are_exact(self):
        self.assertEqual(ks.KmsSignerError.code, "kms-signer-refused")
        self.assertEqual(ks.KmsSignerAlgorithmError.code,
                         "kms-signer-algorithm-refused")
        self.assertEqual(ks.KmsSignerMessageTooLargeError.code,
                         "kms-signer-message-too-large")
        self.assertEqual(ks.KmsSignerKeyRefError.code,
                         "kms-signer-keyref-invalid")


class LoopbackTests(unittest.TestCase):
    def _loopback(self, alg="ed25519-rfc8032"):
        lb = kl.LoopbackKms()
        ref = lb.provision_key("vault", "%s-key" % alg[:8], alg)
        return lb, ref

    def test_provision_and_sign_verify(self):
        lb, ref = self._loopback()
        sig = lb.sign(ref, b"hello")
        self.assertIsInstance(sig, bytes)
        self.assertEqual(len(sig), 64)
        self.assertTrue(lb.verify(ref, b"hello", sig))

    def test_verify_with_raw_pubkey(self):
        lb, ref = self._loopback()
        sig = lb.sign(ref, b"hello")
        pub = lb.public_key_for(ref)
        self.assertTrue(lb.verify(pub, b"hello", sig,
                                 algorithm="ed25519-rfc8032"))

    def test_verify_raw_pubkey_needs_algorithm(self):
        lb, ref = self._loopback()
        sig = lb.sign(ref, b"hello")
        pub = lb.public_key_for(ref)
        with self.assertRaises(ks.KmsSignerError) as cm:
            lb.verify(pub, b"hello", sig)
        self.assertEqual(cm.exception.code,
                         "kms-signer-algorithm-refused")

    def test_unknown_algorithm_refused(self):
        lb = kl.LoopbackKms()
        with self.assertRaises(ks.KmsSignerError) as cm:
            lb.provision_key("vault", "k", "nope-v99")
        self.assertEqual(cm.exception.code,
                         "kms-signer-algorithm-refused")
        ref = ks.KeyRef("vault", "k", "nope-v99")
        with self.assertRaises(ks.KmsSignerError) as cm2:
            lb.sign(ref, b"msg")
        self.assertEqual(cm2.exception.code,
                         "kms-signer-algorithm-refused")

    def test_unknown_key_id_refused(self):
        lb = kl.LoopbackKms()
        ref = ks.KeyRef("vault", "never-provisioned", "ed25519-rfc8032")
        with self.assertRaises(ks.KmsSignerError):
            lb.sign(ref, b"msg")

    def test_message_too_large(self):
        lb, ref = self._loopback()
        with self.assertRaises(ks.KmsSignerError) as cm:
            lb.sign(ref, b"x" * (ks.MAX_MESSAGE_BYTES + 1))
        self.assertEqual(cm.exception.code, "kms-signer-message-too-large")
        # Exactly at the bound is accepted.
        sig = lb.sign(ref, b"x" * ks.MAX_MESSAGE_BYTES)
        self.assertTrue(lb.verify(ref, b"x" * ks.MAX_MESSAGE_BYTES, sig))

    def test_max_message_bytes_value(self):
        self.assertEqual(ks.MAX_MESSAGE_BYTES, 1 << 20)

    def test_tampered_fails(self):
        lb, ref = self._loopback()
        sig = lb.sign(ref, b"msg")
        self.assertFalse(lb.verify(ref, b"other", sig))
        bad = bytearray(sig)
        bad[7] ^= 0x01
        self.assertFalse(lb.verify(ref, b"msg", bytes(bad)))

    def test_no_key_material_exfil(self):
        lb, ref = self._loopback()
        # No public attribute reveals seeds or private keys.
        for name in dir(lb):
            self.assertFalse(
                ("seed" in name.lower() or "private" in name.lower())
                and not name.startswith("_"),
                "key-material accessor: %s" % name)
        # The store holds the seed but nothing public reaches it.
        self.assertNotIn("seed", lb.key_ids()[0][0])

    def test_determinism(self):
        lb, ref = self._loopback()
        self.assertEqual(lb.sign(ref, b"m"), lb.sign(ref, b"m"))

    def test_receipt_honest_tiers(self):
        lb, ref = self._loopback("ed25519-rfc8032")
        r = lb.sign_labeled(ref, b"m")
        self.assertTrue(r.non_repudiation)
        self.assertEqual(r.algorithm, "ed25519-rfc8032")
        d = r.describe()
        self.assertNotIn("signature", d)
        self.assertEqual(d["non_repudiation"], True)

        lb2, mref = self._loopback("hmac-sha256-mac")
        mr = lb2.sign_labeled(mref, b"m")
        self.assertFalse(mr.non_repudiation)
        self.assertEqual(mr.describe()["non_repudiation"], False)

    def test_custom_registry(self):
        reg = ar.AlgorithmRegistry()

        def _kg():
            s = ed.generate_seed()
            return s, ed.publickey(s)

        reg.register("ed25519-rfc8032",
                     sign_fn=lambda s, m: ed.sign(bytes(s), bytes(m)),
                     verify_fn=lambda k, m, g: ed.verify(bytes(k),
                                                         bytes(m),
                                                         bytes(g)),
                     keygen=_kg,
                     domain_separator=b"sasanam-unit-test:",
                     non_repudiation=True)
        lb = kl.LoopbackKms(registry=reg)
        ref = lb.provision_key("vault", "k", "ed25519-rfc8032")
        sig = lb.sign(ref, b"m")
        self.assertTrue(lb.verify(ref, b"m", sig))

    def test_loopback_docstring_warns(self):
        self.assertIn("NEVER a production KMS substitute",
                      " ".join((kl.__doc__ or "").split()))


class RegistryBackendTests(unittest.TestCase):
    def test_defaults_unchanged(self):
        reg = ar.default_registry()
        self.assertFalse(reg.has_signer_backend("ed25519-rfc8032"))
        self.assertFalse(reg.has_signer_backend("hmac-sha256-mac"))
        # Legacy sign() path untouched.
        seed, pub = reg.keygen("ed25519-rfc8032")
        sig = reg.sign("ed25519-rfc8032", b"legacy", seed)
        self.assertTrue(reg.verify("ed25519-rfc8032", b"legacy", sig, pub))

    def test_register_and_use_backend(self):
        reg = ar.AlgorithmRegistry()

        def _kg():
            s = ed.generate_seed()
            return s, ed.publickey(s)

        reg.register("ed25519-rfc8032",
                     sign_fn=lambda s, m: ed.sign(bytes(s), bytes(m)),
                     verify_fn=lambda k, m, g: ed.verify(bytes(k),
                                                         bytes(m),
                                                         bytes(g)),
                     keygen=_kg,
                     domain_separator=b"sasanam-unit-test-2:",
                     non_repudiation=True)
        lb = kl.LoopbackKms(registry=reg)
        ref = lb.provision_key("vault", "k", "ed25519-rfc8032")
        reg.register_signer_backend("ed25519-rfc8032", lb)
        self.assertTrue(reg.has_signer_backend("ed25519-rfc8032"))
        sig = reg.sign_via_backend("ed25519-rfc8032", b"via", ref)
        self.assertTrue(reg.verify("ed25519-rfc8032", b"via", sig,
                                  lb.public_key_for(ref)))
        reg.clear_signer_backend("ed25519-rfc8032")
        self.assertFalse(reg.has_signer_backend("ed25519-rfc8032"))

    def test_backend_unknown_alg_refused(self):
        reg = ar.AlgorithmRegistry()
        lb = kl.LoopbackKms(registry=reg)
        with self.assertRaises(ar.AlgError) as cm:
            reg.register_signer_backend("nope-v99", lb)
        self.assertEqual(cm.exception.code, "alg-unregistered")

    def test_sign_via_backend_no_backend_refused(self):
        reg = ar.AlgorithmRegistry()

        def _kg():
            s = ed.generate_seed()
            return s, ed.publickey(s)

        reg.register("ed25519-rfc8032",
                     sign_fn=lambda s, m: ed.sign(bytes(s), bytes(m)),
                     verify_fn=lambda k, m, g: ed.verify(bytes(k),
                                                         bytes(m),
                                                         bytes(g)),
                     keygen=_kg,
                     domain_separator=b"sasanam-unit-test-3:",
                     non_repudiation=True)
        with self.assertRaises(ar.AlgError) as cm:
            reg.sign_via_backend("ed25519-rfc8032", b"m", None)
        self.assertEqual(cm.exception.code, "alg-unregistered")

    def test_backend_needs_callable_sign(self):
        reg = ar.AlgorithmRegistry()

        def _kg():
            s = ed.generate_seed()
            return s, ed.publickey(s)

        reg.register("ed25519-rfc8032",
                     sign_fn=lambda s, m: ed.sign(bytes(s), bytes(m)),
                     verify_fn=lambda k, m, g: ed.verify(bytes(k),
                                                         bytes(m),
                                                         bytes(g)),
                     keygen=_kg,
                     domain_separator=b"sasanam-unit-test-5:",
                     non_repudiation=True)
        with self.assertRaises(ar.AlgError) as cm:
            reg.register_signer_backend("ed25519-rfc8032", object())
        self.assertEqual(cm.exception.code, "alg-registration-refused")

    def test_sign_via_backend_routes_to_backend(self):
        # The backend's sign is the ONLY code path used.
        seen = []

        class _Spy:
            def sign(self, key_ref, message):
                seen.append((key_ref, message))
                return b"spy-sig"

        reg = ar.AlgorithmRegistry()

        def _kg():
            s = ed.generate_seed()
            return s, ed.publickey(s)

        reg.register("ed25519-rfc8032",
                     sign_fn=lambda s, m: ed.sign(bytes(s), bytes(m)),
                     verify_fn=lambda k, m, g: ed.verify(bytes(k),
                                                         bytes(m),
                                                         bytes(g)),
                     keygen=_kg,
                     domain_separator=b"sasanam-unit-test-4:",
                     non_repudiation=True)
        reg.register_signer_backend("ed25519-rfc8032", _Spy())
        ref = ks.KeyRef("vault", "k", "ed25519-rfc8032")
        out = reg.sign_via_backend("ed25519-rfc8032", b"m", ref)
        self.assertEqual(out, b"spy-sig")
        self.assertEqual(seen, [(ref, b"m")])


if __name__ == "__main__":
    unittest.main()
