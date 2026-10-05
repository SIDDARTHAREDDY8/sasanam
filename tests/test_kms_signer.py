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


class _RecordingDisciplineAdapter(ks.KmsSigner):
    """Test-local fake KMS for the receipt discipline: owns NO key
    bytes. The "signature" is a deterministic tag over the bytes
    received -- it stands in for a separate KMS process."""

    def __init__(self, adapter_id="test-kms-1", fail=False):
        super(_RecordingDisciplineAdapter, self).__init__()
        self._adapter_id = adapter_id
        self._fail = fail
        self.received = []

    def _backend_sign(self, key_ref, message):
        if self._fail:
            raise RuntimeError("KMS unreachable")
        self.received.append(bytes(message))
        return b"TAG:" + bytes(message)[:16]

    def _public_key_for(self, key_ref):
        return b""


def _discipline_verifier(canonical_bytes, signature, key_ref):
    return signature == b"TAG:" + canonical_bytes[:16]


_DISCIPLINE_RECEIPT = {"principal": "agent-7", "action": "read",
                       "target": "file:///etc/x", "nonce": "n-001"}


class ReceiptDisciplineTests(unittest.TestCase):
    """Wave-244 lane E: the receipt discipline. The signing key is
    NEVER in-process; raw key bytes in any input path refuse
    signer-key-material-in-process; a declared handle wrapping
    in-process material refuses signer-adapter-tampered; adapter
    failure fails closed (signer-unavailable) with no fallback;
    the verifier's bool contract is enforced (exactly True
    verifies)."""

    def setUp(self):
        self._ledger_len = len(ks.SIGNING_LEDGER)

    def tearDown(self):
        del ks.SIGNING_LEDGER[self._ledger_len:]

    def _algorithm(self):
        return sorted(ar.default_registry().names())[0]

    def _key_ref(self, provider="test-kms", key_id="k-1"):
        return ks.KeyRef(provider, key_id, self._algorithm())

    def _expect(self, code, fn):
        try:
            fn()
        except ks.KmsSignerError as exc:
            self.assertEqual(exc.code, code,
                             "code %r, expected %r" % (exc.code, code))
            return
        self.fail("no refusal; expected %s" % code)

    def test_happy_path_and_ledger(self):
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        self.assertEqual(signed["v"], 1)
        self.assertEqual(signed["key_ref"]["provider"], "test-kms")
        self.assertEqual(len(signed["canonical_sha256"]), 64)
        self.assertTrue(signed["signature"].startswith("5441473a"))
        entries = [e for e in ks.SIGNING_LEDGER
                   if e["canonical_sha256"] == signed["canonical_sha256"]]
        self.assertTrue(entries)
        self.assertEqual(entries[0]["provider"], "test-kms")
        self.assertEqual(entries[0]["key_id"], "k-1")
        digest = ks.verify_signed_receipt(signed, ref,
                                          _discipline_verifier)
        self.assertEqual(digest, signed["canonical_sha256"])

    def test_raw_bytes_signer_refused(self):
        ref = self._key_ref()
        self._expect(
            "signer-key-material-in-process",
            lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                    b"\x01" * 32, ref))

    def test_slots_object_scanned_without_typeerror(self):
        # _own_attributes tolerates __slots__-only objects where
        # vars() raises TypeError; the tamper scan still sees the
        # slot.
        class SlotsOnly(object):
            __slots__ = ("_secret",)

            def __init__(self):
                self._secret = b"\x06" * 32
        attrs = dict(ks._own_attributes(SlotsOnly()))
        self.assertEqual(attrs["_secret"], b"\x06" * 32)
        self.assertEqual(ks._scan_value("_secret", attrs["_secret"]),
                         "_secret")

    def test_dict_signer_with_bland_name_material_refused(self):
        # Shape-only: the dict key gives no hint, but the value is
        # key-length bytes on the signer-argument path.
        ref = self._key_ref()
        self._expect(
            "signer-key-material-in-process",
            lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                    {"k": b"\x02" * 32}, ref))

    def test_object_with_seed_refused(self):
        class Sneaky(object):
            def __init__(self):
                self.seed = b"\x03" * 32
        ref = self._key_ref()
        self._expect("signer-key-material-in-process",
                     lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                             Sneaky(), ref))

    def test_tampered_adapter_refused(self):
        class TamperedAdapter(ks.KmsSigner):
            def __init__(self):
                super(TamperedAdapter, self).__init__()
                self._key_material = b"\x04" * 32

            def _backend_sign(self, key_ref, message):
                return b"TAG" + bytes(message)[:4]

            def _public_key_for(self, key_ref):
                return b""
        ref = self._key_ref()
        self._expect("signer-adapter-tampered",
                     lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                             TamperedAdapter(), ref))

    def test_loopback_test_double_refused(self):
        loop = kl.LoopbackKms()
        ref = loop.provision_key("loopback", "dev-1", self._algorithm())
        self._expect("signer-adapter-tampered",
                     lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                             loop, ref))

    def test_config_pem_refused(self):
        config = {"adapter": "vault-transit", "key_id": "k-1",
                  "private_key_pem": "-----BEGIN PRIVATE KEY-----\nAAA\n"
                                     "-----END PRIVATE KEY-----",
                  "algorithm": self._algorithm()}
        self._expect("signer-key-material-in-process",
                     lambda: ks.signer_from_config(config))

    def test_config_raw_seed_refused(self):
        config = {"adapter": "hsm", "key_id": "k-1",
                  "seed": "00" * 32, "algorithm": self._algorithm()}
        self._expect("signer-key-material-in-process",
                     lambda: ks.signer_from_config(config))

    def test_config_bland_name_seed_refused(self):
        # Shape-only pass: the slot name is irrelevant on the
        # declaration path; key-length bytes are refused whatever
        # they are called.
        config = {"adapter": "hsm", "key_id": "k-1",
                  "banana": b"\x05" * 32,
                  "algorithm": self._algorithm()}
        self._expect("signer-key-material-in-process",
                     lambda: ks.signer_from_config(config))

    def test_declared_adapter_unavailable_fails_closed(self):
        config = {"adapter": "vault-transit", "key_id": "k-9",
                  "algorithm": self._algorithm()}
        handle = ks.signer_from_config(config)
        ref = self._key_ref("vault-transit", "k-9")
        self._expect("signer-unavailable",
                     lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                             handle, ref))

    def test_backend_failure_fails_closed_no_fallback(self):
        adapter = _RecordingDisciplineAdapter("kms-down", fail=True)
        ref = self._key_ref()
        self._expect("signer-unavailable",
                     lambda: ks.sign_receipt(dict(_DISCIPLINE_RECEIPT),
                                             adapter, ref))

    def test_identity_mismatch_refused(self):
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref("test-kms", "k-1")
        other = self._key_ref("test-kms", "k-9")
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        self._expect("signer-identity-mismatch",
                     lambda: ks.verify_signed_receipt(
                         signed, other, _discipline_verifier))

    def test_identity_algorithm_mismatch_refused(self):
        # Identity is the full KeyRef record: provider, key_id AND
        # algorithm. An algorithm-substituted record mismatches.
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref("test-kms", "k-1")
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        other_alg = ks.KeyRef("test-kms", "k-1",
                              "hmac-sha256-256"
                              if ref.algorithm != "hmac-sha256-256"
                              else "ed25519-rfc8032")
        self._expect("signer-identity-mismatch",
                     lambda: ks.verify_signed_receipt(
                         signed, other_alg, _discipline_verifier))

    def test_adapter_receives_canonical_bytes_only(self):
        import json as _json
        adapter = _RecordingDisciplineAdapter("kms-canon")
        ref = self._key_ref()
        messy = {"target": "file:///etc/x", "nonce": "n-001",
                 "principal": "agent-7", "action": "read"}
        ks.sign_receipt(messy, adapter, ref)
        self.assertEqual(len(adapter.received), 1)
        expected = _json.dumps(messy, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True).encode("utf-8")
        self.assertEqual(adapter.received[0], expected)

    def test_mutated_receipt_refused(self):
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        mutated = dict(signed)
        mutated_receipt = dict(signed["receipt"])
        mutated_receipt["action"] = "delete"
        mutated["receipt"] = mutated_receipt
        self._expect("signed-receipt-malformed",
                     lambda: ks.verify_signed_receipt(
                         mutated, ref, _discipline_verifier))

    def test_verifier_false_refused(self):
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        self._expect("signed-receipt-signature-invalid",
                     lambda: ks.verify_signed_receipt(
                         signed, ref, lambda c, s, k: False))

    def test_verifier_none_refused(self):
        # Bool contract: None is not True -- never verified.
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        self._expect("signed-receipt-signature-invalid",
                     lambda: ks.verify_signed_receipt(
                         signed, ref, lambda c, s, k: None))

    def test_verifier_raises_refused(self):
        def bad_verifier(c, s, k):
            raise RuntimeError("verifier exploded")
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        signed = ks.sign_receipt(dict(_DISCIPLINE_RECEIPT), adapter, ref)
        self._expect("signed-receipt-signature-invalid",
                     lambda: ks.verify_signed_receipt(signed, ref,
                                                      bad_verifier))

    def test_non_dict_receipt_refused(self):
        adapter = _RecordingDisciplineAdapter("kms-east-1")
        ref = self._key_ref()
        self._expect("signed-receipt-malformed",
                     lambda: ks.sign_receipt("not-a-dict", adapter, ref))

    def test_codes_in_taxonomy(self):
        from gov import decision_codes as dc
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 2100) # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 lane 4: pin 1641 -> 1642 (+1 keyset-pin-key-invalid).; Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        for code in ("signer-key-material-in-process",
                     "signer-adapter-tampered", "signer-unavailable",
                     "signer-identity-mismatch",
                     "signed-receipt-malformed",
                     "signed-receipt-signature-invalid"):
            dc.code_for(code)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "kms-signer")


if __name__ == "__main__":
    unittest.main()
