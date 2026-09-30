#!/usr/bin/env python3
"""Unit tests for algorithm agility (wave-224 lane C).

Covers gov/alg_registry.py at its public seam plus the additive
wiring in gov/posture.py, gov/absence.py and gov/revocation.py:
registration validation, the two built-in tiers (ed25519-rfc8032
and the honestly-labeled hmac-sha256-mac MAC tier), negotiation,
the non-repudiation guard, and per-record alg dispatch with legacy
(byte-identical, no-alg-field) records verifying as ed25519.
"""

import os
import secrets
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import absence as ab
from gov import alg_registry as ar
from gov import ed25519 as _ed
from gov import posture as po
from gov import revocation as rv

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_ED = "ed25519-rfc8032"
_MAC = "hmac-sha256-mac"


def _ed_keypair():
    seed = _ed.generate_seed()
    return seed, _ed.publickey(seed)


def _mac_key():
    return secrets.token_bytes(32)


class RegistryBuiltinsTest(unittest.TestCase):
    def test_both_builtins_registered(self):
        reg = ar.default_registry()
        self.assertIn(_ED, reg.names())
        self.assertIn(_MAC, reg.names())

    def test_default_registry_is_singleton(self):
        self.assertIs(ar.default_registry(), ar.default_registry())

    def test_hmac_tier_honestly_labeled(self):
        info = ar.default_registry().info(_MAC)
        self.assertFalse(info["non_repudiation"])
        info_ed = ar.default_registry().info(_ED)
        self.assertTrue(info_ed["non_repudiation"])

    def test_info_hides_functions(self):
        info = ar.default_registry().info(_ED)
        self.assertNotIn("sign_fn", info)
        self.assertEqual(set(info),
                         {"name", "domain_separator", "non_repudiation",
                          "symmetric"})

    def test_info_unknown_refuses(self):
        with self.assertRaises(ar.AlgError) as ctx:
            ar.default_registry().info("rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")


class RegistrationValidationTest(unittest.TestCase):
    def _good(self, domain=b"sasanam-test/unit:"):
        return dict(sign_fn=lambda s, m: b"x",
                    verify_fn=lambda k, m, s: True,
                    keygen=lambda: (b"k", b"k"),
                    domain_separator=domain)

    def test_duplicate_name_refused(self):
        reg = ar.AlgorithmRegistry()
        reg.register("t1", **self._good())
        with self.assertRaises(ar.AlgError) as ctx:
            reg.register("t1", **self._good(b"sasanam-test/other:"))
        self.assertEqual(ctx.exception.code, "alg-registration-refused")

    def test_duplicate_domain_refused(self):
        reg = ar.AlgorithmRegistry()
        reg.register("t1", **self._good())
        with self.assertRaises(ar.AlgError) as ctx:
            reg.register("t2", **self._good())
        self.assertEqual(ctx.exception.code, "alg-registration-refused")

    def test_empty_domain_refused(self):
        reg = ar.AlgorithmRegistry()
        kwargs = self._good(domain=b"")
        with self.assertRaises(ar.AlgError) as ctx:
            reg.register("t1", **kwargs)
        self.assertEqual(ctx.exception.code, "alg-registration-refused")

    def test_non_callable_refused(self):
        reg = ar.AlgorithmRegistry()
        kwargs = self._good()
        kwargs["sign_fn"] = "nope"
        with self.assertRaises(ar.AlgError) as ctx:
            reg.register("t1", **kwargs)
        self.assertEqual(ctx.exception.code, "alg-registration-refused")

    def test_empty_name_refused(self):
        reg = ar.AlgorithmRegistry()
        with self.assertRaises(ar.AlgError) as ctx:
            reg.register("", **self._good())
        self.assertEqual(ctx.exception.code, "alg-registration-refused")

    def test_sign_unregistered_refused(self):
        reg = ar.default_registry()
        with self.assertRaises(ar.AlgError) as ctx:
            reg.sign("rot13", b"m", b"k" * 32)
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_verify_unregistered_refused(self):
        reg = ar.default_registry()
        with self.assertRaises(ar.AlgError) as ctx:
            reg.verify("rot13", b"m", b"s", b"k" * 32)
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_custom_registration_roundtrip(self):
        reg = ar.AlgorithmRegistry()
        seen = {}

        def sign_fn(secret, message):
            seen["m"] = (secret, message)
            return b"TAG:" + message

        def verify_fn(key, message, signature):
            return signature == b"TAG:" + message and key == b"key"

        reg.register("t-custom", sign_fn=sign_fn, verify_fn=verify_fn,
                     keygen=lambda: (b"key", b"pub"),
                     domain_separator=b"sasanam-test/custom:")
        sig = reg.sign("t-custom", b"hello", b"key")
        self.assertEqual(seen["m"], (b"key", b"hello"))
        self.assertTrue(reg.verify("t-custom", b"hello", sig, b"key"))
        self.assertFalse(reg.verify("t-custom", b"hello", b"wrong",
                                    b"key"))


class PrimitiveRoundtripTest(unittest.TestCase):
    def test_ed25519_roundtrip(self):
        reg = ar.default_registry()
        seed, pub = _ed_keypair()
        sig = reg.sign(_ED, b"hello", seed)
        self.assertTrue(reg.verify(_ED, b"hello", sig, pub))
        self.assertFalse(reg.verify(_ED, b"tampered", sig, pub))

    def test_hmac_roundtrip(self):
        reg = ar.default_registry()
        key = _mac_key()
        tag = reg.sign(_MAC, b"hello", key)
        # for_symmetric_key=True: the caller declares this key a shared
        # secret (algorithm-confusion guard, CWE-347 — see verify()).
        self.assertTrue(reg.verify(_MAC, b"hello", tag, key,
                                   for_symmetric_key=True))
        self.assertFalse(reg.verify(_MAC, b"tampered", tag, key,
                                    for_symmetric_key=True))
        self.assertFalse(reg.verify(_MAC, b"hello", tag, _mac_key(),
                                    for_symmetric_key=True))

    def test_hmac_without_secret_flag_refuses(self):
        # Algorithm-confusion guard: a symmetric tier verified without
        # for_symmetric_key refuses even with the correct secret — the
        # caller must declare the key a secret, never a public key.
        reg = ar.default_registry()
        key = _mac_key()
        tag = reg.sign(_MAC, b"hello", key)
        self.assertFalse(reg.verify(_MAC, b"hello", tag, key))
        self.assertTrue(reg.is_symmetric(_MAC))
        self.assertFalse(reg.is_symmetric(_ED))

    def test_verify_malformed_never_raises_raw(self):
        reg = ar.default_registry()
        seed, pub = _ed_keypair()
        self.assertFalse(reg.verify(_ED, "not-bytes", b"x", pub))
        self.assertFalse(reg.verify(_MAC, b"m", None, _mac_key(),
                                    for_symmetric_key=True))

    def test_keygen_shapes(self):
        reg = ar.default_registry()
        seed, pub = reg.keygen(_ED)
        self.assertEqual(len(seed), 32)
        self.assertEqual(pub, _ed.publickey(seed))
        key, _ = reg.keygen(_MAC)
        self.assertEqual(len(key), 32)


class NonRepudiationGuardTest(unittest.TestCase):
    def test_ed25519_passes(self):
        self.assertTrue(
            ar.default_registry().require_non_repudiation(_ED))

    def test_hmac_refused(self):
        with self.assertRaises(ar.AlgError) as ctx:
            ar.default_registry().require_non_repudiation(_MAC)
        self.assertEqual(ctx.exception.code,
                         "alg-non-repudiation-refused")

    def test_unknown_refused(self):
        with self.assertRaises(ar.AlgError) as ctx:
            ar.default_registry().require_non_repudiation("rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")


class NegotiationTest(unittest.TestCase):
    def test_picks_highest_mutual_preference(self):
        got = ar.negotiate_algorithms([_MAC, _ED], {_ED})
        self.assertEqual(got, _ED)

    def test_preference_order_wins(self):
        got = ar.negotiate_algorithms([_ED, _MAC], {_MAC, _ED})
        self.assertEqual(got, _ED)

    def test_no_mutual_refused(self):
        with self.assertRaises(ar.AlgError) as ctx:
            ar.negotiate_algorithms([_ED], set())
        self.assertEqual(ctx.exception.code, "alg-no-mutual")

    def test_unknown_name_skipped_not_refused(self):
        # Unknown names can never be mutual: skipped, so the
        # outcome is alg-no-mutual rather than alg-unregistered.
        with self.assertRaises(ar.AlgError) as ctx:
            ar.negotiate_algorithms(["rot13"], {_ED})
        self.assertEqual(ctx.exception.code, "alg-no-mutual")

    def test_unknown_acceptable_skipped(self):
        with self.assertRaises(ar.AlgError) as ctx:
            ar.negotiate_algorithms([_ED], {"rot13"})
        self.assertEqual(ctx.exception.code, "alg-no-mutual")


class PostureAgilityTest(unittest.TestCase):
    def test_default_emit_has_no_alg_field(self):
        seed, _pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        self.assertNotIn("alg", sig)
        self.assertEqual(set(sig),
                         {"v", "iss", "jti", "iat", "sub", "events",
                          "scope", "signature"})

    def test_unknown_alg_emit_refused(self):
        seed, _pub = _ed_keypair()
        with self.assertRaises(po.PostureError) as ctx:
            po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                           issuer_id="i", now=1700000000.0, alg="rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_hmac_emit_carries_alg_and_verifies(self):
        key = _mac_key()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                             issuer_id="i", now=1700000000.0, alg=_MAC)
        self.assertEqual(sig["alg"], _MAC)
        rec = po.verify_signal(sig, {"i": key}, expect_alg=_MAC)
        self.assertEqual(rec["sub"], _DIGEST_A)

    def test_legacy_record_verifies(self):
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        rec = po.verify_signal(sig, {"i": pub})
        self.assertEqual(rec["sub"], _DIGEST_A)

    def test_expect_alg_mismatch_refused(self):
        key = _mac_key()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                             issuer_id="i", now=1700000000.0, alg=_MAC)
        with self.assertRaises(po.PostureError) as ctx:
            po.verify_signal(sig, {"i": key}, expect_alg=_ED)
        self.assertEqual(ctx.exception.code, "alg-mismatch")

    def test_expect_alg_satisfied_by_legacy(self):
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        po.verify_signal(sig, {"i": pub}, expect_alg=_ED)

    def test_unknown_alg_verify_refused(self):
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        forged = dict(sig, alg="rot13")
        with self.assertRaises(po.SignalUnverifiableError) as ctx:
            po.verify_signal(forged, {"i": pub})
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_malformed_alg_field_refused(self):
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        bad = dict(sig, alg="")
        with self.assertRaises(po.PostureError) as ctx:
            po.verify_signal(bad, {"i": pub})
        self.assertEqual(ctx.exception.code, "signal-unverifiable")

    def test_relabel_breaks_signature(self):
        key = _mac_key()
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", key,
                             issuer_id="i", now=1700000000.0, alg=_MAC)
        relabeled = dict(sig, alg=_ED)
        with self.assertRaises(po.PostureError) as ctx:
            po.verify_signal(relabeled, {"i": pub})
        self.assertEqual(ctx.exception.code, "signal-unverifiable")


class AbsenceAgilityTest(unittest.TestCase):
    def test_default_issuer_ed25519(self):
        seed, pub = _ed_keypair()
        issuer = ab.AbsenceIssuer("i", seed)
        self.assertEqual(issuer.alg, _ED)
        self.assertEqual(issuer.public_key, pub)
        neg = issuer.attest_absence(_DIGEST_A, now=1700000000.0)
        self.assertNotIn("alg", neg)
        rec = ab.verify_negative(neg, pub)
        self.assertEqual(rec["claim"], "never-advertised")

    def test_hmac_issuer_tier(self):
        key = _mac_key()
        issuer = ab.AbsenceIssuer("i", key, alg=_MAC)
        self.assertIsNone(issuer.public_key)  # symmetric: no pubkey
        neg = issuer.attest_absence(_DIGEST_A, now=1700000000.0)
        self.assertEqual(neg["alg"], _MAC)
        # expect_alg pins the symmetric tier: the caller declares the
        # key a shared secret (algorithm-confusion guard, CWE-347).
        rec = ab.verify_negative(neg, key, expect_alg=_MAC)
        self.assertEqual(rec["claim"], "never-advertised")

    def test_per_record_override(self):
        seed, pub = _ed_keypair()
        issuer = ab.AbsenceIssuer("i", seed)
        key = _mac_key()
        # An ed25519 issuer overriding to hmac must hand the MAC key
        # through its own custody — here we only check the refusal
        # path for an unknown tier.
        with self.assertRaises(ab.AbsenceError) as ctx:
            issuer.attest_absence(_DIGEST_A, now=1700000000.0,
                                  alg="rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_expect_alg_mismatch_refused(self):
        key = _mac_key()
        issuer = ab.AbsenceIssuer("i", key, alg=_MAC)
        neg = issuer.attest_absence(_DIGEST_A, now=1700000000.0)
        with self.assertRaises(ab.AbsenceUnverifiableError) as ctx:
            ab.verify_negative(neg, key, expect_alg=_ED)
        self.assertEqual(ctx.exception.code, "alg-mismatch")

    def test_unknown_issuer_tier_refused(self):
        seed, _pub = _ed_keypair()
        with self.assertRaises(ab.AbsenceError) as ctx:
            ab.AbsenceIssuer("i", seed, alg="rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")


class RevocationAgilityTest(unittest.TestCase):
    def test_default_revoke_has_no_alg_field(self):
        seed, pub = _ed_keypair()
        rl = rv.RevocationList()
        entry = rl.revoke(_DIGEST_A, issuer_id="i", seed=seed,
                          now=1700000000.0)
        self.assertNotIn("alg", entry)
        self.assertTrue(rl.verify({"i": pub}))

    def test_hmac_revoke_roundtrip(self):
        key = _mac_key()
        rl = rv.RevocationList()
        entry = rl.revoke(_DIGEST_A, issuer_id="i", seed=key,
                          now=1700000000.0, alg=_MAC)
        self.assertEqual(entry["alg"], _MAC)
        self.assertTrue(rl.verify({"i": key}, expect_alg=_MAC))
        fresh = rv.RevocationList()
        fresh.import_entries([entry], {"i": key},
                             expect_alg=_MAC)
        self.assertEqual(fresh.check(_DIGEST_A), "revoked")

    def test_expect_alg_mismatch_refused(self):
        key = _mac_key()
        rl = rv.RevocationList()
        rl.revoke(_DIGEST_A, issuer_id="i", seed=key,
                  now=1700000000.0, alg=_MAC)
        with self.assertRaises(rv.RevocationEntryUnverifiableError) as ctx:
            rl.verify({"i": key}, expect_alg=_ED)
        self.assertEqual(ctx.exception.code, "alg-mismatch")

    def test_import_expect_alg_mismatch_refused(self):
        key = _mac_key()
        rl = rv.RevocationList()
        entry = rl.revoke(_DIGEST_A, issuer_id="i", seed=key,
                          now=1700000000.0, alg=_MAC)
        fresh = rv.RevocationList()
        with self.assertRaises(rv.RevocationEntryUnverifiableError) as ctx:
            fresh.import_entries([entry], {"i": key}, expect_alg=_ED)
        self.assertEqual(ctx.exception.code, "alg-mismatch")

    def test_unknown_alg_revoke_refused(self):
        seed, _pub = _ed_keypair()
        rl = rv.RevocationList()
        with self.assertRaises(rv.RevocationError) as ctx:
            rl.revoke(_DIGEST_A, issuer_id="i", seed=seed,
                      now=1700000000.0, alg="rot13")
        self.assertEqual(ctx.exception.code, "alg-unregistered")

    def test_unknown_alg_import_refused(self):
        seed, pub = _ed_keypair()
        rl = rv.RevocationList()
        entry = rl.revoke(_DIGEST_A, issuer_id="i", seed=seed,
                          now=1700000000.0)
        forged = dict(entry, alg="rot13")
        fresh = rv.RevocationList()
        with self.assertRaises(rv.RevocationEntryUnverifiableError) as ctx:
            fresh.import_entries([forged], {"i": pub})
        self.assertEqual(ctx.exception.code, "alg-unregistered")


class AbsenceSignalCompositionTest(unittest.TestCase):
    def test_defaults_to_issuer_tier(self):
        key = _mac_key()
        issuer = ab.AbsenceIssuer("i", key, alg=_MAC)
        sig = po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                     now=1700000000.0)
        self.assertEqual(sig["alg"], _MAC)
        rec = po.verify_signal(sig, {"i": key}, expect_alg=_MAC)
        kinds = [p.get("kind") for p in rec["events"].values()]
        self.assertEqual(kinds, ["never-advertised"])

    def test_ed25519_issuer_composes_default(self):
        seed, pub = _ed_keypair()
        issuer = ab.AbsenceIssuer("i", seed)
        sig = po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                     now=1700000000.0)
        self.assertNotIn("alg", sig)
        po.verify_signal(sig, {"i": pub})

    def test_cross_tier_refused(self):
        seed, _pub = _ed_keypair()
        issuer = ab.AbsenceIssuer("i", seed)
        with self.assertRaises(po.PostureError) as ctx:
            po.emit_absence_signal(issuer, _DIGEST_A, "admission",
                                   now=1700000000.0, alg=_MAC)
        self.assertEqual(ctx.exception.code, "alg-mismatch")


class LegacyByteIdentityTest(unittest.TestCase):
    """The default tier is byte-identical to the pre-agility
    records: same inputs, same bytes, no "alg" field."""

    def test_posture_default_shape_unchanged(self):
        seed, pub = _ed_keypair()
        sig = po.emit_signal("revocation", _DIGEST_A, "permit", seed,
                             issuer_id="i", now=1700000000.0)
        self.assertEqual(set(sig),
                         {"v", "iss", "jti", "iat", "sub", "events",
                          "scope", "signature"})
        # And a fresh ed25519 signature is deterministic.
        sig2 = po.emit_signal("revocation", _DIGEST_A, "permit",
                              seed, issuer_id="i", now=1700000000.0)
        self.assertEqual(sig["signature"], sig2["signature"])
        po.verify_signal(sig2, {"i": pub})


if __name__ == "__main__":
    unittest.main()
