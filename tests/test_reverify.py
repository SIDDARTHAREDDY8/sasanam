#!/usr/bin/env python3
"""Unit tests for gov/reverify.py and the permit-leases redeem wiring.

Independent spec-vector literals (no recomputation of the
implementation's own internals): fixed seeds, fixed clocks, fixed
digests. Public seams only.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import absence as _ab  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import permit_leases as _pl  # noqa: E402
from gov import posture as _po  # noqa: E402
from gov import revocation as _rv  # noqa: E402
from gov import reverify as _rvf  # noqa: E402

# Fixed test fixtures: a 32-byte seed, its real public key, a wrong
# key, fixed digests, one fixed timestamp.
_SEED = bytes(range(32))
_PUB = _ed.publickey(_SEED)
_WRONG_PUB = _ed.publickey(bytes(32 - i for i in range(32)))
_NOW = 1780000000.0
_DIGEST = "a" * 64


def _signal(seed=_SEED, now=_NOW):
    return _po.emit_signal("permit-refusal", _DIGEST, "scope:unit",
                           seed, issuer_id="unit-iss",
                           kind="permit-revoked", now=now)


def _envelope(parent, kind="posture-signal", pubkeys=None,
              digest=None, expires=None, last_verified=None):
    return {"v": 1,
            "parent_kind": kind,
            "parent": parent,
            "parent_pubkeys": {"unit-iss": _PUB}
            if pubkeys is None else pubkeys,
            "parent_digest": _DIGEST if digest is None else digest,
            "parent_expires_at": expires,
            "last_verified_at": last_verified}


def _verifier(**kw):
    kw.setdefault("now", lambda: _NOW)
    return _rvf.UseTimeVerifier(**kw)


class TestUseTimeVerifier(unittest.TestCase):
    def test_valid_parent_verifies_and_receipt_fields(self):
        sig = _signal()
        receipt = _verifier().verify_at_use(_envelope(sig))
        self.assertEqual(set(receipt),
                         {"v", "record_digest", "parent_digest",
                          "verified_at", "outcome"})
        self.assertEqual(receipt["parent_digest"], _DIGEST)
        self.assertEqual(receipt["outcome"], "verified")
        self.assertEqual(receipt["verified_at"], _NOW)
        self.assertTrue(receipt["record_digest"].startswith("sha256:"))

    def test_deterministic_receipt(self):
        sig = _signal()
        r1 = _verifier().verify_at_use(_envelope(sig))
        r2 = _verifier().verify_at_use(_envelope(sig))
        self.assertEqual(r1, r2)

    def test_tampered_parent_refused(self):
        sig = _signal()
        sig["sub"] = "f" * 64
        with self.assertRaises(
                _rvf.ReverifyParentSignatureInvalidError) as ctx:
            _verifier().verify_at_use(_envelope(sig))
        self.assertEqual(ctx.exception.code,
                         "reverify-parent-signature-invalid")

    def test_forged_key_refused(self):
        sig = _signal()
        env = _envelope(sig, pubkeys={"unit-iss": _WRONG_PUB})
        with self.assertRaises(_rvf.ReverifyParentSignatureInvalidError):
            _verifier().verify_at_use(env)

    def test_revoked_parent_refused(self):
        sig = _signal()
        rlist = _rv.RevocationList()
        rlist.revoke(_DIGEST, issuer_id="rev-iss", seed=_SEED,
                     now=_NOW)
        with self.assertRaises(_rvf.ReverifyRevokedError) as ctx:
            _verifier(revocation_registry=rlist).verify_at_use(
                _envelope(sig))
        self.assertEqual(ctx.exception.code, "reverify-revoked")

    def test_no_registry_no_check(self):
        # A revoked digest elsewhere: without an attached registry the
        # check is skipped, not invented.
        sig = _signal()
        _rv.RevocationList().revoke(_DIGEST, issuer_id="rev-iss",
                                    seed=_SEED, now=_NOW)
        receipt = _verifier().verify_at_use(_envelope(sig))
        self.assertEqual(receipt["outcome"], "verified")

    def test_expired_parent_refused(self):
        sig = _signal()
        env = _envelope(sig, expires=_NOW - 1)
        with self.assertRaises(_rvf.ReverifyStaleError) as ctx:
            _verifier().verify_at_use(env)
        self.assertEqual(ctx.exception.code, "reverify-stale")

    def test_stale_cached_verification_refused(self):
        sig = _signal()
        old = _envelope(sig, last_verified=_NOW - 301)
        with self.assertRaises(_rvf.ReverifyStaleError):
            _verifier().verify_at_use(old)
        fresh = _envelope(sig, last_verified=_NOW - 299)
        receipt = _verifier().verify_at_use(fresh)
        self.assertEqual(receipt["outcome"], "verified")

    def test_custom_max_age(self):
        sig = _signal()
        env = _envelope(sig, last_verified=_NOW - 61)
        with self.assertRaises(_rvf.ReverifyStaleError):
            _verifier(max_verification_age=60).verify_at_use(env)
        receipt = _verifier(max_verification_age=62).verify_at_use(env)
        self.assertEqual(receipt["outcome"], "verified")

    def test_unknown_parent_kind_refused(self):
        sig = _signal()
        env = _envelope(sig, kind="quantum-signal")
        with self.assertRaises(
                _rvf.ReverifyUnknownParentKindError) as ctx:
            _verifier().verify_at_use(env)
        self.assertEqual(ctx.exception.code,
                         "reverify-unknown-parent-kind")

    def test_malformed_envelope_refused(self):
        with self.assertRaises(_rvf.ReverifyMalformedError):
            _verifier().verify_at_use({"v": 1})
        with self.assertRaises(_rvf.ReverifyMalformedError):
            _verifier().verify_at_use("not-a-record")
        with self.assertRaises(_rvf.ReverifyMalformedError):
            _verifier().verify_at_use(_envelope(_signal(),
                                                pubkeys={}))

    def test_absence_parent_kind(self):
        issuer = _ab.AbsenceIssuer("unit-abs", _SEED)
        neg = issuer.attest_absence("b" * 64, now=_NOW)
        pub = _ed.publickey(_SEED)
        env = _envelope(neg, kind="absence-negative",
                        pubkeys={"unit-abs": pub}, digest="b" * 64)
        receipt = _verifier().verify_at_use(env)
        self.assertEqual(receipt["outcome"], "verified")

    def test_revocation_entry_parent_kind(self):
        rlist = _rv.RevocationList()
        entry = rlist.revoke("c" * 64, issuer_id="rev-iss",
                             seed=_SEED, now=_NOW)
        env = _envelope(entry, kind="revocation-entry",
                        pubkeys={"rev-iss": _PUB}, digest="c" * 64)
        receipt = _verifier().verify_at_use(env)
        self.assertEqual(receipt["outcome"], "verified")

    def test_unknown_alg_fails_closed(self):
        sig = _signal()
        sig["alg"] = "pq-hybrid-magic"
        with self.assertRaises(
                _rvf.ReverifyParentSignatureInvalidError):
            _verifier().verify_at_use(_envelope(sig))

    def test_expect_alg_pin(self):
        sig = _signal()
        receipt = _verifier().verify_at_use(
            _envelope(sig), expect_alg="ed25519-rfc8032")
        self.assertEqual(receipt["outcome"], "verified")
        with self.assertRaises(
                _rvf.ReverifyParentSignatureInvalidError):
            _verifier().verify_at_use(
                _envelope(sig), expect_alg="hmac-sha256-mac")

    def test_audit_trail(self):
        events = []
        sig = _signal()
        _verifier(audit=events.append).verify_at_use(_envelope(sig))
        self.assertEqual(events[-1]["event"], "reverify_verified")
        bad = _envelope(sig, kind="quantum-signal")
        with self.assertRaises(_rvf.ReverifyUnknownParentKindError):
            _verifier(audit=events.append).verify_at_use(bad)
        self.assertEqual(events[-1]["event"], "reverify_refused")
        self.assertEqual(events[-1]["code"],
                         "reverify-unknown-parent-kind")

    def test_receipt_carries_no_authority(self):
        receipt = _verifier().verify_at_use(_envelope(_signal()))
        with self.assertRaises(
                _rvf.ReverifyNotAuthorizationError) as ctx:
            _rvf.reverify_receipt_carries_no_authority(receipt)
        self.assertEqual(ctx.exception.code,
                         "reverify-not-authorization")
        # Non-receipt records pass through.
        self.assertTrue(
            _rvf.reverify_receipt_carries_no_authority({"a": 1}))

    def test_register_parent_kind(self):
        verifier = _verifier()
        verifier.register_parent_kind(
            "custom", lambda rec, keys, alg: rec)
        sig = _signal()
        receipt = verifier.verify_at_use(_envelope(sig, kind="custom",
                                                   pubkeys={"x": b"k"}))
        self.assertEqual(receipt["outcome"], "verified")
        with self.assertRaises(ValueError):
            verifier.register_parent_kind("custom",
                                           lambda r, k, a: r)


class TestRedeemReverifyWiring(unittest.TestCase):
    def _mint(self):
        reg = _pl.PermitRegistry(now=lambda: _NOW)
        digest = _pl.parameter_digest({"op": "read"})
        lease = reg.issue("permit-unit", params_digest=digest,
                          grant_scope={"action": {"read"}},
                          ttl_s=600)
        return reg, lease, digest

    def test_missing_verifier_refused(self):
        _reg, lease, digest = self._mint()
        with self.assertRaises(_rvf.ReverifyRequiredError) as ctx:
            lease.redeem(digest, now=lambda: _NOW,
                         reverify_at_use=True)
        self.assertEqual(ctx.exception.code, "reverify-required")
        self.assertFalse(lease.used)  # refused redeem never consumes

    def test_stale_record_refused(self):
        _reg, lease, digest = self._mint()
        stale = _envelope(_signal(), expires=_NOW - 1)
        with self.assertRaises(_rvf.ReverifyRequiredError):
            lease.redeem(digest, now=lambda: _NOW,
                         reverify_at_use=True,
                         use_verifier=_verifier(),
                         use_record=stale)

    def test_fresh_record_redeems(self):
        _reg, lease, digest = self._mint()
        env = _envelope(_signal())
        grant = lease.redeem(digest, now=lambda: _NOW,
                             reverify_at_use=True,
                             use_verifier=_verifier(),
                             use_record=env)
        self.assertEqual(grant["permit_id"], "permit-unit")
        self.assertTrue(lease.used)

    def test_default_off_legacy_identical(self):
        reg, lease, digest = self._mint()
        grant = lease.redeem(digest, now=lambda: _NOW)
        self.assertEqual(set(grant),
                         {"permit_id", "parameter_digest",
                          "granted_at"})

    def test_registry_passthrough(self):
        reg, lease, digest = self._mint()
        env = _envelope(_signal())
        grant = reg.redeem("permit-unit", digest,
                           reverify_at_use=True,
                           use_verifier=_verifier(),
                           use_record=env)
        self.assertEqual(grant["permit_id"], "permit-unit")


if __name__ == "__main__":
    unittest.main()
