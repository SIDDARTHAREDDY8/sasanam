#!/usr/bin/env python3
"""Unit tests for gov/attenuation.py (wave-223 lane B).

Independent spec-vector literals; public seams only. All clocks are
fixed, all keys are fixed seeds.
"""

import unittest

from gov import attenuation as at
from gov import ed25519 as _ed
from gov import permit_leases as pl

# Fixed 32-byte seeds (never reused as credentials; test-local).
_SEED_A = bytes(range(32))
_SEED_B = bytes([255 - i for i in range(32)])

_DIGEST_A = "aa" * 32
_DIGEST_B = "bb" * 32

_GRANT = {"action": {"read", "write"}, "resource": {"toolbox"}}

# Spec vectors: issue(lease_digest, narrowed_scope, requester_id, seed,
# ttl_s, now) must produce exactly these field values (signature binds
# the body deterministically via RFC 8032).
_VEC_NOW = 1700000000.0
_VEC_TTL = 300


def _lease(now=_VEC_NOW):
    return pl.PermitLease.issue(
        "permit-1", params_digest=_DIGEST_A, grant_scope=_GRANT,
        ttl_s=3600, now=lambda: float(now))


def _block(now=_VEC_NOW, ttl=_VEC_TTL, narrowed=None, seed=_SEED_A,
           requester_id="req-1", digest=_DIGEST_A):
    return at.issue(digest, {"action": {"read"}} if narrowed is None
                    else narrowed, requester_id, seed, ttl_s=ttl, now=now)


class TestAttenuationIssue(unittest.TestCase):

    def test_block_fields(self):
        block = _block()
        self.assertEqual(block["v"], 1)
        self.assertEqual(block["lease_digest"], _DIGEST_A)
        self.assertEqual(block["narrowed_scope"], {"action": ["read"]})
        self.assertEqual(block["issued_at"], _VEC_NOW)
        self.assertEqual(block["expires_at"], _VEC_NOW + _VEC_TTL)
        self.assertEqual(block["requester_id"], "req-1")
        self.assertEqual(block["requester_pubkey"],
                         _ed.publickey(_SEED_A).hex())
        self.assertEqual(len(bytes.fromhex(block["requester_signature"])), 64)

    def test_ttl_over_600_refused_at_issuance(self):
        with self.assertRaises(at.AttenuationError) as ctx:
            _block(ttl=601)
        self.assertEqual(ctx.exception.code, "attenuation-ttl-refused")

    def test_ttl_exactly_600_accepted(self):
        block = _block(ttl=600)
        self.assertEqual(block["expires_at"], _VEC_NOW + 600)

    def test_ttl_nonpositive_refused(self):
        with self.assertRaises(at.AttenuationError) as ctx:
            _block(ttl=0)
        self.assertEqual(ctx.exception.code, "attenuation-ttl-refused")

    def test_malformed_narrowed_scope_refused(self):
        with self.assertRaises(at.AttenuationError) as ctx:
            at.issue(_DIGEST_A, {"action": [123]}, "req-1", _SEED_A,
                     ttl_s=300, now=_VEC_NOW)
        self.assertEqual(ctx.exception.code, "attenuation-widening-refused")


class TestAttenuationBind(unittest.TestCase):

    def test_valid_bind_returns_narrowed_scope(self):
        lease = _lease()
        narrowed = at.bind(_block(), lease, now=_VEC_NOW + 10)
        self.assertEqual(narrowed, {"action": frozenset({"read"})})

    def test_forged_body_refused(self):
        lease = _lease()
        forged = dict(_block())
        forged["narrowed_scope"] = {"action": ["read", "write"]}
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(forged, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-unverifiable")

    def test_wrong_key_refused(self):
        lease = _lease()
        block = _block()
        wrong_pub = _ed.publickey(_SEED_B).hex()
        tampered = dict(block)
        tampered["requester_pubkey"] = wrong_pub
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(tampered, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-unverifiable")

    def test_wrong_lease_refused(self):
        lease = _lease()
        block = _block(digest=_DIGEST_B)
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(block, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-lease-mismatch")

    def test_expired_refused(self):
        lease = _lease()
        block = _block()
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(block, lease, now=_VEC_NOW + _VEC_TTL)
        self.assertEqual(ctx.exception.code, "attenuation-expired")

    def test_widened_scope_refused(self):
        lease = _lease()
        block = _block(narrowed={"action": {"read", "write", "admin"}})
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(block, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-widening-refused")

    def test_unknown_dimension_refused(self):
        lease = _lease()
        block = _block(narrowed={"action": {"read"}, "zone": {"x"}})
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(block, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-widening-refused")

    def test_missing_field_refused(self):
        lease = _lease()
        block = dict(_block())
        del block["requester_signature"]
        with self.assertRaises(at.AttenuationError) as ctx:
            at.bind(block, lease, now=_VEC_NOW + 10)
        self.assertEqual(ctx.exception.code, "attenuation-unverifiable")


class TestAttenuationRedeemWiring(unittest.TestCase):

    def test_redeem_with_block(self):
        lease = _lease()
        block = _block()
        grant = lease.redeem(_DIGEST_A,
                             request_scope={"action": {"read"}},
                             now=lambda: _VEC_NOW + 10,
                             attenuation=block)
        self.assertIn("attenuation", grant)
        self.assertEqual(grant["attenuation"]["requester_id"], "req-1")

    def test_missing_block_required_refused(self):
        lease = _lease()
        with self.assertRaises(at.AttenuationError) as ctx:
            lease.redeem(_DIGEST_A, now=lambda: _VEC_NOW + 10,
                         attenuation=None, require_attenuation=True)
        self.assertEqual(ctx.exception.code, "attenuation-missing")

    def test_legacy_grant_shape_byte_identical(self):
        lease = _lease()
        grant = lease.redeem(_DIGEST_A, now=lambda: _VEC_NOW + 10)
        self.assertEqual(set(grant),
                         {"permit_id", "parameter_digest", "granted_at"})

    def test_registry_passthrough(self):
        events = []
        reg = pl.PermitRegistry(audit=events.append,
                                now=lambda: _VEC_NOW)
        lease = reg.issue("p1", params_digest=_DIGEST_A,
                          grant_scope=_GRANT)
        block = at.issue(_DIGEST_A, {"action": {"read"}}, "req-1",
                         _SEED_A, ttl_s=300, now=_VEC_NOW)
        grant = reg.redeem("p1", _DIGEST_A,
                           request_scope={"action": {"read"}},
                           attenuation=block)
        self.assertIn("attenuation", grant)
        with self.assertRaises(pl.PermitError) as ctx:
            reg.redeem("p1", _DIGEST_A, attenuation=block)
        self.assertEqual(ctx.exception.code, "permit-reused")

    def test_used_lease_with_valid_block_refused(self):
        lease = _lease()
        block = _block()
        lease.redeem(_DIGEST_A, now=lambda: _VEC_NOW + 10,
                     attenuation=block)
        block2 = _block(now=_VEC_NOW + 20)
        with self.assertRaises(pl.PermitError) as ctx:
            lease.redeem(_DIGEST_A, now=lambda: _VEC_NOW + 30,
                         attenuation=block2)
        self.assertEqual(ctx.exception.code, "permit-reused")


if __name__ == "__main__":
    unittest.main()
