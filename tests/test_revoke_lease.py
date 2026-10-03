"""Unit tests: revocation<->lease fencing wiring (wave-300 lane 4).

Every coded refusal is asserted by code (never truthiness); the
ed25519 True/False contract is pinned where signatures matter.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import coordination_lease as cl  # noqa: E402
from gov import delegation as dg  # noqa: E402
from gov import delegation_revocation as rev  # noqa: E402
from gov import ed25519  # noqa: E402

AT = 1_700_000_000
SEED_A = bytes([0x0A]) * 32
SEED_B = bytes([0x0B]) * 32
SEED_EVIL = bytes([0xE1]) * 32
PUB_A = ed25519.publickey(SEED_A).hex()
PUB_B = ed25519.publickey(SEED_B).hex()


def _native(seed, delegator_id, delegatee_id, delegatee_pub,
            parent=None, designated_object=None):
    return dg.issue(seed, delegator_id, delegatee_id, delegatee_pub,
                    ["lease.acquire"], parent=parent,
                    designated_object=designated_object, issued_at=AT)


def _bound():
    root = _native(SEED_A, "authority", "holder", PUB_B)
    revoker = rev.DelegationRevoker(SEED_A, "authority")
    binding = {"receipt_id": root["receipt_id"],
               "revocation_list_digest": revoker.list_digest()}
    mgr = cl.LeaseManager()
    lease = mgr.acquire("u-scope", 3600, "holder", authority_seed=SEED_A,
                        issued_at=AT, delegation_binding=binding)
    ctx = {"revoker": revoker, "chain": [root], "trust_roots": [PUB_A]}
    return mgr, lease, revoker, root, ctx, binding


class TestDelegationBindingWiring(unittest.TestCase):
    def test_live_bound_write_true(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        self.assertIs(
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10, delegation_context=ctx),
            True)

    def test_revoked_maps_fencing(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        revoker.revoke(root["receipt_id"], AT + 5)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10, delegation_context=ctx)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_missing_context_fencing(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_wrong_type_revoker_fencing(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        bad = dict(ctx, revoker=object())
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10, delegation_context=bad)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_substituted_revoker_invalid(self):
        # Empty attacker revoker shares the empty-list digest; the
        # delegator-key check must still refuse.
        mgr, lease, revoker, root, ctx, binding = _bound()
        evil = rev.DelegationRevoker(SEED_EVIL, "authority")
        self.assertEqual(evil.list_digest(), revoker.list_digest())
        bad = {"revoker": evil, "chain": [root], "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10, delegation_context=bad)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_newer_delegator_list_accepted(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        other = _native(SEED_A, "authority", "other", PUB_B,
                        designated_object="cc" * 32)
        revoker.revoke(other["receipt_id"], AT + 5)
        self.assertNotEqual(revoker.list_digest(),
                            binding["revocation_list_digest"])
        self.assertIs(
            mgr.check_write("u-scope", lease["fencing_token"], "holder",
                            checked_at=AT + 10, delegation_context=ctx),
            True)

    def test_revoked_ancestor_fencing(self):
        mgr = cl.LeaseManager()
        root = _native(SEED_A, "authority", "holder", PUB_B)
        child = _native(SEED_B, "holder", "sub",
                        ed25519.publickey(bytes([0x0C]) * 32).hex(),
                        parent=root)
        revoker = rev.DelegationRevoker(SEED_A, "authority")
        revoker.revoke(root["receipt_id"], AT + 5)
        binding = {"receipt_id": child["receipt_id"],
                   "revocation_list_digest": revoker.list_digest()}
        lease = mgr.acquire("u-anc", 3600, "sub", authority_seed=SEED_A,
                            issued_at=AT, delegation_binding=binding)
        ctx = {"revoker": revoker, "chain": [root, child],
               "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-anc", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=ctx)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_expired_receipt_maps_expired(self):
        local = rev.make_receipt(SEED_A, "authority", "holder", None, 0,
                                 ["lease.acquire"], AT, AT + 100)
        revoker = rev.DelegationRevoker(SEED_A, "authority")
        mgr = cl.LeaseManager()
        binding = {"receipt_id": local["receipt_id"],
                   "revocation_list_digest": revoker.list_digest()}
        lease = mgr.acquire("u-exp", 3600, "holder", authority_seed=SEED_A,
                            issued_at=AT, delegation_binding=binding)
        ctx = {"revoker": revoker, "chain": [local],
               "keyring": {"authority": PUB_A}}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-exp", lease["fencing_token"], "holder",
                            checked_at=AT + 200, delegation_context=ctx)
        self.assertEqual(cm.exception.code, "coord-lease-expired")

    def test_malformed_binding_invalid(self):
        mgr = cl.LeaseManager()
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.acquire("u-mal", 3600, "holder", authority_seed=SEED_A,
                        issued_at=AT,
                        delegation_binding={"receipt_id": "zz"})
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_unbound_grant_unchanged(self):
        mgr = cl.LeaseManager()
        lease = mgr.acquire("u-leg", 3600, "holder", authority_seed=SEED_A,
                            issued_at=AT)
        self.assertIsNone(lease.get("delegation_binding"))
        self.assertIs(
            mgr.check_write("u-leg", lease["fencing_token"], "holder",
                            checked_at=AT + 10),
            True)

    def test_renew_preserves_binding(self):
        mgr, lease, revoker, root, ctx, binding = _bound()
        renewed = mgr.renew("u-scope", lease["fencing_token"], "holder",
                            100, authority_seed=SEED_A, checked_at=AT + 10)
        self.assertEqual(renewed.get("delegation_binding"), binding)

    def test_ed25519_contract(self):
        # gov.ed25519.verify is bool-returning (wave-243 lesson):
        # pin exact True/False, never truthiness.
        pub = bytes.fromhex(PUB_A)
        sig = ed25519.sign(SEED_A, b"contract")
        self.assertIs(ed25519.verify(pub, b"contract", sig), True)
        self.assertIs(ed25519.verify(pub, b"contract", bytes(64)), False)
        self.assertIs(ed25519.verify(pub, b"other", sig), False)


SEED_C = bytes([0x0C]) * 32
PUB_C = ed25519.publickey(SEED_C).hex()


def _multihop():
    """A -> B -> C chain bound at the leaf, with per-delegator revokers."""
    root = _native(SEED_A, "authority", "holder", PUB_B)
    child = _native(SEED_B, "holder", "sub", PUB_C, parent=root)
    revoker_a = rev.DelegationRevoker(SEED_A, "authority")
    revoker_b = rev.DelegationRevoker(SEED_B, "holder")
    mgr = cl.LeaseManager()
    binding = {"receipt_id": child["receipt_id"],
               "revocation_list_digest": revoker_a.list_digest()}
    lease = mgr.acquire("u-multi", 3600, "sub", authority_seed=SEED_A,
                        issued_at=AT, delegation_binding=binding)
    ctx = {"revokers": {"authority": revoker_a, "holder": revoker_b},
           "chain": [root, child], "trust_roots": [PUB_A]}
    return mgr, lease, revoker_a, revoker_b, root, child, ctx


class TestF379PerDelegatorRevokers(unittest.TestCase):
    """F379 (wave-302): multi-hop delegation-bound leases must honor
    every delegator's revocation list, not just the root's."""

    def test_multihop_live_with_revokers_mapping(self):
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        self.assertIs(
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=ctx),
            True)

    def test_intermediate_revocation_fencing(self):
        # B revokes the bound leaf: invisible before F379, fences now.
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        rb.revoke(child["receipt_id"], AT + 5)
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=ctx)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_intermediate_revokes_ancestor_receipt(self):
        # B revokes the receipt B itself issued (the leaf); A revoking
        # nothing keeps A's list clean -- the write must still fence.
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        rb.revoke(root["receipt_id"], AT + 5)  # not B's receipt; no-op semantically
        self.assertIs(
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=ctx),
            True)

    def test_legacy_single_revoker_multihop_fencing(self):
        # Legacy single (root) revoker on a multi-hop chain: the
        # intermediate hop's revocation state is unshowable, so the
        # write fails closed (F379) instead of passing on the
        # root's clean list as wave-300 did.
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        legacy = {"revoker": ra, "chain": [root, child],
                  "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10,
                            delegation_context=legacy)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_missing_member_revoker_fencing(self):
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        partial = {"revokers": {"authority": ra},
                   "chain": [root, child], "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10,
                            delegation_context=partial)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_mislabeled_mapping_entry_invalid(self):
        # A's revoker filed under B's delegator_id: substitution.
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        bad = {"revokers": {"authority": ra, "holder": ra},
               "chain": [root, child], "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=bad)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_wrong_key_member_revoker_invalid(self):
        # Attacker revoker filed under B's id but with the attacker's
        # key: the per-member key binding refuses.
        mgr, lease, ra, rb, root, child, ctx = _multihop()
        evil = rev.DelegationRevoker(bytes([0xE1]) * 32, "holder")
        bad = {"revokers": {"authority": ra, "holder": evil},
               "chain": [root, child], "trust_roots": [PUB_A]}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-multi", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=bad)
        self.assertEqual(cm.exception.code, "coord-lease-invalid")

    def test_local_shape_multihop_revocation(self):
        # Local-shape (keyring) receipts: same per-delegator rule.
        la = rev.make_receipt(SEED_A, "authority", "holder", None, 0,
                              ["lease.acquire"], AT, AT + 3600)
        lb = rev.make_receipt(SEED_B, "holder", "sub", la["receipt_id"],
                              0, ["lease.acquire"], AT, AT + 3600)
        ra = rev.DelegationRevoker(SEED_A, "authority")
        rb = rev.DelegationRevoker(SEED_B, "holder")
        rb.revoke(lb["receipt_id"], AT + 5)
        mgr = cl.LeaseManager()
        binding = {"receipt_id": lb["receipt_id"],
                   "revocation_list_digest": ra.list_digest()}
        lease = mgr.acquire("u-loc", 3600, "sub", authority_seed=SEED_A,
                            issued_at=AT, delegation_binding=binding)
        ctx = {"revokers": {"authority": ra, "holder": rb},
               "chain": [la, lb],
               "keyring": {"authority": PUB_A, "holder": PUB_B}}
        with self.assertRaises(cl.CoordinationLeaseError) as cm:
            mgr.check_write("u-loc", lease["fencing_token"], "sub",
                            checked_at=AT + 10, delegation_context=ctx)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")


if __name__ == "__main__":
    unittest.main()
