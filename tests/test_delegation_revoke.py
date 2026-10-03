"""Unit tests for gov/delegation_revocation.py (wave-299 lane 5).

Red-first: written against the new module; every coded refusal is
asserted by code.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation_revocation as dr
from gov import ed25519


def _seed(tag):
    return hashlib.sha256(b"w299-unit:" + tag.encode()).digest()


class _Harness:
    def __init__(self):
        self.seeds = {n: _seed("key-" + n) for n in ("root", "a", "b")}
        self.keyring = {n: ed25519.publickey(s).hex()
                        for n, s in self.seeds.items()}
        self.revoker = dr.DelegationRevoker(self.seeds["root"], "root")

    def receipt(self, delegator="root", delegate="a", parent=None, epoch=0,
                caps=("read",), nb=0, na=1000, seed=None):
        return dr.make_receipt(seed or self.seeds[delegator], delegator,
                               delegate, parent, epoch, list(caps), nb, na)

    def chain3(self):
        root = self.receipt()
        hop1 = self.receipt("a", "b", root["receipt_id"], epoch=1)
        hop2 = self.receipt("b", "c", hop1["receipt_id"], epoch=2)
        return [root, hop1, hop2]


class TestCodes(unittest.TestCase):
    def test_code_constants(self):
        self.assertEqual(dr.RV_REVOKED, "delegation-revoked")
        self.assertEqual(dr.RV_INVALID, "delegation-revocation-invalid")
        self.assertEqual(dr.RV_LIST_FULL, "delegation-revocation-list-full")

    def test_error_carries_code(self):
        with self.assertRaises(dr.RevocationError) as ctx:
            dr.DelegationRevoker(b"short", "root")
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")


class TestRevoke(unittest.TestCase):
    def setUp(self):
        self.h = _Harness()

    def test_revoke_record_shape(self):
        root = self.h.receipt()
        rec = self.h.revoker.revoke(root["receipt_id"], 100, target_epoch=0)
        self.assertEqual(rec["schema"], "delegation-revocation/v1")
        self.assertEqual(rec["delegator_id"], "root")
        self.assertEqual(rec["target_receipt_id"], root["receipt_id"])
        self.assertEqual(rec["target_epoch"], 0)
        self.assertEqual(rec["revoked_at"], 100)
        self.assertTrue(self.h.revoker.verify_revocation(rec))

    def test_revoke_idempotent(self):
        root = self.h.receipt()
        r1 = self.h.revoker.revoke(root["receipt_id"], 100)
        r2 = self.h.revoker.revoke(root["receipt_id"], 200)
        self.assertEqual(r1["revocation_id"], r2["revocation_id"])
        self.assertEqual(len(self.h.revoker), 1)

    def test_revoke_bad_target(self):
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.revoke("zz", 100)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_revoke_bad_instant(self):
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.revoke("00" * 32, -1)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_backwards_revoked_at(self):
        root = self.h.receipt()
        self.h.revoker.revoke(root["receipt_id"], 500)
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.revoke("11" * 32, 100)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_list_full(self):
        old = dr.MAX_REVOCATIONS
        dr.MAX_REVOCATIONS = 1
        try:
            self.h.revoker.revoke("00" * 32, 1)
            with self.assertRaises(dr.RevocationError) as ctx:
                self.h.revoker.revoke("11" * 32, 2)
            self.assertEqual(ctx.exception.code,
                             "delegation-revocation-list-full")
        finally:
            dr.MAX_REVOCATIONS = old

    def test_no_unrevoke_api(self):
        for name in ("rescind", "unrevoke", "remove", "retract"):
            self.assertFalse(hasattr(self.h.revoker, name),
                             "un-revoke API must not exist: %s" % name)

    def test_revoke_epoch(self):
        r = self.h.receipt(epoch=3)
        recs = self.h.revoker.revoke_epoch(3, [r["receipt_id"]], 700)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["target_epoch"], 3)


class TestIsLive(unittest.TestCase):
    def setUp(self):
        self.h = _Harness()

    def test_honest_chain_live(self):
        chain = self.h.chain3()
        self.assertEqual(self.h.revoker.is_live(chain, 500, self.h.keyring),
                         chain[-1]["receipt_id"])

    def test_direct_revocation(self):
        chain = self.h.chain3()
        self.h.revoker.revoke(chain[-1]["receipt_id"], 100, target_epoch=2)
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_ancestor_revocation_kills_descendants(self):
        chain = self.h.chain3()
        self.h.revoker.revoke(chain[0]["receipt_id"], 100, target_epoch=0)
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_revocation_beats_expiry(self):
        r = self.h.receipt(nb=0, na=10 ** 9)
        self.h.revoker.revoke(r["receipt_id"], 100)
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live([r], 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_expired(self):
        chain = self.h.chain3()
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 5000, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-expired")

    def test_broken_linkage(self):
        chain = self.h.chain3()
        chain[1] = dict(chain[1])
        chain[1]["parent_receipt_id"] = "ff" * 32
        # The body changed, so receipt_id no longer matches the body
        # digest -> invalid (the digest check precedes the linkage check).
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_forged_hop(self):
        # Linkage and digest hold; only the signature is wrong (signed
        # by a key that is not the delegator's).
        chain = self.h.chain3()
        evil_seed = _seed("evil-a")
        body = {k: chain[1][k] for k in dr._RECEIPT_UNSIGNED_FIELDS}
        bad = dict(chain[1])
        bad["signature"] = ed25519.sign(
            evil_seed, dr._canon(body)).hex()
        chain[1] = bad
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-signature-invalid")

    def test_tampered_receipt_id(self):
        chain = self.h.chain3()
        chain[0] = dict(chain[0])
        chain[0]["receipt_id"] = "ab" * 32
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live(chain, 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_empty_chain(self):
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.is_live([], 500, self.h.keyring)
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")


class TestOfflineVerify(unittest.TestCase):
    def setUp(self):
        self.h = _Harness()

    def test_export_verify_offline(self):
        chain = self.h.chain3()
        self.h.revoker.revoke(chain[0]["receipt_id"], 100, target_epoch=0)
        exported = self.h.revoker.export_list()
        fresh = dr.DelegationRevoker(_seed("other"), "root")
        self.assertTrue(fresh.verify_list(exported,
                                          pubkey_hex=self.h.keyring["root"]))

    def test_forged_revocation_rejected(self):
        chain = self.h.chain3()
        evil = dr.DelegationRevoker(_seed("evil"), "root")
        forged = evil.revoke(chain[0]["receipt_id"], 100)
        with self.assertRaises(dr.RevocationError) as ctx:
            self.h.revoker.verify_revocation(forged)
        self.assertEqual(ctx.exception.code, "delegation-signature-invalid")

    def test_unordered_list_rejected(self):
        r1 = self.h.receipt()
        rec1 = self.h.revoker.revoke(r1["receipt_id"], 100)
        r2 = self.h.receipt(delegate="q", epoch=1)
        rec2 = self.h.revoker.revoke(r2["receipt_id"], 200)
        fresh = dr.DelegationRevoker(_seed("other"), "root")
        with self.assertRaises(dr.RevocationError) as ctx:
            fresh.verify_list([rec2, rec1],
                              pubkey_hex=self.h.keyring["root"])
        self.assertEqual(ctx.exception.code, "delegation-revocation-invalid")

    def test_ed25519_contract(self):
        s = _seed("contract")
        pub = ed25519.publickey(s)
        sig = ed25519.sign(s, b"m")
        self.assertIs(ed25519.verify(pub, b"m", sig), True)
        self.assertIs(ed25519.verify(pub, b"x", sig), False)


if __name__ == "__main__":
    unittest.main()
