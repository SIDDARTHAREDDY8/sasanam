"""Unit tests for gov/delegation.py: contract pins for delegation receipts.

Every coded refusal is asserted by code (F351 contract); the
ed25519 True/False contract is pinned (wave-243); receipts and
escrow records are frozen.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import ed25519


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()


class DelegationContractTest(unittest.TestCase):
    def setUp(self):
        self.seed_a = _seed("lane2-a")
        self.seed_b = _seed("lane2-b")
        self.seed_c = _seed("lane2-c")
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.at = 1_700_000_000
        self.cons = {"expires_at": self.at + 3600, "max_depth": 4}

    def _root(self, rights=("tool.invoke",), **kw):
        kw.setdefault("constraints", dict(self.cons))
        return dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                        rights, issued_at=self.at, **kw)

    def _code_of(self, fn, *args, **kwargs):
        with self.assertRaises(dg.DelegationError) as ctx:
            fn(*args, **kwargs)
        return ctx.exception.code

    # -- construction --------------------------------------------------------

    def test_root_receipt_shape(self):
        r = self._root()
        self.assertEqual(r["schema"], "delegation-receipt/v1")
        self.assertIsNone(r["parent_receipt_id"])
        self.assertEqual(r["depth"], 0)
        self.assertEqual(len(r["receipt_id"]), 64)
        self.assertEqual(len(r["signature"]), 128)

    def test_receipt_id_binds_body(self):
        r = self._root()
        body = {k: r[k] for k in dg._UNSIGNED_FIELDS if k != "receipt_id"}
        self.assertEqual(r["receipt_id"],
                         hashlib.sha256(dg._canonical(body)).hexdigest())

    def test_signature_verifies_with_is_true(self):
        r = self._root()
        body = dg._canonical({k: r[k] for k in dg._UNSIGNED_FIELDS})
        self.assertIs(
            ed25519.verify(bytes.fromhex(r["delegator_pubkey"]), body,
                           bytes.fromhex(r["signature"])),
            True)

    def test_empty_rights_refused(self):
        self.assertEqual(
            self._code_of(dg.issue, self.seed_a, "agent-a", "agent-b",
                          self.pub_b, (),
                          constraints=dict(self.cons), issued_at=self.at),
            "delegation-invalid")

    def test_max_depth_bound(self):
        bad = dict(self.cons, max_depth=17)
        self.assertEqual(
            self._code_of(dg.issue, self.seed_a, "agent-a", "agent-b",
                          self.pub_b, ("tool.invoke",), constraints=bad,
                          issued_at=self.at),
            "delegation-invalid")

    # -- narrowing / widening --------------------------------------------------

    def test_downstream_subset_ok(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("memory.read",), parent=root,
                       constraints=dict(self.cons), issued_at=self.at)
        self.assertEqual(mid["depth"], 1)
        self.assertEqual(mid["parent_receipt_id"], root["receipt_id"])

    def test_widened_refused_coded(self):
        root = self._root(rights=("memory.read",))
        self.assertEqual(
            self._code_of(dg.issue, self.seed_b, "agent-b", "agent-c",
                          self.pub_c, ("memory.read", "tool.invoke"),
                          parent=root, constraints=dict(self.cons),
                          issued_at=self.at),
            "delegation-widened")

    def test_attenuation_digest_binds_parent_rights(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke",), parent=root,
                       constraints=dict(self.cons), issued_at=self.at)
        expected = hashlib.sha256(
            dg._canonical(sorted(root["rights"]))).hexdigest()
        self.assertEqual(mid["attenuation_digest"], expected)

    # -- chain verification -----------------------------------------------------

    def test_verify_chain_ok(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke",), parent=root,
                       constraints=dict(self.cons), issued_at=self.at)
        v = dg.verify_chain(mid, [root, mid], at=self.at,
                            trust_roots=[self.pub_a])
        self.assertTrue(v["verified"])

    def test_tampered_parent_link_refused(self):
        root = self._root()
        evil = dict(root)
        evil["delegatee_id"] = "agent-evil"
        self.assertEqual(
            self._code_of(dg.verify_chain, evil, [evil], at=self.at,
                          trust_roots=[self.pub_a]),
            "delegation-chain-broken")

    def test_holder_continuity_enforced(self):
        root = self._root(rights=("tool.invoke",))
        # signed by agent-c's key but claims agent-b as delegator: the
        # signing key is not the parent's designated delegatee key, so
        # key continuity (not label continuity) refuses coded.
        self.assertEqual(
            self._code_of(dg.issue, self.seed_c, "agent-b", "agent-c",
                          self.pub_c, ("tool.invoke",), parent=root,
                          constraints=dict(self.cons), issued_at=self.at),
            "delegation-chain-broken")

    def test_label_key_mismatch_refused_at_verify(self):
        # A hand-built chain whose labels match but whose keys do not
        # must not verify: confused-deputy resistance by construction.
        root = self._root(rights=("tool.invoke",))
        mid = dg.issue(self.seed_b, "agent-b", "agent-c", self.pub_c,
                       ("tool.invoke",), parent=root,
                       constraints=dict(self.cons), issued_at=self.at)
        forged = dict(mid)
        forged["delegator_pubkey"] = self.pub_a  # wrong key for this link
        self.assertEqual(
            self._code_of(dg.verify_chain, forged, [root, forged],
                          at=self.at, trust_roots=[self.pub_a]),
            "delegation-chain-broken")

    # -- escrow -----------------------------------------------------------------

    def test_escrow_lifecycle(self):
        effect = hashlib.sha256(b"e1").hexdigest()
        esc = dg.escrow_begin(
            [{"step_id": "s1", "expected_effect_digest": effect}],
            self.seed_a, "agent-a", at=self.at)
        self.assertEqual(esc["state"], "open")
        r = dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                     ("escrow.commit",), designated_object=effect,
                     constraints=dict(self.cons), issued_at=self.at)
        done = dg.escrow_commit(esc, {"s1": [r]}, at=self.at,
                                trust_roots=[self.pub_a])
        self.assertEqual(done["state"], "committed")
        aborted = dg.escrow_abort(esc)
        self.assertEqual(aborted["state"], "aborted")

    def test_escrow_duplicate_step_ids_refused(self):
        effect = hashlib.sha256(b"e1").hexdigest()
        self.assertEqual(
            self._code_of(
                dg.escrow_begin,
                [{"step_id": "s1", "expected_effect_digest": effect},
                 {"step_id": "s1", "expected_effect_digest": effect}],
                self.seed_a, "agent-a", at=self.at),
            "delegation-escrow-violated")


if __name__ == "__main__":
    unittest.main(verbosity=1)
