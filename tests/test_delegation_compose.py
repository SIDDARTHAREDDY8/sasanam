"""Wave-299 merge integration: the delegation composition seams.

Proves the three parallel receipt shapes compose through the merge-time
adapters (no hand-waving):

* ``gov/delegation.py`` is the canonical native receipt issuer.
* ``gov/delegation_revocation.py::DelegationRevoker.assert_live_native``
  composes native chain verification with revocation (revoking a native
  receipt id kills the chain, including descendants).
* ``gov/delegation_identity.py`` composes directly: ``verify_identity_evidence``
  takes the receipt digest + signer key explicitly, and
  ``export_native_chain`` / ``verify_native_chain_offline`` handle
  native receipt chains.
* ``gov/delegation_tickets.py::issue_ticket_on_receipt`` anchors a
  ticket on a native receipt (holder continuity across the seam), and
  ``present`` verifies the receipt-anchored chain.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_revocation as dr
from gov import delegation_identity as di
from gov import delegation_tickets as dt
from gov import ed25519


def _seed(n):
    return bytes([n]) * 32


def _pubkey(seed):
    return ed25519.publickey(seed).hex()


def _constraints(expires_at, max_depth=4):
    return {"expires_at": expires_at, "max_depth": max_depth,
            "allowed_targets": []}


class DelegationComposeTest(unittest.TestCase):
    def setUp(self):
        self.root_seed = _seed(1)
        self.child_seed = _seed(2)
        self.grandchild_seed = _seed(3)
        self.at = 1_700_000_000
        rights = ["tool.invoke", "memory.read"]
        self.root = dg.issue(
            self.root_seed, "root-agent", "child-agent",
            _pubkey(self.child_seed), rights,
            constraints=_constraints(self.at + 3600))
        self.child = dg.issue(
            self.child_seed, "child-agent", "grandchild-agent",
            _pubkey(self.grandchild_seed), ["tool.invoke"],
            parent=self.root,
            constraints=_constraints(self.at + 1800))
        self.chain = [self.root, self.child]
        self.roots = [_pubkey(self.root_seed)]

    # -- lane 2 native chain sanity ------------------------------------
    def test_native_chain_verifies(self):
        verdict = dg.verify_chain(self.child, self.chain, at=self.at,
                                  trust_roots=self.roots)
        self.assertTrue(verdict["verified"])
        self.assertEqual(verdict["leaf_receipt_id"],
                         self.child["receipt_id"])

    # -- lane 5: revocation of native receipts --------------------------
    def test_revoke_native_receipt_kills_chain(self):
        revoker = dr.DelegationRevoker(_seed(9), "root-agent")
        live = revoker.assert_live_native(self.chain, self.at, self.roots)
        self.assertEqual(live, self.child["receipt_id"])
        revoker.revoke(self.child["receipt_id"], self.at)
        with self.assertRaises(dr.RevocationError) as ctx:
            revoker.assert_live_native(self.chain, self.at, self.roots)
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_revoke_native_root_kills_descendant(self):
        revoker = dr.DelegationRevoker(_seed(9), "root-agent")
        revoker.revoke(self.root["receipt_id"], self.at)
        with self.assertRaises(dr.RevocationError) as ctx:
            revoker.assert_live_native(self.chain, self.at, self.roots)
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_revoke_unknown_receipt_id_is_noop_for_chain(self):
        revoker = dr.DelegationRevoker(_seed(9), "root-agent")
        revoker.revoke("ab" * 32, self.at)
        live = revoker.assert_live_native(self.chain, self.at, self.roots)
        self.assertEqual(live, self.child["receipt_id"])

    # -- lane 6: identity evidence on native receipts -------------------
    def _did_evidence(self, receipt, signer_seed):
        did = "did:sasanam:child"
        controller_seed = _seed(7)
        doc = di.issue_did_document(
            did, controller_seed, [_pubkey(signer_seed)], self.at)
        doc_digest = di.verify_did_document(doc)
        evidence = di.make_identity_evidence(
            "did", receipt["receipt_id"], did=did,
            did_document_digest=doc_digest, controller_seed=controller_seed)
        return evidence, {did: doc}

    def test_identity_evidence_on_native_receipt(self):
        evidence, docs = self._did_evidence(self.child, self.child_seed)
        record = di.verify_identity_evidence(
            evidence, self.child["receipt_id"],
            self.child["delegator_pubkey"], docs)
        self.assertTrue(record["verified"])
        self.assertEqual(record["authorization"], "capabilityDelegation")

    def test_identity_evidence_wrong_signer_refused(self):
        evidence, docs = self._did_evidence(self.child, self.child_seed)
        # The receipt was signed by child-agent's key; claim root's key.
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_identity_evidence(
                evidence, self.child["receipt_id"],
                _pubkey(self.root_seed), docs)
        self.assertEqual(ctx.exception.code,
                         "delegation-identity-unauthorized-key")

    def test_export_and_verify_native_chain_offline(self):
        evidence, docs = self._did_evidence(self.child, self.child_seed)
        entries = [
            {"receipt": self.root, "identity_evidence": None,
             "did_documents": {}},
            {"receipt": self.child, "identity_evidence": evidence,
             "did_documents": docs},
        ]
        chain_doc = di.export_native_chain(
            entries, _seed(11), self.at, self.at, self.roots)
        record = di.verify_native_chain_offline(
            chain_doc, self.at, docs, self.roots)
        self.assertTrue(record["verified"])
        self.assertEqual(record["leaf"], self.child["receipt_id"])
        self.assertTrue(record["offline"])

    def test_export_native_chain_with_revoked_receipt_still_exports(self):
        # Export is about identity evidence, not liveness; revocation is
        # checked separately via assert_live_native. A revoked receipt
        # still exports (the evidence is historical fact).
        entries = [{"receipt": self.root, "identity_evidence": None,
                    "did_documents": {}}]
        chain_doc = di.export_native_chain(
            entries, _seed(11), self.at, self.at, self.roots)
        self.assertEqual(chain_doc["schema"], "delegation-native-chain/v1")

    # -- lane 3: ticket anchored on a native receipt --------------------
    # (wave-301 F378: receipt-anchored ticket paths enforce revocation
    # liveness fail-closed, so every call below presents the anchor's
    # delegator's revoker -- child-agent's own list.)
    def _opt_ins(self, delegatee_seed, delegatee_id):
        reg = dt.OptInRegistry()
        opt_in = dt.declare_opt_in(delegatee_seed, delegatee_id, 3600,
                                   self.at)
        reg.register(opt_in, self.at)
        return reg

    def _revocation(self):
        return {"revoker": dr.DelegationRevoker(self.child_seed,
                                                "child-agent")}

    def test_ticket_on_receipt_roundtrip(self):
        reg = self._opt_ins(_seed(4), "ticket-holder")
        ticket, ticket_seed = dt.issue_ticket_on_receipt(
            self.child, self.chain, self.grandchild_seed, "ticket-holder",
            "tool.invoke", dt.FORWARDABLE, [], 900, reg, self.at,
            self.roots, revocation=self._revocation())
        self.assertEqual(ticket["parent_ticket_digest"],
                         self.child["receipt_id"])
        action_digest = "cd" * 32
        presented = dt.present(
            ticket, "ticket-holder", "tool.invoke", action_digest,
            self.at, ticket_store={},
            receipt_chain=self.chain, trust_roots=self.roots,
            revocation=self._revocation())
        self.assertEqual(presented["ticket_id"], ticket["ticket_id"])

    def test_ticket_on_receipt_requires_chain_at_present(self):
        reg = self._opt_ins(_seed(4), "ticket-holder")
        ticket, _ = dt.issue_ticket_on_receipt(
            self.child, self.chain, self.grandchild_seed, "ticket-holder",
            "tool.invoke", dt.FORWARDABLE, [], 900, reg, self.at,
            self.roots, revocation=self._revocation())
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.present(ticket, "ticket-holder", "tool.invoke", "cd" * 32,
                       self.at, ticket_store={})
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")

    def test_ticket_on_receipt_by_non_holder_refused(self):
        reg = self._opt_ins(_seed(4), "ticket-holder")
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_ticket_on_receipt(
                self.child, self.chain, _seed(5), "ticket-holder",
                "tool.invoke", dt.FORWARDABLE, [], 900, reg, self.at,
                self.roots, revocation=self._revocation())
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")

    def test_ticket_scope_escaping_receipt_rights_refused(self):
        reg = self._opt_ins(_seed(4), "ticket-holder")
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_ticket_on_receipt(
                self.child, self.chain, self.grandchild_seed, "ticket-holder",
                "subagent.spawn", dt.FORWARDABLE, [], 900, reg, self.at,
                self.roots, revocation=self._revocation())
        self.assertEqual(ctx.exception.code,
                         "delegation-ticket-type-violated")


if __name__ == "__main__":
    unittest.main()
