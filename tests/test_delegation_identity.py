"""Unit tests for gov/delegation_identity.py (wave-299 lane 6).

Every coded refusal is asserted by machine code (F351 contract);
ed25519 verify contract pinned with `is True` / `is False`.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import delegation_identity as di
from gov import ed25519


def _seed(b):
    return bytes([b]) * 32


def _pub(seed):
    return ed25519.publickey(seed).hex()


class TestDidDocuments(unittest.TestCase):
    def test_issue_and_verify(self):
        doc = di.issue_did_document("did:sasanam:alice", _seed(1),
                                    [_pub(_seed(2))], created_at=100)
        digest = di.verify_did_document(doc)
        self.assertEqual(digest, di.did_document_digest(doc))

    def test_tampered_delegation_keys_fail(self):
        doc = di.issue_did_document("did:sasanam:alice", _seed(1),
                                    [_pub(_seed(2))], created_at=100)
        doc["delegation_keys"] = [_pub(_seed(3))]
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_did_document(doc)
        self.assertEqual(ctx.exception.code, "delegation-identity-invalid")

    def test_bad_did_shape(self):
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.issue_did_document("not-a-did", _seed(1), [_pub(_seed(2))],
                                  created_at=100)
        self.assertEqual(ctx.exception.code, "delegation-identity-invalid")


class TestIdentityEvidence(unittest.TestCase):
    def setUp(self):
        self.ctrl = _seed(11)
        self.signer = _seed(12)
        self.doc = di.issue_did_document(
            "did:sasanam:bob", self.ctrl, [_pub(self.signer)],
            created_at=100)

    def test_did_evidence_happy_path(self):
        receipt = di.make_receipt("bob", "carol", "ab" * 32, self.signer,
                                  100, 200)
        evidence = di.make_identity_evidence(
            "did", receipt["receipt_id"], did="did:sasanam:bob",
            did_document_digest=di.did_document_digest(self.doc),
            controller_seed=self.ctrl)
        rec = di.verify_identity_evidence(
            evidence, receipt["receipt_id"], _pub(self.signer),
            {"did:sasanam:bob": self.doc})
        self.assertTrue(rec["verified"])
        self.assertEqual(rec["authorization"], "capabilityDelegation")

    def test_rogue_signer_refused_coded(self):
        rogue = _seed(13)
        receipt = di.make_receipt("bob", "carol", "ab" * 32, rogue,
                                  100, 200)
        evidence = di.make_identity_evidence(
            "did", receipt["receipt_id"], did="did:sasanam:bob",
            did_document_digest=di.did_document_digest(self.doc),
            controller_seed=self.ctrl)
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_identity_evidence(
                evidence, receipt["receipt_id"], _pub(rogue),
                {"did:sasanam:bob": self.doc})
        self.assertEqual(ctx.exception.code,
                         "delegation-identity-unauthorized-key")

    def test_untrusted_did_refused(self):
        receipt = di.make_receipt("bob", "carol", "ab" * 32, self.signer,
                                  100, 200)
        evidence = di.make_identity_evidence(
            "did", receipt["receipt_id"], did="did:sasanam:bob",
            did_document_digest=di.did_document_digest(self.doc),
            controller_seed=self.ctrl)
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_identity_evidence(evidence, receipt["receipt_id"],
                                        _pub(self.signer), {})
        self.assertEqual(ctx.exception.code,
                         "delegation-identity-unauthorized-key")

    def test_hardware_claim_without_quote_refused(self):
        transcript = di.make_ceremony_transcript(
            "dave", self.signer, 100, "software-ceremony",
            [("witness-a", _seed(14))])
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.make_identity_evidence(
                "attestation", "ab" * 32,
                ceremony_transcript=transcript, claim_hardware=True,
                quote_bytes=None)
        self.assertEqual(ctx.exception.code,
                         "delegation-identity-false-hardware-claim")

    def test_attestation_transcript_not_about_signer(self):
        other = _seed(15)
        transcript = di.make_ceremony_transcript(
            "dave", other, 100, "software-ceremony",
            [("witness-a", _seed(14))])
        evidence = di.make_identity_evidence(
            "attestation", "ab" * 32, ceremony_transcript=transcript,
            claim_hardware=False)
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_identity_evidence(evidence, "ab" * 32,
                                        _pub(self.signer), {})
        self.assertEqual(ctx.exception.code,
                         "delegation-identity-unauthorized-key")

    def test_unknown_method(self):
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.make_identity_evidence("telepathy", "ab" * 32)
        self.assertEqual(ctx.exception.code, "delegation-identity-invalid")


class TestChainExport(unittest.TestCase):
    def test_export_and_offline_verify(self):
        s1, s2, exporter = _seed(21), _seed(22), _seed(23)
        r1 = di.make_receipt("erin", "frank", "aa" * 32, s1, 100, 500)
        r2 = di.make_receipt("frank", "grace", "bb" * 32, s2, 150, 500,
                             parent_digest=r1["receipt_id"])
        chain = di.export_chain([
            {"receipt": r1, "from_pubkey": _pub(s1)},
            {"receipt": r2, "from_pubkey": _pub(s2)},
        ], exporter, 200)
        rec = di.verify_chain_offline(chain, 300, {})
        self.assertTrue(rec["verified"])
        self.assertTrue(rec["offline"])
        self.assertEqual(rec["depth"], 2)
        self.assertEqual(rec["leaf"], "grace")

    def test_tampered_link_signature_refused(self):
        s1, exporter = _seed(31), _seed(32)
        r1 = di.make_receipt("heidi", "ivan", "aa" * 32, s1, 100, 500)
        chain = di.export_chain([{"receipt": r1, "from_pubkey": _pub(s1)}],
                                exporter, 200)
        chain["links"][0]["receipt"]["signature"] = "00" * 128
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_chain_offline(chain, 300, {})
        self.assertEqual(ctx.exception.code, "delegation-signature-invalid")

    def test_expired_link_refused(self):
        s1, exporter = _seed(41), _seed(42)
        r1 = di.make_receipt("judy", "karl", "aa" * 32, s1, 100, 200)
        chain = di.export_chain([{"receipt": r1, "from_pubkey": _pub(s1)}],
                                exporter, 150)
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_chain_offline(chain, 200, {})  # at == not_after
        self.assertEqual(ctx.exception.code, "delegation-expired")

    def test_trace_edge_shape(self):
        edge = di.delegated_authority_edge("a", "b", "ab" * 32, "cd" * 32)
        self.assertEqual(edge["kind"], "delegated-authority")
        with self.assertRaises(di.DelegationIdentityError):
            di.delegated_authority_edge("a", "b", "xx", "cd" * 32)


class TestF377PinnedTrustRoots(unittest.TestCase):
    """F377 closure: embedded DID documents never replace the verifier's
    pinned trust roots. A conflicting embedded document refuses coded
    ``delegation-identity-invalid`` on BOTH offline paths; a
    byte-identical embedded copy still verifies."""

    def _forged_vs_real(self, tag):
        # The real Alice doc (Victor's pin) names Alice's key; the forged
        # doc reuses Alice's DID but names Mallory's key, self-signed by
        # Mallory's controller key (a valid controller signature).
        alice_ctrl, alice_key = _seed(tag), _seed(tag + 1)
        mallory_ctrl, mallory_key = _seed(tag + 2), _seed(tag + 3)
        real = di.issue_did_document(
            "did:sasanam:alice", alice_ctrl, [_pub(alice_key)],
            created_at=100)
        forged = di.issue_did_document(
            "did:sasanam:alice", mallory_ctrl, [_pub(mallory_key)],
            created_at=100)
        return real, forged, mallory_ctrl, mallory_key

    def _did_evidence_for(self, receipt_digest, doc, controller_seed):
        return di.make_identity_evidence(
            "did", receipt_digest, did="did:sasanam:alice",
            did_document_digest=di.did_document_digest(doc),
            controller_seed=controller_seed)

    def test_local_conflicting_embedded_refuses_coded(self):
        alice_ctrl = _seed(61)
        mallory_ctrl, signer = _seed(63), _seed(65)
        real = di.issue_did_document(
            "did:sasanam:alice", alice_ctrl, [_pub(_seed(62))],
            created_at=100)
        # Mallory self-issues an Alice doc naming the receipt signer's key.
        forged = di.issue_did_document(
            "did:sasanam:alice", mallory_ctrl, [_pub(signer)],
            created_at=100)
        r1 = di.make_receipt("alice", "mallory", "ab" * 32, signer, 100,
                             10 ** 6, None)
        ev = self._did_evidence_for(r1["receipt_id"], forged, mallory_ctrl)
        r1e = di.make_receipt("alice", "mallory", "ab" * 32, signer, 100,
                              10 ** 6, None, identity_evidence=ev)
        chain = di.export_chain(
            [{"receipt": r1e, "from_pubkey": _pub(signer),
              "did_documents": {"did:sasanam:alice": forged}}],
            _seed(66), 200)
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_chain_offline(chain, 200,
                                    {"did:sasanam:alice": real})
        self.assertEqual(ctx.exception.code, "delegation-identity-invalid")

    def test_native_conflicting_embedded_refuses_coded(self):
        from gov import delegation as dg
        real, _, mallory_ctrl, _ = self._forged_vs_real(71)
        rs, ms = _seed(75), _seed(76)
        rp, mp = _pub(rs), _pub(ms)
        cons = {"expires_at": 10 ** 12, "max_depth": 8}
        root = dg.issue(rs, "root-f377u", "mid-f377u", mp,
                        {"memory.read"}, constraints=dict(cons))
        leaf = dg.issue(ms, "mid-f377u", "leaf-f377u", _pub(_seed(77)),
                        {"memory.read"}, parent=root,
                        constraints=dict(cons))
        # Mallory (mid) forges an Alice doc naming the leaf-holder's key.
        forged = di.issue_did_document(
            "did:sasanam:alice", mallory_ctrl, [leaf["delegator_pubkey"]],
            created_at=100)
        ev = self._did_evidence_for(leaf["receipt_id"], forged,
                                    mallory_ctrl)
        entries = [
            {"receipt": root, "identity_evidence": None,
             "did_documents": {}},
            {"receipt": leaf, "identity_evidence": ev,
             "did_documents": {"did:sasanam:alice": forged}},
        ]
        chain = di.export_native_chain(entries, ms, 200, 200, [rp])
        with self.assertRaises(di.DelegationIdentityError) as ctx:
            di.verify_native_chain_offline(
                chain, 200, {"did:sasanam:alice": real}, [rp])
        self.assertEqual(ctx.exception.code, "delegation-identity-invalid")

    def test_identical_embedded_doc_still_verifies(self):
        # The embedded copy is byte-identical to the pinned root: the
        # honest flow must keep working.
        ctrl = _seed(81)
        signer = _seed(82)
        doc = di.issue_did_document("did:sasanam:carol", ctrl,
                                    [_pub(signer)], created_at=100)
        r1 = di.make_receipt("carol", "dave", "ab" * 32, signer, 100,
                             10 ** 6, None)
        ev = di.make_identity_evidence(
            "did", r1["receipt_id"], did="did:sasanam:carol",
            did_document_digest=di.did_document_digest(doc),
            controller_seed=ctrl)
        r1e = di.make_receipt("carol", "dave", "ab" * 32, signer, 100,
                              10 ** 6, None, identity_evidence=ev)
        chain = di.export_chain(
            [{"receipt": r1e, "from_pubkey": _pub(signer),
              "did_documents": {"did:sasanam:carol": doc}}],
            _seed(83), 200)
        rec = di.verify_chain_offline(chain, 200,
                                      {"did:sasanam:carol": doc})
        self.assertIs(rec["verified"], True)

    def test_unpinned_embedded_doc_admitted(self):
        # Residual, pinned deliberately: an embedded document for a DID
        # the verifier never pinned is still admitted as that DID's root
        # for this verification. Pinning stays the trust decision.
        ctrl = _seed(91)
        signer = _seed(92)
        doc = di.issue_did_document("did:sasanam:erin", ctrl,
                                    [_pub(signer)], created_at=100)
        r1 = di.make_receipt("erin", "fred", "ab" * 32, signer, 100,
                             10 ** 6, None)
        ev = di.make_identity_evidence(
            "did", r1["receipt_id"], did="did:sasanam:erin",
            did_document_digest=di.did_document_digest(doc),
            controller_seed=ctrl)
        r1e = di.make_receipt("erin", "fred", "ab" * 32, signer, 100,
                              10 ** 6, None, identity_evidence=ev)
        chain = di.export_chain(
            [{"receipt": r1e, "from_pubkey": _pub(signer),
              "did_documents": {"did:sasanam:erin": doc}}],
            _seed(93), 200)
        rec = di.verify_chain_offline(chain, 200, {})
        self.assertIs(rec["verified"], True)


class TestEd25519Contract(unittest.TestCase):
    def test_verify_returns_bool(self):
        seed = _seed(51)
        pub = ed25519.publickey(seed)
        sig = ed25519.sign(seed, b"m")
        self.assertIs(ed25519.verify(pub, b"m", sig), True)
        self.assertIs(ed25519.verify(pub, b"m", b"\x00" * 64), False)


if __name__ == "__main__":
    unittest.main()
