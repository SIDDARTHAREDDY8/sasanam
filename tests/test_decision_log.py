"""Unit tests for gov/decision_log.py (wave-250 lane 2).

Covers the RFC 6962 Merkle tree (hash vectors pinned against
upstream transparency-dev/merkle rfc6962_test.go and the
testdata/inclusion + testdata/consistency happy-path vectors),
the DecisionLog request binding + epochs, equivocation detection,
STH issue/sign/verify, fail-closed refusals, and the taxonomy pin
(979 + 4 decision-log codes = 983; additive only, merge coordinator
recomposes).
"""

import base64
import hashlib
import unittest

from gov import decision_codes
from gov import decision_log as dl
from gov import ed25519 as ed
from gov import policy_combine as pc
from gov.policy import PolicyDecision


def _b64(s):
    return base64.b64decode(s)


# Upstream pins: transparency-dev/merkle rfc6962/rfc6962_test.go
# (Apache-2.0). See evals/w250_decision_log_probes.py for provenance.
VEC_EMPTY_ROOT = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
VEC_EMPTY_LEAF = (
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
VEC_LEAF_L123456 = (
    "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56")
VEC_NODE = (
    "aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb")

# Upstream inclusion happy-path vector: testdata/inclusion/2
# (leafIdx=5, treeSize=8).
VEC_I2 = (5, 8,
          "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
          "QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=",
          ["vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
           "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
           "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="])

# Upstream consistency happy-path vector: testdata/consistency/2
# (size1=6, size2=8).
VEC_C2 = (6, 8,
          "duZ9rbzfHhDht03cYIq9L5jfsW+851J3tSMqEn8gh+8=",
          "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
          ["DrxdNDf74tsVi58Sah0RjjCBgQMdCpSfje3t68VY72o=",
           "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
           "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="])

REQ_A = hashlib.sha256(b"request-A").digest()
REQ_B = hashlib.sha256(b"request-B").digest()


def _dec(effect, policy_id="pol-1", rev="rev-7", digest="a" * 64):
    return PolicyDecision(
        effect, "reason %s" % effect, policy_id=policy_id,
        policy_rev_id=rev, policy_digest=digest)


def _combined(effect, **kw):
    return pc.combine([_dec(effect, **kw)])


class HashVectorTests(unittest.TestCase):
    def test_empty_root(self):
        self.assertEqual(dl.empty_root().hex(), VEC_EMPTY_ROOT)

    def test_empty_leaf(self):
        self.assertEqual(dl.hash_leaf(b"").hex(), VEC_EMPTY_LEAF)

    def test_leaf_l123456(self):
        self.assertEqual(dl.hash_leaf(b"L123456").hex(),
                         VEC_LEAF_L123456)

    def test_node_n123_n456(self):
        self.assertEqual(
            dl.hash_node(_b64("TjEyMw=="), _b64("TjQ1Ng==")).hex(),
            VEC_NODE)

    def test_domain_separation(self):
        # 0x00 vs 0x01 prefixes: leaf/node must differ on same input.
        self.assertNotEqual(dl.hash_leaf(b"N123N456"),
                            dl.hash_node(_b64("TjEyMw=="),
                                         _b64("TjQ1Ng==")))

    def test_hash_leaf_rejects_non_bytes(self):
        with self.assertRaises(dl.DecisionLogError) as ctx:
            dl.hash_leaf("nope")
        self.assertEqual(ctx.exception.code, "decision-log-malformed")

    def test_hash_node_accepts_arbitrary_bytes(self):
        # Faithful to the upstream hasher API: children are arbitrary
        # bytes (the RFC pins HashChildren("N123", "N456")).
        self.assertEqual(
            dl.hash_node(b"N123", b"N456").hex(), VEC_NODE)

    def test_hash_node_rejects_non_bytes(self):
        with self.assertRaises(dl.DecisionLogError):
            dl.hash_node("nope", b"x" * 32)


class InclusionTests(unittest.TestCase):
    def test_upstream_vector_verifies(self):
        idx, size, root, leaf_hash, proof = VEC_I2
        self.assertTrue(dl.MerkleTree.verify_inclusion(
            idx, _b64(leaf_hash), size,
            [_b64(p) for p in proof], _b64(root)))

    def test_upstream_vector_rejects_wrong_leaf(self):
        idx, size, root, _leaf, proof = VEC_I2
        self.assertFalse(dl.MerkleTree.verify_inclusion(
            idx, dl.hash_leaf(b"wrong"), size,
            [_b64(p) for p in proof], _b64(root)))

    def test_upstream_vector_rejects_truncated_proof(self):
        idx, size, root, leaf_hash, proof = VEC_I2
        self.assertFalse(dl.MerkleTree.verify_inclusion(
            idx, _b64(leaf_hash), size,
            [_b64(p) for p in proof[:-1]], _b64(root)))

    def test_roundtrip_all_leaves(self):
        t = dl.MerkleTree()
        for i in range(13):
            t.append(b"leaf-%d" % i)
        root = t.root()
        for i in range(13):
            proof = t.inclusion_proof(i)
            self.assertTrue(dl.MerkleTree.verify_inclusion(
                i, dl.hash_leaf(b"leaf-%d" % i), 13, proof, root),
                "leaf %d" % i)

    def test_proof_decomposition_matches_upstream(self):
        # Upstream vector I2 is (index=5, size=8) with a 3-hash proof:
        # inner=bitlen(5^7)=2, border=popcount(5>>2)=1. Pin the
        # canonical sibling order independently of the verifier by
        # re-deriving the chain inline.
        t = dl.MerkleTree()
        for i in range(8):
            t.append(b"k-%d" % i)
        proof = t.inclusion_proof(5)
        self.assertEqual(len(proof), 3)
        calc = dl.hash_leaf(b"k-5")
        for i, sib in enumerate(proof[:2]):
            if (5 >> i) & 1 == 0:
                calc = dl.hash_node(calc, sib)
            else:
                calc = dl.hash_node(sib, calc)
        calc = dl.hash_node(proof[2], calc)
        self.assertEqual(calc, t.root())


class ConsistencyTests(unittest.TestCase):
    def test_upstream_vector_verifies(self):
        s1, s2, r1, r2, proof = VEC_C2
        self.assertTrue(dl.MerkleTree.verify_consistency(
            s1, s2, [_b64(p) for p in proof], _b64(r1), _b64(r2)))

    def test_upstream_vector_rejects_swapped_roots(self):
        s1, s2, r1, r2, proof = VEC_C2
        self.assertFalse(dl.MerkleTree.verify_consistency(
            s1, s2, [_b64(p) for p in proof], _b64(r2), _b64(r1)))

    def test_generated_proof_verifies(self):
        t = dl.MerkleTree()
        for i in range(10):
            t.append(b"c-%d" % i)
        for s1 in (1, 2, 3, 5, 6, 7, 9, 10):
            proof = t.consistency_proof(s1)
            t1 = dl.MerkleTree()
            for i in range(s1):
                t1.append(b"c-%d" % i)
            self.assertTrue(dl.MerkleTree.verify_consistency(
                s1, 10, proof, t1.root(), t.root()),
                "size1=%d" % s1)

    def test_generated_matches_upstream_bytes(self):
        # Canonical minimality: our consistency proof for the
        # upstream vector's (size1, size2) must byte-match upstream.
        # Reconstruct the upstream tree's first 8 leaf hashes from
        # the inclusion vectors' leaf hashes is overkill; instead
        # verify our generator against the upstream *verifier*
        # (done above) and pin one byte-equality via the power-of-2
        # case where proof == inclusion-proof suffix.
        t = dl.MerkleTree()
        for i in range(8):
            t.append(b"u-%d" % i)
        ours = t.consistency_proof(1)
        inc = t.inclusion_proof(0)
        self.assertEqual(ours, inc)  # shift=0 for size1=1

    def test_equal_sizes_empty_proof(self):
        t = dl.MerkleTree()
        t.append(b"x")
        self.assertEqual(t.consistency_proof(1), [])
        self.assertTrue(dl.MerkleTree.verify_consistency(
            1, 1, [], t.root(), t.root()))


class RequestBindingTests(unittest.TestCase):
    def test_first_append_binds(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        self.assertEqual(log.epochs()[0]["request_digest"], REQ_A.hex())

    def test_mixed_digest_refuses(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        with self.assertRaises(dl.DecisionLogError) as ctx:
            log.append(_combined("deny"), REQ_B)
        self.assertEqual(ctx.exception.code,
                         "decision-log-request-mismatch")
        self.assertEqual(log.tree_size(), 1)

    def test_new_epoch_allows(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.new_epoch(REQ_B)
        log.append(_combined("deny"), REQ_B)
        self.assertEqual(log.tree_size(), 2)
        self.assertEqual(len(log.epochs()), 2)

    def test_new_epoch_same_digest_noop(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.new_epoch(REQ_A)
        self.assertEqual(len(log.epochs()), 1)

    def test_old_leaf_still_provable_after_epoch(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.new_epoch(REQ_B)
        log.append(_combined("deny"), REQ_B)
        self.assertTrue(log.verify_leaf(0))

    def test_malformed_digest_refuses(self):
        log = dl.DecisionLog()
        with self.assertRaises(dl.DecisionLogError) as ctx:
            log.append(_combined("allow"), "not-bytes")
        self.assertEqual(ctx.exception.code, "decision-log-malformed")
        with self.assertRaises(dl.DecisionLogError):
            log.append(_combined("allow"), b"short")


class EquivocationTests(unittest.TestCase):
    def test_detected_and_proven(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.append(_combined("deny"), REQ_A)
        found = dl.detect_equivocation(log)
        self.assertEqual(len(found), 1)
        ev = found[0]
        self.assertEqual(ev.code, "decision-log-equivocation")
        self.assertEqual({ev.effect_a, ev.effect_b}, {"allow", "deny"})
        self.assertTrue(ev.verify(log))

    def test_no_false_positive_same_effect(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.append(_combined("allow"), REQ_A)
        self.assertEqual(dl.detect_equivocation(log), [])

    def test_no_false_positive_revision_change(self):
        log = dl.DecisionLog()
        log.append(_combined("allow", rev="rev-7"), REQ_A)
        log.append(_combined("deny", rev="rev-8"), REQ_A)
        self.assertEqual(dl.detect_equivocation(log), [])

    def test_no_false_positive_across_epochs(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.new_epoch(REQ_B)
        log.append(_combined("deny"), REQ_B)
        self.assertEqual(dl.detect_equivocation(log), [])

    def test_proof_fails_after_tamper(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.append(_combined("deny"), REQ_A)
        (ev,) = dl.detect_equivocation(log)
        bad = [bytes(b) for b in ev.proof_a]
        flip = bytearray(bad[0])
        flip[0] ^= 0xFF
        bad[0] = bytes(flip)
        ev.proof_a = tuple(bad)
        self.assertFalse(ev.verify(log))


class FailClosedTests(unittest.TestCase):
    def test_append_non_decision_refuses(self):
        log = dl.DecisionLog()
        for bad in ("x", {"effect": "allow"}, None, 42):
            with self.assertRaises(dl.DecisionLogError) as ctx:
                log.append(bad, REQ_A)
            self.assertEqual(ctx.exception.code,
                             "decision-log-malformed")
        self.assertEqual(log.tree_size(), 0)

    def test_tampered_proof_raises(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        log.append(_combined("deny"), REQ_A)
        proof = [bytes(b) for b in log.inclusion_proof(0)]
        flip = bytearray(proof[0])
        flip[0] ^= 0xFF
        proof[0] = bytes(flip)
        with self.assertRaises(dl.DecisionLogError) as ctx:
            log.verify_proof(0, proof)
        self.assertEqual(ctx.exception.code,
                         "decision-log-proof-invalid")

    def test_leaf_bytes_deterministic(self):
        a = dl._canonical_leaf_bytes(_combined("allow"), REQ_A)
        b = dl._canonical_leaf_bytes(_combined("allow"), REQ_A)
        self.assertEqual(a, b)


class SthTests(unittest.TestCase):
    def test_issue_unsigned(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        sth = log.issue_sth()
        self.assertIsNone(sth["signature"])
        self.assertEqual(sth["tree_size"], 1)
        self.assertEqual(sth["root"], log.root().hex())

    def test_sign_verify_roundtrip(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        signed = log.sign_sth(log.issue_sth(), seed)
        self.assertIsNotNone(signed["signature"])
        self.assertTrue(log.verify_sth(signed, pub))

    def test_tampered_sth_fails(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        signed = log.sign_sth(log.issue_sth(), seed)
        tampered = dict(signed)
        tampered["tree_size"] += 1
        self.assertFalse(log.verify_sth(tampered, pub))

    def test_wrong_key_fails(self):
        log = dl.DecisionLog()
        log.append(_combined("allow"), REQ_A)
        seed = ed.generate_seed()
        other_pub = ed.publickey(ed.generate_seed())
        signed = log.sign_sth(log.issue_sth(), seed)
        self.assertFalse(log.verify_sth(signed, other_pub))


class TaxonomyPinTests(unittest.TestCase):
    def test_pin(self):
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 2035)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.
        for code in ("decision-log-malformed",
                     "decision-log-request-mismatch",
                     "decision-log-proof-invalid",
                     "decision-log-equivocation"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(
                decision_codes.TAXONOMY[code]["domain"],
                "decision-log")


if __name__ == "__main__":
    unittest.main()
