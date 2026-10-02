"""Unit tests for gov/evidence_receipt.py (wave-286 lane 7).

Covers: receipt issuance/verification at the public seams, offline
verification with only the operator key, tampered-proof/root/digest
refusals, witness cosigning quorum, fork denunciation (proven and
clean), envelope composition, JSON transport, and the fail-fast
operator-seed rule. Deterministic; synthetic key material only.
"""

import copy
import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import evidence_anchor as ea
from gov import evidence_receipt as er


def _fresh_log(tmp, seed=None, origin="test-log.example"):
    seed = seed if seed is not None else ed25519.generate_seed()
    root = os.path.join(tmp, "log-%s" % secrets.token_hex(4))
    log = ea.TransparencyLog(root, origin=origin, signer_keyid="op-1",
                             signer_seed=seed)
    return log, ed25519.publickey(bytes(seed)), seed


def _anchor(log, digest=None):
    digest = digest or secrets.token_hex(32)
    anchored = ea.anchor(log, digest)
    return anchored, digest


class IssueShapeTest(unittest.TestCase):
    def test_receipt_binds_all_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            anchored, digest = _anchor(log)
            rcpt = er.bind_receipt(anchored, seed)
        self.assertEqual(rcpt["receipt_format"], "ccf-inclusion-receipt/1")
        p = rcpt["payload"]
        self.assertEqual(p["bundle_digest"], digest)
        self.assertEqual(p["leaf_index"], 0)
        self.assertEqual(p["tree_size"], 1)
        self.assertEqual(p["vds"], "gov/evidence-anchor/tlog-tiles")
        self.assertTrue(all(len(h) == 64 for h in p["inclusion_path"]))
        self.assertEqual(rcpt["protected"]["alg"], "EdDSA")
        self.assertEqual(len(rcpt["signature"]), 128)

    def test_issue_receipt_convenience_anchors(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            digest = secrets.token_hex(32)
            rcpt = er.issue_receipt(log, digest, seed)
            self.assertTrue(er.verify_receipt_offline(rcpt, pub))

    def test_wrong_operator_seed_refuses_at_issuance(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            anchored, _digest = _anchor(log)
            other = ed25519.generate_seed()
            with self.assertRaises(er.ReceiptError) as ctx:
                er.bind_receipt(anchored, other)
            self.assertEqual(ctx.exception.code,
                             "inclusion-receipt-malformed")


class OfflineVerifyTest(unittest.TestCase):
    def test_verify_offline_with_only_pubkey(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            digest = secrets.token_hex(32)
            rcpt = er.issue_receipt(log, digest, seed)
            del log  # the log store is gone; the auditor is offline
        self.assertTrue(er.verify_receipt_offline(rcpt, pub))

    def test_verify_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        self.assertTrue(er.verify_receipt_offline(rcpt, pub))
        self.assertTrue(er.verify_receipt_offline(rcpt, pub))

    def test_tampered_proof_trips_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            for _ in range(3):
                ea.anchor(log, secrets.token_hex(32))
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad = copy.deepcopy(rcpt)
        first = bad["payload"]["inclusion_path"][0]
        bad["payload"]["inclusion_path"][0] = \
            ("00" if first[:2] != "00" else "ff") + first[2:]
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(bad, pub)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")

    def test_tampered_root_trips_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad = copy.deepcopy(rcpt)
        root = bad["payload"]["root"]
        bad["payload"]["root"] = ("00" if root[:2] != "00" else "ff") \
            + root[2:]
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(bad, pub)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")

    def test_forged_key_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        other = ed25519.publickey(ed25519.generate_seed())
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(rcpt, other)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")

    def test_swapped_digest_refuses(self):
        # The digest is inside the signed payload: swapping it trips
        # the signature before the Merkle check is even reached.
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad = copy.deepcopy(rcpt)
        bad["payload"]["bundle_digest"] = secrets.token_hex(32)
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(bad, pub)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")

    def test_malformed_receipt_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad = copy.deepcopy(rcpt)
        del bad["payload"]
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(bad, pub)
        self.assertEqual(ctx.exception.code,
                         "inclusion-receipt-malformed")

    def test_inclusion_mismatch_when_proof_bad_but_signed(self):
        # The inclusion path is inside the signed payload, so a
        # tampered path normally trips receipt-signature-invalid. This
        # test covers the genuine inclusion-mismatch path: the operator
        # signs a BAD proof (models a log serving a corrupt proof),
        # the signature verifies, and the Merkle check refuses.
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            for _ in range(3):
                ea.anchor(log, secrets.token_hex(32))
            anchored, _digest = _anchor(log)
        bad = copy.deepcopy(anchored)
        first = bad["inclusion_proof"]["hashes"][0]
        bad["inclusion_proof"]["hashes"][0] = \
            ("00" if first[:2] != "00" else "ff") + first[2:]
        rcpt = er.bind_receipt(bad, seed)
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(rcpt, pub)
        self.assertEqual(ctx.exception.code,
                         "receipt-inclusion-mismatch")

    def test_leaf_mismatch_against_divergent_store(self):
        # The opt-in log_root cross-check: the receipt is valid, but
        # the tile store presented for cross-checking holds a different
        # leaf at the claimed index (models a rewritten tile).
        with tempfile.TemporaryDirectory() as tmp:
            log_a, pub_a, seed_a = _fresh_log(tmp)
            root_b = os.path.join(tmp, "log-b")
            log_b = ea.TransparencyLog(root_b, "test-log.example",
                                       "op-1", signer_seed=seed_a)
            rcpt = er.issue_receipt(log_a, secrets.token_hex(32),
                                    seed_a)
            ea.anchor(log_b, secrets.token_hex(32))  # same size,
            # different leaf
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(rcpt, pub_a, log_root=root_b)
        self.assertEqual(ctx.exception.code, "receipt-leaf-mismatch")

    def test_tile_cross_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "log")
            log = ea.TransparencyLog(root, "test-log.example", "op-1",
                                     signer_seed=ed25519.generate_seed())
            seed = log._seed
            pub = ed25519.publickey(bytes(seed))
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
            self.assertTrue(
                er.verify_receipt_offline(rcpt, pub, log_root=root))

    def test_ed25519_verify_contract_is_checked(self):
        # Wave-243: gov.ed25519.verify returns True/False -- callers
        # must check it. A verifier that ignored False would accept
        # this flipped-signature receipt.
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        good = ed25519.sign(bytes(seed), b"receipt-test-message")
        bad = bytearray(good)
        bad[0] ^= 0x01
        self.assertIs(ed25519.verify(pub, b"receipt-test-message",
                                     bytes(bad)), False)
        with tempfile.TemporaryDirectory() as tmp:
            log, _p, _s = _fresh_log(tmp, seed=seed)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad_rcpt = copy.deepcopy(rcpt)
        sig = bytearray.fromhex(bad_rcpt["signature"])
        sig[0] ^= 0x01
        bad_rcpt["signature"] = bytes(sig).hex()
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(bad_rcpt, pub)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")


class WitnessTest(unittest.TestCase):
    def _policy(self, quorum=2, n=3):
        from gov import signing
        wit, seeds = {}, {}
        for _i in range(n):
            s = ed25519.generate_seed()
            kid = signing.ed25519_key_id(ed25519.publickey(bytes(s)))
            wit[kid] = ed25519.publickey(bytes(s)).hex()
            seeds[kid] = s
        return ea.WitnessPolicy(policy_id="wp-1", witnesses=wit,
                                quorum=quorum), seeds

    def test_quorum_cosign_verifies(self):
        policy, seeds = self._policy()
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed,
                                    witness_policy=policy,
                                    witness_seeds=seeds)
            self.assertTrue(er.verify_receipt_offline(rcpt, pub,
                                                      witness_policy=policy))

    def test_under_quorum_issuance_refuses(self):
        # Anchor without a witness policy, then bind with an
        # under-quorum witness set: the RECEIPT layer's fail-fast
        # quorum rule fires (the anchor layer has its own identical
        # rule when the policy is passed to anchor time).
        policy, seeds = self._policy(quorum=2, n=3)
        one = dict(list(seeds.items())[:1])
        with tempfile.TemporaryDirectory() as tmp:
            log, _pub, seed = _fresh_log(tmp)
            anchored, _digest = _anchor(log)
            with self.assertRaises(er.ReceiptError) as ctx:
                er.bind_receipt(anchored, seed, witness_policy=policy,
                                witness_seeds=one)
            self.assertEqual(ctx.exception.code,
                             "receipt-policy-mismatch")

    def test_stripped_cosignature_refuses(self):
        policy, seeds = self._policy()
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed,
                                    witness_policy=policy,
                                    witness_seeds=seeds)
        thin = copy.deepcopy(rcpt)
        thin["unprotected"]["witness_signatures"] = \
            thin["unprotected"]["witness_signatures"][:1]
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(thin, pub,
                                      witness_policy=policy)
        self.assertEqual(ctx.exception.code, "receipt-policy-mismatch")

    def test_wrong_policy_id_refuses(self):
        policy, seeds = self._policy()
        other, _seeds = self._policy()
        other = ea.WitnessPolicy(policy_id="wp-other",
                                 witnesses=policy.witnesses,
                                 quorum=policy.quorum)
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed,
                                    witness_policy=policy,
                                    witness_seeds=seeds)
        with self.assertRaises(er.ReceiptError) as ctx:
            er.verify_receipt_offline(rcpt, pub, witness_policy=other)
        self.assertEqual(ctx.exception.code, "receipt-policy-mismatch")


class ForkTest(unittest.TestCase):
    def test_fork_proven(self):
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        rcpts = []
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(2):
                log, _p, _s = _fresh_log(tmp, seed=seed)
                rcpts.append(er.issue_receipt(log, secrets.token_hex(32),
                                              seed))
        self.assertNotEqual(rcpts[0]["payload"]["root"],
                            rcpts[1]["payload"]["root"])
        verdict = er.denounce_fork(rcpts[0], rcpts[1], pub)
        self.assertTrue(verdict["fork"] is True)
        proof = verdict["proof"]
        self.assertEqual(proof["tree_size"], 1)
        self.assertNotEqual(proof["root_a"], proof["root_b"])

    def test_agreement_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            anchored, _d = _anchor(log)
            rcpt_a = er.bind_receipt(anchored, seed)
            rcpt_b = er.bind_receipt(anchored, seed)
            verdict = er.denounce_fork(rcpt_a, rcpt_b, pub)
        self.assertTrue(verdict["fork"] is False)

    def test_fork_needs_equal_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt_a = er.issue_receipt(log, secrets.token_hex(32), seed)
            rcpt_b = er.issue_receipt(log, secrets.token_hex(32), seed)
        with self.assertRaises(er.ReceiptError) as ctx:
            er.denounce_fork(rcpt_a, rcpt_b, pub)
        self.assertEqual(ctx.exception.code, "inclusion-receipt-malformed")

    def test_fork_verifies_signatures_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt_a = er.issue_receipt(log, secrets.token_hex(32), seed)
            rcpt_b = er.issue_receipt(log, secrets.token_hex(32), seed)
        bad = copy.deepcopy(rcpt_b)
        bad["signature"] = "ff" * 64
        with self.assertRaises(er.ReceiptError) as ctx:
            er.denounce_fork(rcpt_a, bad, pub)
        self.assertEqual(ctx.exception.code, "receipt-signature-invalid")


class TransportTest(unittest.TestCase):
    def test_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub, seed = _fresh_log(tmp)
            rcpt = er.issue_receipt(log, secrets.token_hex(32), seed)
            blob = er.receipt_to_json(rcpt)
            back = er.receipt_from_json(blob)
            self.assertTrue(er.verify_receipt_offline(back, pub))

    def test_from_json_rejects_garbage(self):
        with self.assertRaises(er.ReceiptError) as ctx:
            er.receipt_from_json(b"not json")
        self.assertEqual(ctx.exception.code, "inclusion-receipt-malformed")

    def test_to_json_refuses_malformed(self):
        with self.assertRaises(er.ReceiptError):
            er.receipt_to_json({"receipt_format": "nope"})


class EnvelopeCompositionTest(unittest.TestCase):
    def test_receipt_covers_sealed_envelope(self):
        from gov import bundle_envelope as be
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        xpriv = secrets.token_bytes(32)
        policy = be.make_recipient_policy(
            [{"id": "auditor-1", "type": "offline",
              "x25519_pub": be.x25519_pub(xpriv).hex()}])
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "log")
            log = ea.TransparencyLog(root, "test-log.example", "op-1",
                                     signer_seed=seed)
            env = be.seal_envelope(b'{"note": "evidence"}',
                                   bundle_id="b1", policy=policy,
                                   signer_seed=seed)
            rcpt = er.issue_receipt_for_envelope(log, env, seed)
        self.assertEqual(rcpt["payload"]["bundle_digest"],
                         be.envelope_digest(env))
        self.assertTrue(er.verify_receipt_offline(rcpt, pub))

    def test_tampered_envelope_breaks_binding(self):
        from gov import bundle_envelope as be
        seed = ed25519.generate_seed()
        pub = ed25519.publickey(bytes(seed))
        xpriv = secrets.token_bytes(32)
        policy = be.make_recipient_policy(
            [{"id": "auditor-1", "type": "offline",
              "x25519_pub": be.x25519_pub(xpriv).hex()}])
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "log")
            log = ea.TransparencyLog(root, "test-log.example", "op-1",
                                     signer_seed=seed)
            env = be.seal_envelope(b'{"note": "evidence"}',
                                   bundle_id="b1", policy=policy,
                                   signer_seed=seed)
            rcpt = er.issue_receipt_for_envelope(log, env, seed)
        # The receipt binds the ORIGINAL envelope digest; a tampered
        # envelope no longer matches what the receipt attests.
        env["bundle_id"] = "b1-tampered"
        self.assertNotEqual(rcpt["payload"]["bundle_digest"],
                            be.envelope_digest(env))
        self.assertTrue(er.verify_receipt_offline(rcpt, pub))


class SelfCheckTest(unittest.TestCase):
    def test_self_check(self):
        self.assertTrue(er._self_check())


if __name__ == "__main__":
    unittest.main()
