"""Unit tests for gov/evidence_anchor.py (wave-285 lane 7, tessera STEAL).

Covers the RFC 6962 Merkle semantics (cross-checked against an
independent iterative reimplementation), the C2SP signed-note
checkpoint round-trip, witness-quorum enforcement, the POSIX tile
layout, the fail-closed refusal matrix, and the GUAC/bundle
composition seams. Deterministic; secrets only for key material.
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import unittest

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import evidence_anchor as ea  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import signing as _signing  # noqa: E402


def _iter_root(leaf_datas):
    """Independent iterative Merkle root (pairwise level reduction).

    A different algorithm from the module's recursive split-at-largest-
    power-of-two, so agreement cross-checks the transcription rather
    than echoing it.
    """
    level = [hashlib.sha256(b"\x00" + d).digest() for d in leaf_datas]
    if not level:
        return hashlib.sha256(b"").digest()
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(
                b"\x01" + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


class TestMerkle(unittest.TestCase):
    def test_leaf_domain_separation(self):
        self.assertEqual(ea._hash_leaf(b"x"),
                         hashlib.sha256(b"\x00x").digest())
        self.assertNotEqual(ea._hash_leaf(b"x"),
                            hashlib.sha256(b"\x01x").digest())

    def test_single_leaf_root_is_leaf_hash(self):
        h = ea._hash_leaf(b"a")
        self.assertEqual(ea._tree_root_hashes([h]), h)

    def test_two_leaf_root(self):
        l0, l1 = ea._hash_leaf(b"a"), ea._hash_leaf(b"b")
        self.assertEqual(ea._tree_root_hashes([l0, l1]),
                         hashlib.sha256(b"\x01" + l0 + l1).digest())

    def test_root_matches_independent_implementation(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 64):
            datas = [b"leaf-%d-of-%d" % (i, n) for i in range(n)]
            hashes = [ea._hash_leaf(d) for d in datas]
            self.assertEqual(ea._tree_root_hashes(hashes),
                             _iter_root(datas),
                             "root mismatch at n=%d" % n)

    def test_inclusion_proofs_verify_all_indices(self):
        for n in (1, 2, 3, 5, 8, 13, 16, 17):
            datas = [b"p-%d" % i for i in range(n)]
            hashes = [ea._hash_leaf(d) for d in datas]
            root = ea._tree_root_hashes(hashes)
            for m in range(n):
                sibs = ea._inclusion_proof_hashes(hashes, m)
                proof = {"leaf_index": m, "tree_size": n,
                         "hashes": [s.hex() for s in sibs]}
                self.assertTrue(ea.verify_inclusion(hashes[m], proof,
                                                   root),
                                "n=%d m=%d" % (n, m))

    def test_proof_length_matches_tree(self):
        # A 5-leaf tree is left-balanced: leaves 0..3 sit three levels
        # deep, leaf 4 hangs off the top split.
        datas = [b"q%d" % i for i in range(5)]
        hashes = [ea._hash_leaf(d) for d in datas]
        lengths = {m: len(ea._inclusion_proof_hashes(hashes, m))
                   for m in range(5)}
        self.assertEqual(lengths, {0: 3, 1: 3, 2: 3, 3: 3, 4: 1})

    def test_tampered_sibling_fails(self):
        datas = [b"t%d" % i for i in range(6)]
        hashes = [ea._hash_leaf(d) for d in datas]
        root = ea._tree_root_hashes(hashes)
        sibs = ea._inclusion_proof_hashes(hashes, 2)
        bad = bytearray(sibs[0])
        bad[0] ^= 0x01
        proof = {"leaf_index": 2, "tree_size": 6,
                 "hashes": [bytes(bad).hex()] +
                           [s.hex() for s in sibs[1:]]}
        self.assertFalse(ea.verify_inclusion(hashes[2], proof, root))

    def test_wrong_root_fails(self):
        h = ea._hash_leaf(b"solo")
        proof = {"leaf_index": 0, "tree_size": 1, "hashes": []}
        self.assertFalse(ea.verify_inclusion(
            h, proof, hashlib.sha256(b"nope").digest()))

    def test_malformed_proof_refuses_loud(self):
        h = ea._hash_leaf(b"solo")
        with self.assertRaises(ea.AnchorError) as ctx:
            ea.verify_inclusion(h, {"leaf_index": 0}, h)
        self.assertEqual(ctx.exception.code, "anchor-inclusion-mismatch")
        with self.assertRaises(ea.AnchorError):
            ea.verify_inclusion(h, {"leaf_index": 5, "tree_size": 3,
                                    "hashes": []}, h)

    def test_empty_tree_root(self):
        self.assertEqual(ea._tree_root_hashes([]),
                         hashlib.sha256(b"").digest())


class TestCheckpoint(unittest.TestCase):
    def _body(self):
        return {"origin": "test.example/log", "size": 41,
                "root": hashlib.sha256(b"r").digest(),
                "timestamp": 1720000000, "witness_policy_id": "none"}

    def test_roundtrip(self):
        body = self._body()
        seed = _ed.generate_seed()
        sig = {"keyid": "op-1",
               "sig": _ed.sign(seed, ea._render_body(body)
                               .encode("utf-8")).hex()}
        note = ea.render_checkpoint(body, [sig])
        parsed, sigs = ea.parse_checkpoint(note)
        self.assertEqual(parsed["origin"], body["origin"])
        self.assertEqual(parsed["size"], 41)
        self.assertEqual(parsed["root"], body["root"])
        self.assertEqual(parsed["timestamp"], 1720000000)
        self.assertEqual(parsed["witness_policy_id"], "none")
        self.assertEqual(len(sigs), 1)
        self.assertEqual(sigs[0]["keyid"], "op-1")
        pub = _ed.publickey(seed)
        self.assertIs(
            _ed.verify(pub, parsed["canonical"],
                       bytes.fromhex(sigs[0]["sig"])), True)

    def test_malformed_notes_refused(self):
        bad_notes = [
            "",
            "no newlines at all",
            "a\nb\nc\nd\ne\n",  # no signature lines
            "a\nb\nc\nd\ne\n\nnot-a-sig-line\n",
            "a\n-1\n" + base64.b64encode(b"x" * 32).decode()
            + "\n1\nwitness_policy: none\n\n\u2014 k "
            + base64.b64encode(b"y" * 64).decode() + "\n",
        ]
        for note in bad_notes:
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.parse_checkpoint(note)
            self.assertEqual(ctx.exception.code,
                             "anchor-checkpoint-invalid",
                             "note %r" % note[:30])

    def test_signature_line_grammar_strict(self):
        body = self._body()
        note = ea._render_body(body) + "\n\u2014 bad key! " \
            + base64.b64encode(b"z" * 64).decode() + "\n"
        with self.assertRaises(ea.AnchorError) as ctx:
            ea.parse_checkpoint(note)
        self.assertEqual(ctx.exception.code, "anchor-checkpoint-invalid")


class TestWitnessPolicy(unittest.TestCase):
    def _policy(self, n=3, quorum=2):
        wit, seeds = {}, {}
        for i in range(n):
            seed = _ed.generate_seed()
            pub = _ed.publickey(seed)
            kid = _signing.ed25519_key_id(pub)
            wit[kid] = pub.hex()
            seeds[kid] = seed
        return ea.WitnessPolicy("wp-test", wit, quorum), seeds

    def test_validation(self):
        wit = {"k1": _ed.publickey(_ed.generate_seed()).hex()}
        with self.assertRaises(ea.AnchorError):
            ea.WitnessPolicy("wp", wit, 0)
        with self.assertRaises(ea.AnchorError):
            ea.WitnessPolicy("wp", wit, 2)
        with self.assertRaises(ea.AnchorError):
            ea.WitnessPolicy("wp", {"k1": "zz"}, 1)
        with self.assertRaises(ea.AnchorError):
            ea.WitnessPolicy("bad id!", wit, 1)
        with self.assertRaises(ea.AnchorError):
            ea.WitnessPolicy("wp", {}, 1)

    def test_quorum_met(self):
        pol, seeds = self._policy(3, 2)
        body = {"origin": "o", "size": 1,
                "root": hashlib.sha256(b"r").digest(), "timestamp": 1,
                "witness_policy_id": "wp-test"}
        canonical = ea._render_body(body).encode("utf-8")
        sigs = [{"keyid": "op", "sig": _ed.sign(
            _ed.generate_seed(), canonical).hex()}]
        for kid, seed in list(seeds.items())[:2]:
            sigs.append({"keyid": kid,
                         "sig": _ed.sign(seed, canonical).hex()})
        note = ea.render_checkpoint(body, sigs)
        self.assertEqual(ea.check_witness_quorum(note, pol), 2)

    def test_quorum_missed_refuses(self):
        pol, seeds = self._policy(3, 2)
        body = {"origin": "o", "size": 1,
                "root": hashlib.sha256(b"r").digest(), "timestamp": 1,
                "witness_policy_id": "wp-test"}
        canonical = ea._render_body(body).encode("utf-8")
        kid, seed = next(iter(seeds.items()))
        note = ea.render_checkpoint(body, [
            {"keyid": "op", "sig": _ed.sign(
                _ed.generate_seed(), canonical).hex()},
            {"keyid": kid, "sig": _ed.sign(seed, canonical).hex()}])
        with self.assertRaises(ea.AnchorError) as ctx:
            ea.check_witness_quorum(note, pol)
        self.assertEqual(ctx.exception.code,
                         "anchor-witness-quorum-failed")

    def test_operator_sig_not_counted(self):
        # The operator's own line must not count toward the witness
        # quorum even if its key id collides with a witness id shape.
        pol, seeds = self._policy(2, 2)
        body = {"origin": "o", "size": 1,
                "root": hashlib.sha256(b"r").digest(), "timestamp": 1,
                "witness_policy_id": "wp-test"}
        canonical = ea._render_body(body).encode("utf-8")
        op_seed = _ed.generate_seed()
        note = ea.render_checkpoint(body, [
            {"keyid": "op-9", "sig": _ed.sign(op_seed, canonical).hex()},
            {"keyid": "op-9", "sig": _ed.sign(op_seed, canonical).hex()}])
        with self.assertRaises(ea.AnchorError) as ctx:
            ea.check_witness_quorum(note, pol, operator_keyid="op-9")
        self.assertEqual(ctx.exception.code,
                         "anchor-witness-quorum-failed")

    def test_operator_keyid_collision_not_counted(self):
        # MAJOR-1 regression: the operator's key id PINNED as a witness
        # (quorum 1) with a checkpoint carrying only the operator line
        # must still refuse -- the operator line never counts.
        op_seed = _ed.generate_seed()
        op_pub = _ed.publickey(op_seed)
        pol = ea.WitnessPolicy("wp-collide", {"op-9": op_pub.hex()}, 1)
        body = {"origin": "o", "size": 1,
                "root": hashlib.sha256(b"r").digest(), "timestamp": 1,
                "witness_policy_id": "wp-collide"}
        canonical = ea._render_body(body).encode("utf-8")
        note = ea.render_checkpoint(body, [
            {"keyid": "op-9",
             "sig": _ed.sign(op_seed, canonical).hex()}])
        with self.assertRaises(ea.AnchorError) as ctx:
            ea.check_witness_quorum(note, pol, operator_keyid="op-9")
        self.assertEqual(ctx.exception.code,
                         "anchor-witness-quorum-failed")

    def test_cosign_seed_mismatch_refused(self):
        pol, seeds = self._policy(2, 1)
        kid = next(iter(seeds))
        body = {"origin": "o", "size": 1,
                "root": hashlib.sha256(b"r").digest(), "timestamp": 1,
                "witness_policy_id": "wp-test"}
        log_seed = _ed.generate_seed()
        with tempfile.TemporaryDirectory() as tmp:
            log = ea.TransparencyLog(tmp, "o", "op", log_seed)
            with self.assertRaises(ea.AnchorError) as ctx:
                log._cosign(body, {"keyid": "op", "sig": "00" * 64},
                            pol, {kid: _ed.generate_seed()})
            self.assertEqual(ctx.exception.code,
                             "anchor-witness-quorum-failed")


class TestLogStore(unittest.TestCase):
    def _log(self, tmp):
        seed = _ed.generate_seed()
        log = ea.TransparencyLog(os.path.join(tmp, "log"), "test/log",
                                 "op-1", seed)
        return log, _ed.publickey(seed)

    def test_add_rejects_bad_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, _ = self._log(tmp)
            with self.assertRaises(ea.AnchorError):
                log.add(b"")
            with self.assertRaises(ea.AnchorError):
                log.add(b"x" * 65537)
            with self.assertRaises(ea.AnchorError):
                log.add("not-bytes")

    def test_await_unknown_index_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, _ = self._log(tmp)
            log.add(b"a")
            with self.assertRaises(ea.AnchorError) as ctx:
                log.await_publication(7)
            self.assertEqual(ctx.exception.code,
                             "anchor-index-unpublished")

    def test_no_signer_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, _ = self._log(tmp)
            log.add(b"a")
            root = os.path.join(tmp, "log")
            ro = ea.TransparencyLog(root, "test/log", "op-1",
                                    signer_seed=None)
            with self.assertRaises(ea.AnchorError) as ctx:
                ro.await_publication(0)
            self.assertEqual(ctx.exception.code, "anchor-no-signer")

    def test_state_tile_disagreement_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, _ = self._log(tmp)
            log.add(b"a")
            root = os.path.join(tmp, "log")
            with open(os.path.join(root, "state.json"), "w") as fh:
                json.dump({"origin": "test/log", "size": 99}, fh)
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.TransparencyLog(root, "test/log", "op-1")
            self.assertEqual(ctx.exception.code, "anchor-log-corrupt")

    def test_tile_corruption_trips_on_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, _ = self._log(tmp)
            log.add(b"a")
            root = os.path.join(tmp, "log")
            data_dir = os.path.join(root, "tile", "data")
            name = os.listdir(data_dir)[0]
            sub = os.path.join(data_dir, name)
            path = os.path.join(sub, os.listdir(sub)[0]) \
                if os.path.isdir(sub) else sub
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not-hex-at-all\n")
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.TransparencyLog(root, "test/log", "op-1")
            self.assertEqual(ctx.exception.code, "anchor-log-corrupt")

    def test_checkpoint_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub = self._log(tmp)
            for i in range(3):
                log.add(b"e%d" % i)
            cp = log.await_publication(2)
            cp2 = log.checkpoint()
            self.assertEqual(cp2["signed_note"], cp["signed_note"])
            self.assertEqual(cp2["size"], 3)

    def test_proof_against_published_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, pub = self._log(tmp)
            idx = [log.add(b"v%d" % i) for i in range(10)]
            cp = log.await_publication(idx[-1])
            body, sigs = ea.parse_checkpoint(cp["signed_note"])
            for m in (0, 4, 9):
                proof = log.inclusion_proof(m, body["size"])
                leaf = ea._hash_leaf(b"v%d" % m)
                self.assertTrue(ea.verify_inclusion(leaf, proof,
                                                   body["root"]))


class TestAnchorReceipt(unittest.TestCase):
    def test_end_to_end_and_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            digest = hashlib.sha256(b"bundle").hexdigest()
            receipt = ea.anchor(log, digest)
            self.assertEqual(set(receipt),
                             {"bundle_digest", "log_index",
                              "inclusion_proof", "checkpoint_signature",
                              "witness_policy_id"})
            self.assertIs(ea.verify_receipt(
                receipt, log_pubkey=_ed.publickey(seed)), True)

    def test_bad_digest_format_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.anchor(log, "ZZZ")
            self.assertEqual(ctx.exception.code, "anchor-leaf-mismatch")

    def test_anchor_refuses_under_quorum_at_issuance(self):
        # MINOR-1: fail fast -- no dead-on-arrival receipt is minted
        # when fewer than quorum witness seeds are supplied.
        wit, seeds = {}, {}
        for i in range(3):
            seed = _ed.generate_seed()
            pub = _ed.publickey(seed)
            kid = _signing.ed25519_key_id(pub)
            wit[kid] = pub.hex()
            seeds[kid] = seed
        pol = ea.WitnessPolicy("wp-iss", wit, 2)
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.anchor(log, hashlib.sha256(b"x").hexdigest(),
                          witness_policy=pol,
                          witness_seeds=dict(list(seeds.items())[:1]))
            self.assertEqual(ctx.exception.code,
                             "anchor-witness-quorum-failed")

    def test_policy_id_binding_mismatch_refused(self):
        # MINOR-2: receipt claims "none" but the checkpoint names a
        # witness policy -- loud signal even with no policy pinned.
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            digest = hashlib.sha256(b"b").hexdigest()
            idx = log.add(bytes.fromhex(digest))
            cp = log.await_publication(idx)
            cbody, _ = ea.parse_checkpoint(cp["signed_note"])
            evil_body = {"origin": cbody["origin"], "size": cbody["size"],
                         "root": cbody["root"],
                         "timestamp": cbody["timestamp"],
                         "witness_policy_id": "wp-z"}
            canonical = ea._render_body(evil_body).encode("utf-8")
            note = ea.render_checkpoint(evil_body, [
                {"keyid": "op",
                 "sig": _ed.sign(seed, canonical).hex()}])
            receipt = {"bundle_digest": digest, "log_index": idx,
                       "inclusion_proof": log.inclusion_proof(
                           idx, cbody["size"]),
                       "checkpoint_signature": note,
                       "witness_policy_id": "none"}
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.verify_receipt(receipt,
                                  log_pubkey=_ed.publickey(seed))
            self.assertEqual(ctx.exception.code,
                             "anchor-witness-quorum-failed")

    def test_non_dict_proof_coded_refusal(self):
        # MINOR-3: a non-dict inclusion proof is a coded refusal, not a
        # bare AttributeError.
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            receipt = ea.anchor(log,
                                hashlib.sha256(b"x").hexdigest())
            receipt["inclusion_proof"] = ["not", "a", "dict"]
            with self.assertRaises(ea.AnchorError) as ctx:
                ea.verify_receipt(receipt,
                                  log_pubkey=_ed.publickey(seed))
            self.assertEqual(ctx.exception.code,
                             "anchor-inclusion-mismatch")

    def test_graph_composition_bad_log_id(self):
        from gov import guac_graph as gg
        with tempfile.TemporaryDirectory() as tmp:
            seed = _ed.generate_seed()
            log = ea.TransparencyLog(os.path.join(tmp, "log"), "o",
                                     "op", seed)
            receipt = ea.anchor(log, hashlib.sha256(b"x").hexdigest())
            graph = gg.GuacGraph()
            with self.assertRaises(ea.AnchorError):
                ea.record_anchor_in_graph(graph, receipt,
                                          log_id="bad id!")


if __name__ == "__main__":
    unittest.main()
