"""Unit tests for gov.rekor_v2_anchor (wave-207 lane B).

Complements evals/rekor_v2_anchor_probes.py (the red-first battery):
the probes attack the public seams break-first; these tests pin
edge-case behavior and error taxonomy at the same seams.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import rekor_v2_anchor as v2

_CFG = {"log_url": "https://rekor-v2.example-operator.invalid",
        "log_id": "deadbeef" * 8,
        "tsa_url": "https://tsa.example-operator.invalid"}


def _client(**kw):
    kw.setdefault("signing_config", dict(_CFG))
    return v2.HermeticRekorV2(**kw)


def _material(seed_byte=77):
    from gov import anchor_backend as _ab
    from gov import ed25519 as _ed
    seed = bytes([seed_byte]) * 32
    digest = hashlib.sha256(b"artifact-%d" % seed_byte).hexdigest()
    sig = _ed.sign_ph(seed, bytes.fromhex(digest))
    pem = _ab.anchor_spki_pem(_ed.publickey(seed))
    return (digest, base64.b64encode(sig).decode("ascii"), pem)


class TestConstants(unittest.TestCase):
    def test_source_values(self):
        self.assertEqual(v2.SOURCE_V1, "rekor-v1")
        self.assertEqual(v2.SOURCE_V2, "rekor-v2-hermetic")
        self.assertEqual(v2.SOURCE_DUAL, "dual-write")

    def test_entry_type_allowlist(self):
        self.assertEqual(v2.V2_ENTRY_TYPES,
                         frozenset({"hashedrekord", "dsse"}))
        self.assertEqual(v2.TILE_SIZE, 256)


class TestConfigRefusal(unittest.TestCase):
    def test_missing_signing_config_fields(self):
        for cfg in ({}, {"log_url": "x"},
                    {"log_url": "x", "log_id": "y"}):
            with self.assertRaises(v2.V2ConfigError):
                v2.HermeticRekorV2(signing_config=cfg)

    def test_non_mapping_config(self):
        with self.assertRaises(v2.V2ConfigError):
            v2.HermeticRekorV2(signing_config=None)

    def test_production_url_refused(self):
        cfg = dict(_CFG, log_url="https://rekor.sigstore.dev/")
        with self.assertRaises(v2.V2ConfigError):
            v2.HermeticRekorV2(signing_config=cfg)

    def test_production_log_id_refused(self):
        cfg = dict(_CFG, log_id="c0d23d6ad406973f9559f3ba1d1ca01f84147d"
                               "8ffc5b8445c2249c2cc77d6cd9d69")
        with self.assertRaises(v2.V2ConfigError):
            v2.HermeticRekorV2(signing_config=cfg)


class TestEntryTypeRefusal(unittest.TestCase):
    def test_v1_only_types_refused(self):
        c = _client()
        for bad in ("rekord", "intoto", "helm", "tuf", "rfc3161",
                    "jar", "rpm", "cose", "alpine", "", None):
            with self.assertRaises(v2.V2ConfigError,
                                   msg="type %r" % (bad,)):
                c.submit(bad, b"x")


class TestHashedrekordSubmit(unittest.TestCase):
    def setUp(self):
        self.c = _client()
        self.digest, self.sig, self.pem = _material()

    def test_receipt_shape(self):
        r = self.c.submit_hashedrekord(self.digest,
                                       signature_b64=self.sig,
                                       pubkey_pem=self.pem)
        self.assertEqual(r["verification.source"], "rekor-v2-hermetic")
        self.assertEqual(r["entry_type"], "hashedrekord")
        self.assertEqual(r["anchor_hash"], self.digest)
        self.assertEqual(r["evidentiary_grade"], "digest-existence-only")
        self.assertFalse(r["authority_proof"])
        # timestamps are separate from the proof
        self.assertIn("tsa", r)
        self.assertTrue(r["tsa"]["hermetic"])
        self.assertNotIn("tsa", json.dumps(r["inclusion"]))

    def test_digestref_accepted(self):
        from gov.digest_ref import DigestRef
        ref = DigestRef.from_hex(self.digest)
        r = self.c.submit_hashedrekord(ref, signature_b64=self.sig,
                                       pubkey_pem=self.pem)
        self.assertEqual(r["anchor_hash"], self.digest)

    def test_raw_ed25519_refused(self):
        with self.assertRaises(v2.V2ConfigError):
            self.c.submit_hashedrekord(self.digest,
                                       signature_b64=self.sig,
                                       pubkey_pem=self.pem,
                                       algorithm="ed25519")

    def test_bad_anchor_hash_refused(self):
        for bad in ("zz" * 32, "ab" * 31, "", None, 123):
            with self.assertRaises(v2.V2ConfigError, msg=str(bad)):
                self.c.submit_hashedrekord(bad, signature_b64=self.sig,
                                           pubkey_pem=self.pem)

    def test_bad_signature_b64_refused(self):
        with self.assertRaises(v2.V2ConfigError):
            self.c.submit_hashedrekord(self.digest,
                                       signature_b64="not-base64!!!",
                                       pubkey_pem=self.pem)

    def test_non_pem_pubkey_refused(self):
        with self.assertRaises(v2.V2ConfigError):
            self.c.submit_hashedrekord(self.digest,
                                       signature_b64=self.sig,
                                       pubkey_pem="not a pem")

    def test_resubmit_is_idempotent(self):
        r1 = self.c.submit_hashedrekord(self.digest,
                                        signature_b64=self.sig,
                                        pubkey_pem=self.pem)
        r2 = self.c.submit_hashedrekord(self.digest,
                                        signature_b64=self.sig,
                                        pubkey_pem=self.pem)
        self.assertEqual(r1["uuid"], r2["uuid"])
        self.assertEqual(r1["log_index"], r2["log_index"])


class TestDsseSubmit(unittest.TestCase):
    def _envelope(self):
        from gov import dsse_envelope as dsse
        from gov.signing import Ed25519Signer
        return dsse.seal(b"payload", "application/vnd.in-toto+json",
                         [Ed25519Signer(bytes([9]) * 32)])

    def test_dsse_receipt(self):
        c = _client()
        r = c.submit_dsse(self._envelope())
        self.assertEqual(r["verification.source"], "rekor-v2-hermetic")
        self.assertEqual(r["entry_type"], "dsse")
        self.assertEqual(r["payload_type"],
                         "application/vnd.in-toto+json")
        self.assertEqual(r["payload_sha256"],
                         hashlib.sha256(b"payload").hexdigest())

    def test_malformed_envelope_refused(self):
        c = _client()
        for bad in (None, "x", {"payload": "eA=="},
                    dict(self._envelope(), extra_field=1)):
            with self.assertRaises(v2.V2ConfigError):
                c.submit_dsse(bad)

    def test_dsse_roundtrip_verifies(self):
        c = _client()
        r = c.submit_dsse(self._envelope())
        entry_bytes = c.entry_bytes_for_receipt(r)
        self.assertTrue(c.verify_inclusion(r, entry_bytes))


class TestInclusion(unittest.TestCase):
    def setUp(self):
        self.c = _client()
        self.digest, self.sig, self.pem = _material()

    def _submit(self):
        return self.c.submit_hashedrekord(self.digest,
                                          signature_b64=self.sig,
                                          pubkey_pem=self.pem)

    def test_verify_ok(self):
        r = self._submit()
        self.assertTrue(
            self.c.verify_inclusion(r,
                                    self.c.entry_bytes_for_receipt(r)))

    def test_tampered_entry_fails(self):
        r = self._submit()
        with self.assertRaises(v2.V2AnchorError):
            self.c.verify_inclusion(r, b"tampered-bytes")

    def test_flipped_proof_sibling_fails(self):
        r = self._submit()
        # grow the tree so the proof has at least one sibling
        d2, s2, _ = _material(seed_byte=78)
        self.c.submit_hashedrekord(d2, signature_b64=s2,
                                   pubkey_pem=self.pem)
        r2 = self.c.submit_hashedrekord(
            d2, signature_b64=s2, pubkey_pem=self.pem)
        bad = dict(r2)
        inc = dict(bad["inclusion"])
        inc["hashes"] = ["ff" * 32 for _ in inc["hashes"]]
        bad["inclusion"] = inc
        with self.assertRaises(v2.V2AnchorError):
            self.c.verify_inclusion(
                bad, self.c.entry_bytes_for_receipt(r2))

    def test_stale_proof_refused_after_growth(self):
        r = self._submit()
        entry_bytes = self.c.entry_bytes_for_receipt(r)
        self.assertTrue(self.c.verify_inclusion(r, entry_bytes))
        d2, s2, _ = _material(seed_byte=78)
        self.c.submit_hashedrekord(d2, signature_b64=s2,
                                   pubkey_pem=self.pem)
        with self.assertRaises(v2.V2AnchorError):
            self.c.verify_inclusion(r, entry_bytes)

    def test_wrong_source_refused(self):
        r = self._submit()
        bad = dict(r)
        bad["verification.source"] = "rekor-v1"
        with self.assertRaises(v2.V2AnchorError):
            self.c.verify_inclusion(
                bad, self.c.entry_bytes_for_receipt(r))

    def test_tsa_not_consulted(self):
        # The TSA token is carried evidence, not proof input:
        # corrupting it must not change the verify outcome.
        r = self._submit()
        entry_bytes = self.c.entry_bytes_for_receipt(r)
        bad = dict(r)
        bad["tsa"] = {"hermetic": True, "signed_time": "forged"}
        self.assertTrue(self.c.verify_inclusion(bad, entry_bytes))


class TestOddTreeInclusion(unittest.TestCase):
    """F205 regression: inclusion proofs for promoted leaves on
    odd-sized trees must recompute to the receipt's root.

    The pre-fix _verify_proof used index parity alone and never
    modeled RFC 6962 leaf promotion, so every proof for a promoted
    leaf (leaf 2 of 3, leaf 4 of 5, ...) failed with "proof does not
    recompute to the receipt's root".
    """

    def test_every_leaf_every_size_to_nine(self):
        # White-box property test: _verify_proof must agree with
        # _inclusion_proof/_root for every leaf of every tree size.
        for n in range(1, 10):
            leaves = [v2._leaf(b"leaf-%d" % i) for i in range(n)]
            root = v2._root(leaves)
            for idx in range(n):
                # _inclusion_proof yields raw bytes (the tile log hexlifies).
                proof = [bytes(h) for h in v2._inclusion_proof(leaves, idx)]
                recomputed = v2._verify_proof(leaves[idx], idx, proof, n)
                self.assertEqual(
                    recomputed, root,
                    "leaf %d of %d does not recompute" % (idx, n))

    def test_verify_inclusion_odd_tree_public_seam(self):
        # Public seam: the last-issued receipt always commits to the
        # current root, so it must verify at every odd tree size.
        c = _client()
        digest, sig, pem = _material()
        for i in range(7):
            d, s, _ = _material(seed_byte=80 + i)
            r = c.submit_hashedrekord(d, signature_b64=s,
                                      pubkey_pem=pem)
            self.assertTrue(
                c.verify_inclusion(r, c.entry_bytes_for_receipt(r)),
                "receipt %d (tree size %d) failed to verify" % (i, i + 1))

    def test_short_proof_refused(self):
        leaves = [v2._leaf(b"leaf-%d" % i) for i in range(4)]
        proof = [bytes(h) for h in v2._inclusion_proof(leaves, 0)]
        with self.assertRaises(ValueError):
            v2._verify_proof(leaves[0], 0, proof[:-1], 4)

    def test_extra_proof_hash_refused(self):
        leaves = [v2._leaf(b"leaf-%d" % i) for i in range(4)]
        proof = [bytes(h) for h in v2._inclusion_proof(leaves, 0)]
        with self.assertRaises(ValueError):
            v2._verify_proof(leaves[0], 0, proof + [b"\x00" * 32], 4)


class TestLocalIndex(unittest.TestCase):
    def test_record_lookup_miss(self):
        idx = v2.V2LocalIndex()
        self.assertIsNone(idx.lookup("ab" * 32))

    def test_record_and_lookup(self):
        idx = v2.V2LocalIndex()
        idx.record("ab" * 32, {"uuid": "u1"})
        hit = idx.lookup("ab" * 32)
        self.assertEqual(hit["uuid"], "u1")

    def test_jsonl_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "index.jsonl")
            idx = v2.V2LocalIndex(path=path)
            idx.record("ab" * 32, {"uuid": "u1"})
            idx2 = v2.V2LocalIndex(path=path)
            self.assertEqual(idx2.lookup("ab" * 32)["uuid"], "u1")

    def test_corrupt_index_file_refused(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "index.jsonl")
            with open(path, "w") as fh:
                fh.write("not json\n")
            with self.assertRaises(v2.V2ConfigError):
                v2.V2LocalIndex(path=path)


class TestDualWriteFlag(unittest.TestCase):
    def setUp(self):
        os.environ.pop("GOV_REKOR_V2_DUAL_WRITE", None)

    def tearDown(self):
        os.environ.pop("GOV_REKOR_V2_DUAL_WRITE", None)

    def test_default_is_off(self):
        self.assertFalse(v2.dual_write_enabled())

    def test_explicit_wins(self):
        os.environ["GOV_REKOR_V2_DUAL_WRITE"] = "1"
        self.assertTrue(v2.dual_write_enabled(True))
        self.assertFalse(v2.dual_write_enabled(False))

    def test_env_enables(self):
        for val in ("1", "true", "TRUE", "yes"):
            os.environ["GOV_REKOR_V2_DUAL_WRITE"] = val
            self.assertTrue(v2.dual_write_enabled(), msg=val)
        os.environ["GOV_REKOR_V2_DUAL_WRITE"] = "0"
        self.assertFalse(v2.dual_write_enabled())


def _fake_v1(receipts):
    def submit(anchor_hash, *, signature_b64, pubkey_pem,
               algorithm):
        r = {"backend": "rekor-v1", "uuid": "v1-%d" % len(receipts),
             "anchor_hash": anchor_hash}
        receipts.append(r)
        return r
    return submit


class TestDualWriteAnchor(unittest.TestCase):
    def setUp(self):
        os.environ.pop("GOV_REKOR_V2_DUAL_WRITE", None)
        self.digest, self.sig, self.pem = _material()
        self.receipts = []

    def tearDown(self):
        os.environ.pop("GOV_REKOR_V2_DUAL_WRITE", None)

    def _anchor(self, **kw):
        return v2.DualWriteAnchor(
            v1_submit=_fake_v1(self.receipts), v2_client=_client(),
            **kw)

    def test_default_is_v1_only(self):
        a = self._anchor()
        self.assertFalse(a.dual_write)
        r = a.anchor(self.digest, signature_b64=self.sig,
                     pubkey_pem=self.pem)
        self.assertEqual(r["verification.source"], "rekor-v1")
        self.assertNotIn("entries", r)
        blob = json.dumps(r, sort_keys=True)
        self.assertNotIn("rekor-v2", blob)
        # the v1 receipt itself is unchanged apart from the stamp
        self.assertEqual(r["anchor_hash"], self.digest)
        self.assertEqual(r["backend"], "rekor-v1")

    def test_dual_write_carries_both(self):
        a = self._anchor(dual_write=True)
        r = a.anchor(self.digest, signature_b64=self.sig,
                     pubkey_pem=self.pem)
        self.assertEqual(r["verification.source"], "dual-write")
        self.assertEqual(
            r["entries"]["rekor-v1"]["verification.source"],
            "rekor-v1")
        self.assertEqual(
            r["entries"]["rekor-v2-hermetic"]["verification.source"],
            "rekor-v2-hermetic")
        self.assertEqual(r["entries"]["rekor-v1"]["anchor_hash"],
                         self.digest)

    def test_dual_write_via_env(self):
        os.environ["GOV_REKOR_V2_DUAL_WRITE"] = "1"
        a = self._anchor()
        self.assertTrue(a.dual_write)

    def test_dual_without_v2_client_refused(self):
        with self.assertRaises(v2.V2ConfigError):
            v2.DualWriteAnchor(v1_submit=_fake_v1(self.receipts),
                               dual_write=True)

    def test_dual_write_dsse_envelope(self):
        from gov import dsse_envelope as dsse
        from gov.signing import Ed25519Signer
        env = dsse.seal(b"p", "t", [Ed25519Signer(bytes([3]) * 32)])
        a = self._anchor(dual_write=True)
        r = a.anchor(self.digest, signature_b64=self.sig,
                     pubkey_pem=self.pem, dsse_envelope=env)
        self.assertEqual(
            r["entries"]["rekor-v2-hermetic"]["entry_type"], "dsse")


if __name__ == "__main__":
    unittest.main()
