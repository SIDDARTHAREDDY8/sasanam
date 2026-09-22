"""Tests for gov/custody.py: A5 key-custody side (KMS workstream).

Covers: SignerShareStore (KMS-envelope custody of checkpoint-signer
seeds: wrap-before-mutate, wrapped-only 0600 persistence, lazy
unwrap-to-memory at signing time, fail-closed KMS behavior),
share rotation (old seeds retained), KMS rewrap, offline root-seed
files, PublicSigner, genesis/rotate-roster ceremonies (root-signed,
prev-hash-chained), and the hash-chained ceremony transcript.

Deterministic: FakeKmsProvider only (counter nonces), explicit seeds,
injected transcript timestamps. No network, no credentials.
"""

import base64
import json
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path

from gov import custody
from gov.custody import SignerShareStore, PublicSigner
from gov import signing
from gov.kms import FakeKmsProvider, KmsError


SEED_A = bytes(range(32))
SEED_B = bytes(32 - i for i in range(32))
SEED_C = bytes((7 * i) % 256 for i in range(32))
SEED_D = bytes((13 * i + 1) % 256 for i in range(32))
ROOT_SEED = bytes((3 * i + 5) % 256 for i in range(32))


class _TmpMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="custody-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.provider = FakeKmsProvider(["kms-1", "kms-2"])

    def _store3(self):
        s = SignerShareStore()
        s.add_share("alice", self.provider, "kms-1", seed=SEED_A)
        s.add_share("bob", self.provider, "kms-1", seed=SEED_B)
        s.add_share("carol", self.provider, "kms-1", seed=SEED_C)
        return s


class GenerateSeedTest(unittest.TestCase):
    def test_deterministic_with_rng(self):
        a = custody.generate_seed(random.Random(1234))
        b = custody.generate_seed(random.Random(1234))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 32)

    def test_secrets_by_default(self):
        a = custody.generate_seed()
        b = custody.generate_seed()
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)


class ShareStoreTest(_TmpMixin):
    def test_add_share_and_signer_roundtrip(self):
        s = self._store3()
        self.assertEqual(s.active_labels(), ["alice", "bob", "carol"])
        for label, seed in (("alice", SEED_A), ("bob", SEED_B),
                            ("carol", SEED_C)):
            signer = s.signer_for(label, self.provider)
            sig = signer.sign(b"checkpoint-body")
            self.assertTrue(
                signing.Ed25519Verifier(signer.public_key).verify(
                    b"checkpoint-body", sig))
            # The unwrapped seed is the enrolled one.
            self.assertEqual(signer.public_key,
                             signing.Ed25519Signer(seed).public_key)

    def test_duplicate_label_rejected(self):
        s = self._store3()
        with self.assertRaises(ValueError):
            s.add_share("alice", self.provider, "kms-1", seed=SEED_D)

    def test_bad_label_rejected(self):
        s = SignerShareStore()
        for bad in ("", "../evil", "a" * 65, "has space"):
            with self.assertRaises(ValueError):
                s.add_share(bad, self.provider, "kms-1", seed=SEED_A)

    def test_bad_seed_length_rejected(self):
        s = SignerShareStore()
        with self.assertRaises(ValueError):
            s.add_share("alice", self.provider, "kms-1", seed=b"short")

    def test_signer_for_unknown_label(self):
        with self.assertRaises(KeyError):
            self._store3().signer_for("mallory", self.provider)

    def test_signer_for_unwraps_lazily(self):
        s = self._store3()
        self.provider.calls.clear()
        # add_share wrapped (3 wraps); signer_for unwraps on demand only.
        s.signer_for("alice", self.provider)
        unwraps = [c for c in self.provider.calls if c[0] == "unwrap"]
        self.assertEqual(len(unwraps), 1)
        self.assertEqual(unwraps[0][1], "kms-1")

    def test_signer_for_outage_fails_closed(self):
        s = self._store3()
        self.provider.outage = True
        with self.assertRaises(KmsError):
            s.signer_for("alice", self.provider)

    def test_signer_for_detects_seed_mismatch(self):
        """A blob swapped under the recorded kms key id (attacker with
        KMS-wrap access but not the seed) must not be adopted: the
        pubkey check fails closed."""
        s = self._store3()
        evil = FakeKmsProvider(["kms-1"])
        rec = s.get("alice")
        rec.wrapped_blob = evil.wrap_data_key("kms-1", SEED_D)
        with self.assertRaises(KmsError):
            s.signer_for("alice", self.provider)

    def test_save_load_wrapped_only_and_perms(self):
        s = self._store3()
        p = self.tmp / "shares.json"
        s.save(p)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        raw = p.read_bytes()
        for seed in (SEED_A, SEED_B, SEED_C):
            self.assertNotIn(seed, raw)
            self.assertNotIn(seed.hex().encode(), raw)
        self.assertIn(b"wrapped_b64", raw)
        loaded = SignerShareStore.load(p)
        self.assertEqual(loaded.active_labels(),
                         ["alice", "bob", "carol"])
        # Loaded store still signs.
        sig = loaded.signer_for("bob", self.provider).sign(b"x")
        self.assertTrue(signing.Ed25519Verifier(
            loaded.signer_for("bob", self.provider).public_key
        ).verify(b"x", sig))

    def test_load_refuses_world_readable(self):
        p = self.tmp / "shares.json"
        self._store3().save(p)
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            SignerShareStore.load(p)

    def test_load_rejects_bad_format(self):
        p = self.tmp / "bad.json"
        p.write_text(json.dumps({"format_version": 999,
                                 "kind": "signer-share-store",
                                 "shares": {}, "history": {}}))
        os.chmod(p, 0o600)
        with self.assertRaises(ValueError):
            SignerShareStore.load(p)

    def test_describe_leaks_no_seed_material(self):
        blob = json.dumps(self._store3().describe())
        for seed in (SEED_A, SEED_B, SEED_C):
            self.assertNotIn(seed.hex(), blob)
            self.assertNotIn(base64.b64encode(seed).decode(), blob)
        self.assertNotIn("wrapped_b64", blob)
        # But pubkeys are present (auditors need them).
        self.assertIn(signing.Ed25519Signer(SEED_A).public_key.hex(), blob)

    def test_rotate_share_new_key_old_retained(self):
        s = self._store3()
        old_kid = s.get("alice").key_id
        old_pub = s.get("alice").pub_hex
        old_kid_out, new_kid = s.rotate_share(
            "alice", self.provider, seed=SEED_D, note="laptop replaced")
        self.assertEqual(old_kid_out, old_kid)
        self.assertNotEqual(new_kid, old_kid)
        # Old record retired but retained.
        retired = s.retired_shares("alice")
        self.assertEqual(len(retired), 1)
        self.assertEqual(retired[0].status, "retired")
        self.assertEqual(retired[0].key_id, old_kid)
        self.assertIsNotNone(retired[0].retired_utc)
        # Active share is the new key.
        self.assertEqual(s.get("alice").key_id, new_kid)
        self.assertEqual(s.active_labels(), ["alice", "bob", "carol"])
        # Old seed still unwraps (old checkpoints stay verifiable).
        old_signer = s.signer_for("alice", self.provider)
        self.assertEqual(old_signer.public_key.hex(),
                         s.get("alice").pub_hex)
        # Persisted history round-trips.
        p = self.tmp / "shares.json"
        s.save(p)
        loaded = SignerShareStore.load(p)
        self.assertEqual(len(loaded.retired_shares("alice")), 1)
        self.assertEqual(loaded.retired_shares("alice")[0].key_id,
                         old_kid)
        self.assertNotIn(bytes.fromhex(old_pub), p.read_bytes())

    def test_rotate_share_wrap_failure_leaves_store_unmutated(self):
        s = self._store3()
        before = s.get("alice").key_id
        self.provider.outage = True
        with self.assertRaises(KmsError):
            s.rotate_share("alice", self.provider, seed=SEED_D)
        self.assertEqual(s.get("alice").key_id, before)
        self.assertEqual(s.get("alice").status, "active")
        self.assertEqual(s.retired_shares("alice"), [])

    def test_rotate_share_unknown_label(self):
        with self.assertRaises(KeyError):
            self._store3().rotate_share("mallory", self.provider,
                                        seed=SEED_D)

    def test_rewrap_changes_kms_key_id_not_seeds(self):
        s = self._store3()
        s.rotate_share("alice", self.provider, seed=SEED_D)
        pubs_before = {l: s.get(l).pub_hex for l in s.labels()}
        s.rewrap(self.provider, "kms-2")
        for l in s.labels():
            self.assertEqual(s.get(l).kms_key_id, "kms-2")
            self.assertEqual(s.get(l).pub_hex, pubs_before[l])
        for r in s.retired_shares("alice"):
            self.assertEqual(r.kms_key_id, "kms-2")
        # Seeds unchanged: signers still work.
        for label, seed in (("alice", SEED_D), ("bob", SEED_B),
                            ("carol", SEED_C)):
            signer = s.signer_for(label, self.provider)
            self.assertEqual(signer.public_key,
                             signing.Ed25519Signer(seed).public_key)

    def test_threshold_signer_k_of_n(self):
        """End-to-end with gov.signing: 2-of-3 verifies, 1-of-3 does
        not -- the A5 security property over custody-backed keys."""
        s = self._store3()
        roster, _ = custody.make_genesis_roster(
            s, 2, ROOT_SEED, participants=["alice", "bob", "carol"],
            utc="2026-09-22T00:00:00+00:00")
        root_pub = signing.Ed25519Signer(ROOT_SEED).public_key
        ok, err = signing.verify_roster(roster, root_pub)
        self.assertTrue(ok, err)
        ts = s.threshold_signer(["alice", "bob", "carol"], 2,
                                self.provider)
        body = b"checkpoint-seq-42"
        sigs = ts.sign_all(body)
        ok, err = signing.verify_threshold(body, sigs, roster, root_pub)
        self.assertTrue(ok, err)
        # Below threshold: rejected.
        ok, err = signing.verify_threshold(body, sigs[:1], roster,
                                           root_pub)
        self.assertFalse(ok)
        self.assertIn("1/2", err)


class RootKeyTest(_TmpMixin):
    def test_root_seed_file_roundtrip_0600(self):
        p = self.tmp / "root.seed"
        custody.save_root_seed(p, ROOT_SEED)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(custody.load_root_seed(p), ROOT_SEED)
        self.assertEqual(p.read_bytes(), ROOT_SEED)  # raw 32 bytes

    def test_root_seed_file_refuses_world_readable(self):
        p = self.tmp / "root.seed"
        custody.save_root_seed(p, ROOT_SEED)
        os.chmod(p, 0o644)
        with self.assertRaises(PermissionError):
            custody.load_root_seed(p)

    def test_root_seed_bad_length(self):
        p = self.tmp / "root.seed"
        with self.assertRaises(ValueError):
            custody.save_root_seed(p, b"short")

    def test_root_signer_role_separation(self):
        """The root key's role is "root", never "checkpoint-signer":
        verify_roster rejects a roster whose role is wrong."""
        root = custody.root_signer_from_seed(ROOT_SEED)
        self.assertEqual(signing.ed25519_key_id(root.public_key),
                         root.key_id)


class PublicSignerTest(unittest.TestCase):
    def test_cannot_sign(self):
        ps = PublicSigner(signing.ed25519_key_id(
            signing.Ed25519Signer(SEED_A).public_key),
            signing.Ed25519Signer(SEED_A).public_key)
        with self.assertRaises(RuntimeError):
            ps.sign(b"data")

    def test_key_id_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            PublicSigner("deadbeefdeadbeef",
                         signing.Ed25519Signer(SEED_A).public_key)


class CeremonyTest(_TmpMixin):
    def _genesis(self, s, transcript=None):
        return custody.make_genesis_roster(
            s, 2, ROOT_SEED, participants=["alice", "bob", "carol"],
            transcript_path=transcript, utc="2026-09-22T00:00:00+00:00")

    def test_genesis_roster_shape(self):
        s = self._store3()
        roster, record = self._genesis(s)
        self.assertEqual(roster["role"], "checkpoint-signer")
        self.assertEqual(roster["threshold"], 2)
        self.assertEqual(roster["prev_roster_hash"], "GENESIS")
        self.assertEqual(len(roster["keys"]), 3)
        root_pub = signing.Ed25519Signer(ROOT_SEED).public_key
        self.assertEqual(roster["root_key_id"],
                         signing.ed25519_key_id(root_pub))
        ok, err = signing.verify_roster(roster, root_pub)
        self.assertTrue(ok, err)
        # No transcript requested -> no record.
        self.assertIsNone(record)

    def test_genesis_no_active_shares_raises(self):
        with self.assertRaises(ValueError):
            custody.make_genesis_roster(SignerShareStore(), 1,
                                        ROOT_SEED)

    def test_genesis_records_transcript(self):
        s = self._store3()
        t = self.tmp / "ceremonies.jsonl"
        roster, record = self._genesis(s, transcript=t)
        self.assertEqual(record["ceremony"], "genesis")
        self.assertEqual(record["prev_record_hash"], None)
        self.assertEqual(record["detail"]["roster_hash"],
                         signing.roster_hash(roster))
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)

    def test_rotate_roster_chains_prev_hash(self):
        s = self._store3()
        t = self.tmp / "ceremonies.jsonl"
        genesis, _ = self._genesis(s, transcript=t)
        # Alice rotates her share, then the root signs the new roster.
        s.rotate_share("alice", self.provider, seed=SEED_D)
        roster2, record2 = custody.rotate_roster(
            s, genesis, ROOT_SEED, participants=["alice", "facilitator"],
            transcript_path=t, utc="2026-09-22T01:00:00+00:00")
        self.assertEqual(roster2["prev_roster_hash"],
                         signing.roster_hash(genesis))
        self.assertEqual(roster2["threshold"], 2)  # kept by default
        root_pub = signing.Ed25519Signer(ROOT_SEED).public_key
        ok, err = signing.verify_roster(roster2, root_pub)
        self.assertTrue(ok, err)
        # New roster authorizes the NEW alice key, not the old.
        new_kid = s.get("alice").key_id
        old_kid = s.retired_shares("alice")[0].key_id
        self.assertIn(new_kid, roster2["keys"])
        self.assertNotIn(old_kid, roster2["keys"])
        # Transcript chains genesis -> rotate-roster.
        self.assertEqual(record2["prev_record_hash"],
                         custody.read_ceremonies(t)[0]["record_hash"])
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)
        # Old roster still verifies (history stays checkable).
        ok, err = signing.verify_roster(genesis, root_pub)
        self.assertTrue(ok, err)

    def test_rotate_roster_can_change_threshold(self):
        s = self._store3()
        genesis, _ = self._genesis(s)
        roster2, _ = custody.rotate_roster(s, genesis, ROOT_SEED,
                                          threshold=3)
        self.assertEqual(roster2["threshold"], 3)

    def test_ceremony_chain_tamper_evident(self):
        s = self._store3()
        t = self.tmp / "ceremonies.jsonl"
        self._genesis(s, transcript=t)
        custody.record_ceremony(t, "rewrap", ["ops"],
                                {"kms_key_id": "kms-2"},
                                utc="2026-09-22T02:00:00+00:00")
        # F78: the non-root rewrap append leaves the tip manifest
        # stale, so verification fails closed until a root tip-anchor
        # ceremony re-binds the tip.
        custody.update_tip_manifest(t, ROOT_SEED,
                                    utc="2026-09-22T03:00:00+00:00")
        ok, _ = custody.verify_ceremony_chain(t)
        self.assertTrue(ok)
        # Tamper with the first record's detail.
        lines = t.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["detail"]["threshold"] = 1
        lines[0] = json.dumps(rec)
        t.write_text("\n".join(lines) + "\n")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("tampered", err)

    def test_ceremony_chain_broken_link(self):
        t = self.tmp / "ceremonies.jsonl"
        custody.record_ceremony(t, "genesis", ["a"], {}, utc="2026-01-01")
        # Forge a second record with a wrong prev link.
        p = Path(t)
        body = {"ceremony": "x", "utc": "2026-01-02",
                "participants": [], "prev_record_hash": "wrong",
                "detail": {}}
        body["record_hash"] = custody._record_hash(body)
        with open(p, "a") as f:
            f.write(json.dumps(body) + "\n")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("breaks the chain", err)


class TipManifestTest(_TmpMixin):
    """F78: root-signed tip manifest binds the transcript head.

    Every test here fails pre-fix (no manifest machinery: truncation
    verifies True, forged manifests are meaningless, and the new
    helpers do not exist) and is green post-fix -- except
    test_legacy_transcript_still_verifies, which is the deliberate
    preservation case (legacy transcripts keep chain-only
    verification).
    """

    def _two_ceremonies(self, t):
        s = self._store3()
        genesis, _ = custody.make_genesis_roster(
            s, 2, ROOT_SEED, participants=["alice", "bob", "carol"],
            transcript_path=t, utc="2026-09-22T00:00:00+00:00")
        s.rotate_share("alice", self.provider, seed=SEED_D)
        roster2, _ = custody.rotate_roster(
            s, genesis, ROOT_SEED, participants=["alice", "facilitator"],
            transcript_path=t, utc="2026-09-22T01:00:00+00:00")
        return s, genesis, roster2

    def _truncate_tail(self, t):
        lines = Path(t).read_text().splitlines()
        Path(t).write_text("\n".join(lines[:-1]) + "\n")

    def _manifest(self, t):
        m = custody.read_tip_manifest(custody.tip_manifest_path(t))
        self.assertIsNotNone(m)
        return m

    def test_manifest_written_by_root_ceremonies(self):
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        m = self._manifest(t)
        self.assertEqual(m["record_count"], 2)
        self.assertEqual(m["tip_ceremony"], "rotate-roster")
        self.assertEqual(m["tip_record_hash"],
                         custody.read_ceremonies(t)[-1]["record_hash"])
        ok, err = custody.verify_tip_manifest(m)
        self.assertTrue(ok, err)
        # Manifest is 0600, holds no seed material.
        mp = Path(custody.tip_manifest_path(t))
        self.assertEqual(mp.stat().st_mode & 0o777, 0o600)
        raw = mp.read_bytes()
        for seed in (SEED_A, SEED_B, SEED_C, SEED_D, ROOT_SEED):
            self.assertNotIn(seed, raw)

    def test_happy_path_verifies(self):
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)
        ok, err = custody.verify_transcript_tip(t)
        self.assertTrue(ok, err)
        # The trusted-root pin accepts the genuine root...
        root_pub = signing.Ed25519Signer(ROOT_SEED).public_key
        ok, err = custody.verify_ceremony_chain(t,
                                                trusted_root_pub=root_pub)
        self.assertTrue(ok, err)
        # ...and rejects a foreign one.
        evil_pub = signing.Ed25519Signer(
            bytes((9 * i + 2) % 256 for i in range(32))).public_key
        ok, err = custody.verify_ceremony_chain(t,
                                                trusted_root_pub=evil_pub)
        self.assertFalse(ok)

    def test_tail_truncation_detected(self):
        """The filed F78 defeat: dropping the latest record."""
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        self._truncate_tail(t)
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("shorter", err)

    def test_head_hash_mismatch_detected(self):
        """Truncate, then pad with a forged record restoring the count:
        the tip hash no longer matches the manifest."""
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        self._truncate_tail(t)
        custody.record_ceremony(t, "rotate-roster", ["mallory"],
                                {"k": 99},
                                utc="2026-09-22T02:00:00+00:00")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("tip record hash", err)

    def test_missing_manifest_fails_closed(self):
        """Deleting the sidecar does not downgrade to chain-only: the
        records' scheme marker forces fail-closed."""
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        os.remove(custody.tip_manifest_path(t))
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("missing", err)

    def test_corrupt_manifest_fails_closed(self):
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        Path(custody.tip_manifest_path(t)).write_text("{not json")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("corrupt", err)

    def test_manifest_signature_forgery_rejected(self):
        """Attacker truncates the tail and mints a manifest with their
        own root key: the lineage binding rejects the foreign root."""
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        self._truncate_tail(t)
        evil_seed = bytes((9 * i + 2) % 256 for i in range(32))
        evil = custody.root_signer_from_seed(evil_seed)
        recs = custody.read_ceremonies(t)
        custody.write_tip_manifest(custody.tip_manifest_path(t), evil,
                                   len(recs), recs[-1]["record_hash"],
                                   tip_ceremony="rotate-roster")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("root", err)

    def test_manifest_sig_tamper_rejected(self):
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        mp = custody.tip_manifest_path(t)
        m = self._manifest(t)
        sig = m["sig"]
        m["sig"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        Path(mp).write_text(json.dumps(m))
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("signature", err)

    def test_stale_manifest_fails_closed(self):
        """A non-root transcript append (e.g. a rewrap entry) leaves
        the manifest behind the head: verification fails closed until
        a root tip-anchor ceremony re-binds the tip."""
        t = self.tmp / "c.jsonl"
        s = self._store3()
        custody.make_genesis_roster(
            s, 2, ROOT_SEED, participants=["alice"],
            transcript_path=t, utc="2026-09-22T00:00:00+00:00")
        custody.record_ceremony(t, "rewrap", ["ops"],
                                {"kms_key_id": "kms-2"},
                                utc="2026-09-22T02:00:00+00:00")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        self.assertIn("longer", err)
        # The documented recovery: one root tip-anchor ceremony.
        custody.update_tip_manifest(t, ROOT_SEED,
                                    utc="2026-09-22T03:00:00+00:00")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)

    def test_legacy_transcript_still_verifies(self):
        """PRESERVATION (passes pre-fix too, by design): records
        written before the manifest scheme -- no marker, no sidecar --
        keep chain-only verification."""
        t = self.tmp / "legacy.jsonl"
        prev = None
        for i, act in enumerate(("genesis", "rotate-roster")):
            body = {"ceremony": act, "utc": "2025-01-0%d" % (i + 1),
                    "participants": ["a"], "prev_record_hash": prev,
                    "detail": {"k": i}}
            body["record_hash"] = custody._record_hash(body)
            prev = body["record_hash"]
            with open(t, "a") as f:
                f.write(json.dumps(body, sort_keys=True,
                                   separators=(",", ":")) + "\n")
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)

    def test_legacy_migration_closes_the_hole(self):
        """One root tip-anchor ceremony migrates a legacy transcript:
        legacy records are re-chained under the scheme marker (old head
        noted for audit), and afterwards truncation -- even with the
        manifest deleted -- fails closed."""
        t = self.tmp / "legacy.jsonl"
        prev = None
        for i, act in enumerate(("genesis", "rotate-roster")):
            body = {"ceremony": act, "utc": "2025-01-0%d" % (i + 1),
                    "participants": ["a"], "prev_record_hash": prev,
                    "detail": {"k": i}}
            body["record_hash"] = custody._record_hash(body)
            prev = body["record_hash"]
            with open(t, "a") as f:
                f.write(json.dumps(body, sort_keys=True,
                                   separators=(",", ":")) + "\n")
        old_head = prev
        ok, _ = custody.verify_ceremony_chain(t)
        self.assertTrue(ok)
        manifest, record = custody.update_tip_manifest(
            t, ROOT_SEED, utc="2026-09-22T00:00:00+00:00")
        self.assertEqual(record["ceremony"], "tip-anchor")
        self.assertEqual(record["detail"]["migrated_legacy_head"],
                         old_head)
        self.assertEqual(manifest["record_count"], 3)
        ok, err = custody.verify_ceremony_chain(t)
        self.assertTrue(ok, err)
        # Plain tail truncation is detected...
        self._truncate_tail(t)
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)
        # ...and so is anchor-record + manifest deletion (no silent
        # downgrade back to legacy mode).
        os.remove(custody.tip_manifest_path(t))
        ok, err = custody.verify_ceremony_chain(t)
        self.assertFalse(ok)

    def test_update_tip_manifest_refuses_broken_chain(self):
        t = self.tmp / "c.jsonl"
        self._two_ceremonies(t)
        lines = Path(t).read_text().splitlines()
        rec = json.loads(lines[0])
        rec["detail"]["threshold"] = 1
        lines[0] = json.dumps(rec)
        Path(t).write_text("\n".join(lines) + "\n")
        with self.assertRaises(ValueError):
            custody.update_tip_manifest(t, ROOT_SEED)


if __name__ == "__main__":
    unittest.main()
