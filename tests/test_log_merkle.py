"""Tests for the crypto workstream prototype: Ed25519 + Merkle checkpoints.

Covers the P2 deliverables against ``workstreams/crypto/`` (prototype;
``gov/`` untouched):
  * RFC 8032 test vectors (byte-exact) for the pure-Python Ed25519.
  * Signature verification failure on tampered entries/checkpoints.
  * Merkle inclusion proofs: positive, negatives (bad leaf/proof/root).
  * Signed checkpoint root verification, incl. attacker-keypair rejection
    and key rotation with old-epoch retention.
  * F70 regression: length-preserving pre-tip rewrite of a reconcile
    marker is detected LOUDLY by the marker manifest (while the current
    incremental tip path stays silent -- pinned as characterization).
  * Forged-checkpoint gap: HMAC-only checkpoints are forgeable with the
    public dev key (pinned); Ed25519-signed checkpoints reject the
    keyless forger.

Hermetic: each test uses a fresh temp dir; key env vars are saved and
restored (tests force the documented public-dev-key attacker model).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
_WORKSTREAMS = os.path.join(os.path.dirname(_REPO_MAIN), "workstreams")
for _p in (_TESTS_DIR, _REPO_MAIN, _WORKSTREAMS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.log import (  # noqa: E402
    ActionLog,
    verify_chain,
    verify_chain_tip,
    write_chain_tip_from_tail,
    _active_key,
    _DEV_KEY,
    _checkpoint_mac,
    _canonical,
    _compute_mac,
)
from crypto import ed25519  # noqa: E402
from crypto.merkle import (  # noqa: E402
    MerkleStack, tree_root, inclusion_proof, verify_inclusion,
)
from crypto.signing_keys import SigningKeyRing  # noqa: E402
from crypto.siglog import (  # noqa: E402
    SignedMerkleLog, verify_checkpoint, entry_leaf,
)
from crypto.markers import build_manifest, check_markers  # noqa: E402

_ENV_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


class CryptoTestBase(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_VARS}
        # Documented attacker model: the PUBLIC dev key (nobody can claim
        # the tests passed because of a secret test key).
        for k in _ENV_VARS:
            os.environ.pop(k, None)
        self.tmp = Path(tempfile.mkdtemp(prefix="test-merkle-"))

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def make_signed_log(self, n=12, marker_seq=5):
        kr_path = self.tmp / "signing_keys.json"
        ring = SigningKeyRing.generate(kr_path, epoch="sig-1")
        slog = SignedMerkleLog(self.tmp / "actions.jsonl", ring)
        for i in range(1, n + 1):
            if i == marker_seq:
                slog.append({"event": "execution_authorized",
                             "approval_id": "aid-9",
                             "decision": "APPROVED-AAAA",
                             "flag": "deploy"})
            else:
                slog.append({"event": "tool_call", "tool": "write_file",
                             "n": i})
        trusted = {ep: ring.get_pub(ep) for ep in ring.epochs()}
        return slog, ring, trusted


class TestEd25519Vectors(CryptoTestBase):
    """RFC 8032 section 7.1 vectors: pubkey, byte-exact sign, verify."""

    def test_rfc8032_vectors_byte_exact(self):
        for i, v in enumerate(ed25519.RFC8032_VECTORS, 1):
            sk = bytes.fromhex(v["sk"])
            pk = bytes.fromhex(v["pk"])
            msg = bytes.fromhex(v["msg"])
            sig = bytes.fromhex(v["sig"])
            self.assertEqual(ed25519.publickey(sk), pk,
                             "vector %d: pubkey mismatch" % i)
            self.assertEqual(ed25519.sign(sk, msg), sig,
                             "vector %d: signature not byte-exact" % i)
            self.assertTrue(ed25519.verify(pk, msg, sig),
                            "vector %d: verify failed" % i)

    def test_tampered_signature_rejected(self):
        v = ed25519.RFC8032_VECTORS[0]
        pk = bytes.fromhex(v["pk"])
        sig = bytearray(bytes.fromhex(v["sig"]))
        sig[10] ^= 1
        self.assertFalse(ed25519.verify(pk, b"", bytes(sig)))

    def test_wrong_message_rejected(self):
        v = ed25519.RFC8032_VECTORS[1]
        pk = bytes.fromhex(v["pk"])
        sig = bytes.fromhex(v["sig"])
        self.assertFalse(ed25519.verify(pk, b"\x73", sig))

    def test_wrong_key_rejected(self):
        v = ed25519.RFC8032_VECTORS[1]
        sig = bytes.fromhex(v["sig"])
        self.assertFalse(ed25519.verify(os.urandom(32), b"\x72", sig))

    def test_malformed_inputs_never_raise(self):
        self.assertFalse(ed25519.verify(b"short", b"m", b"\x00" * 64))
        self.assertFalse(ed25519.verify(b"\x00" * 32, b"m", b"short"))
        self.assertFalse(ed25519.verify(b"\xff" * 32, b"m", b"\x00" * 64))
        with self.assertRaises(ValueError):
            ed25519.publickey(b"short")
        with self.assertRaises(ValueError):
            ed25519.sign(b"short", b"m")

    def test_roundtrip_random_keys(self):
        for _ in range(3):
            seed = ed25519.generate_seed()
            pk = ed25519.publickey(seed)
            msg = os.urandom(64)
            sig = ed25519.sign(seed, msg)
            self.assertTrue(ed25519.verify(pk, msg, sig))
            # deterministic: same seed+msg -> same signature
            self.assertEqual(ed25519.sign(seed, msg), sig)


class TestMerkleProofs(CryptoTestBase):
    """Inclusion proofs: positive for every leaf, negatives fail."""

    def test_proofs_over_signed_log(self):
        slog, ring, trusted = self.make_signed_log(n=12)
        ok, err, checked = slog.verify_sig_chain(trusted)
        self.assertTrue(ok, err)
        self.assertEqual(checked, 12)
        for seq in (1, 5, 12):
            bundle = slog.prove_inclusion(seq, trusted)
            self.assertTrue(
                SignedMerkleLog.verify_proof_bundle(bundle, trusted),
                "inclusion proof failed for seq %d" % seq)
            # proof is O(log n)
            self.assertLessEqual(len(bundle["proof"]), 5)

    def test_proof_negatives(self):
        slog, ring, trusted = self.make_signed_log(n=8)
        bundle = slog.prove_inclusion(3, trusted)
        # wrong leaf
        bad = dict(bundle)
        bad["leaf"] = "00" * 32
        self.assertFalse(
            SignedMerkleLog.verify_proof_bundle(bad, trusted))
        # tampered proof element
        bad = dict(bundle)
        p = [x for x in bad["proof"]]
        p[0] = "ff" * 32
        bad["proof"] = p
        self.assertFalse(
            SignedMerkleLog.verify_proof_bundle(bad, trusted))
        # wrong root
        bad = dict(bundle)
        bad["root"] = "11" * 32
        self.assertFalse(
            SignedMerkleLog.verify_proof_bundle(bad, trusted))
        # truncated proof
        bad = dict(bundle)
        bad["proof"] = bad["proof"][:-1]
        self.assertFalse(
            SignedMerkleLog.verify_proof_bundle(bad, trusted))

    def test_tampered_entry_breaks_proof(self):
        """Signature verification failure on tampered entry: rewrite a log
        entry; the signed root no longer matches -> prove fails loudly."""
        slog, ring, trusted = self.make_signed_log(n=8)
        p = self.tmp / "actions.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        e = json.loads(lines[2])
        e["n"] = 99999
        lines[2] = json.dumps(e, ensure_ascii=True, default=str)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(RuntimeError):
            slog.prove_inclusion(3, trusted)

    def test_stack_root_matches_batch(self):
        leaves = [os.urandom(32) for _ in range(25)]
        st = MerkleStack()
        for lf in leaves:
            st.append(lf)
        self.assertEqual(st.root(), tree_root(leaves))


class TestCheckpointVerification(CryptoTestBase):
    def test_sig_chain_verifies(self):
        slog, ring, trusted = self.make_signed_log(n=10)
        ok, err, checked = slog.verify_sig_chain(trusted)
        self.assertTrue(ok, err)
        self.assertEqual(checked, 10)

    def test_tampered_checkpoint_rejected(self):
        slog, ring, trusted = self.make_signed_log(n=6)
        cp = dict(slog._read_sig_checkpoints()[-1])
        cp["merkle_root"] = "ff" * 32  # no re-sign possible w/o seed
        ok, err = verify_checkpoint(cp, trusted)
        self.assertFalse(ok)
        self.assertIn("signature", err)

    def test_attacker_keypair_rejected(self):
        """A run-dir writer who mints their own keypair is not in the
        trusted pubkey set: their checkpoints are rejected."""
        slog, ring, trusted = self.make_signed_log(n=6)
        evil_seed = ed25519.generate_seed()
        cp = dict(slog._read_sig_checkpoints()[-1])
        cp["pub"] = ed25519.publickey(evil_seed).hex()
        ok, err = verify_checkpoint(cp, trusted)
        self.assertFalse(ok)

    def test_unknown_epoch_rejected(self):
        slog, ring, trusted = self.make_signed_log(n=6)
        cp = dict(slog._read_sig_checkpoints()[-1])
        cp["signing_epoch"] = "sig-999"
        ok, err = verify_checkpoint(cp, trusted)
        self.assertFalse(ok)

    def test_rotation_keeps_old_checkpoints_verifiable(self):
        slog, ring, trusted = self.make_signed_log(n=6)
        new_ep = ring.rotate()
        trusted[new_ep] = ring.get_pub(new_ep)
        slog.append({"event": "tool_call", "tool": "noop"})
        ok, err, checked = slog.verify_sig_chain(trusted)
        self.assertTrue(ok, err)
        self.assertEqual(checked, 7)
        cps = slog._read_sig_checkpoints()
        self.assertEqual(cps[0]["signing_epoch"], "sig-1")
        self.assertEqual(cps[-1]["signing_epoch"], new_ep)


class TestForgedCheckpointGap(CryptoTestBase):
    """Pins the HMAC-only gap the Ed25519 layer closes: with the PUBLIC
    dev key, history rewrite + re-minted HMAC checkpoint verifies clean.
    The same forgery shape against signed checkpoints is rejected."""

    def test_hmac_checkpoint_forgeable_with_dev_key(self):
        log = ActionLog(self.tmp / "actions.jsonl")
        for i in range(6):
            log.append({"event": "tool_call", "n": i})
        p = self.tmp / "actions.jsonl"
        entries = [json.loads(l) for l in
                   p.read_text(encoding="utf-8").splitlines() if l.strip()]
        prev = entries[1]["hash"]
        forged = entries[:2]
        for e in entries[2:]:
            e = dict(e)
            e["prev_hash"] = prev
            if e["seq"] == 3:
                e["tool"] = "exfiltrate"
            e.pop("hash", None)
            e["hash"] = _compute_mac(_DEV_KEY, "dev", prev, _canonical(e))
            prev = e["hash"]
            forged.append(e)
        p.write_text("\n".join(json.dumps(e, ensure_ascii=True, default=str)
                               for e in forged) + "\n", encoding="utf-8")
        tail = forged[-1]
        cp = {"seq": tail["seq"], "hash": tail["hash"], "key_epoch": "dev",
              "format_version": 1,
              "mac": _checkpoint_mac(_DEV_KEY, "dev",
                                     tail["seq"], tail["hash"])}
        (self.tmp / "checkpoints.jsonl").write_text(
            json.dumps(cp) + "\n", encoding="utf-8")
        ok, _, _ = verify_chain(p)
        self.assertTrue(ok, "expected: dev-key forgery verifies clean "
                            "without the Ed25519 layer")

    def test_signed_checkpoint_rejects_keyless_forger(self):
        slog, ring, trusted = self.make_signed_log(n=6)
        # Forger rewrites history; tries to mint a checkpoint. They have
        # no seed, so the best they can do is copy an old signature over
        # new content -- rejected.
        cp = dict(slog._read_sig_checkpoints()[-1])
        cp["hash"] = "ab" * 32
        ok, _ = verify_checkpoint(cp, trusted)
        self.assertFalse(ok)


class TestF70Regression(CryptoTestBase):
    """F70: length-preserving pre-tip rewrite of a genuine
    execution_authorized marker.

    Characterization: the CURRENT incremental tip path stays silent
    (verify_chain_tip -> ok=True) -- this pins the open finding.
    New layer: the MAC'd marker manifest detects the rewrite LOUDLY,
    naming approval_id and seq, with O(#markers) seeks (no rescan).
    """

    def _attack_log(self, n=20, marker_seq=10):
        slog, ring, trusted = self.make_signed_log(n=n,
                                                   marker_seq=marker_seq)
        p = self.tmp / "actions.jsonl"
        ok, _, _ = verify_chain(p)
        self.assertTrue(ok)
        write_chain_tip_from_tail(p, {})
        key, epoch = _active_key()
        manifest = build_manifest(p, key, epoch)
        self.assertIn("aid-9", manifest["markers"])
        # F70 attacker: length-preserving rewrite, hash string kept.
        lines = p.read_text(encoding="utf-8").splitlines()
        raw = lines[marker_seq - 1]
        self.assertIn("APPROVED-AAAA", raw)
        lines[marker_seq - 1] = raw.replace("APPROVED-AAAA",
                                            "DENIED---AAAA")
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p, manifest, key

    def test_incremental_tip_path_is_silent_f70_open(self):
        p, manifest, key = self._attack_log()
        tip_v = verify_chain_tip(p)
        self.assertIsNotNone(tip_v)
        self.assertTrue(
            tip_v["ok"],
            "characterization of F70-OPEN: the incremental tip path does "
            "not see length-preserving pre-tip rewrites")
        # ...while full verification still catches it loudly.
        ok, broken, _ = verify_chain(p)
        self.assertFalse(ok)
        self.assertEqual(broken, 10)

    def test_marker_manifest_detects_f70_loudly(self):
        p, manifest, key = self._attack_log()
        v = check_markers(p, manifest, key)
        self.assertFalse(v["ok"])
        self.assertEqual(v["approval_id"], "aid-9")
        self.assertEqual(v["seq"], 10)
        self.assertIn("F70", v["error"])

    def test_marker_manifest_clean_when_untampered(self):
        slog, ring, trusted = self.make_signed_log(n=12, marker_seq=5)
        p = self.tmp / "actions.jsonl"
        key, epoch = _active_key()
        manifest = build_manifest(p, key, epoch)
        v = check_markers(p, manifest, key)
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["checked"], 1)

    def test_length_changing_rewrite_also_loud(self):
        slog, ring, trusted = self.make_signed_log(n=12, marker_seq=5)
        p = self.tmp / "actions.jsonl"
        key, epoch = _active_key()
        manifest = build_manifest(p, key, epoch)
        lines = p.read_text(encoding="utf-8").splitlines()
        # Length-CHANGING edit: offsets shift; recorded offset no longer
        # parses to the expected seq -> loud failure, never silent.
        lines[4] = lines[4].replace("APPROVED-AAAA", "APPROVED")
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        v = check_markers(p, manifest, key)
        self.assertFalse(v["ok"])
        self.assertEqual(v["approval_id"], "aid-9")

    def test_forged_manifest_rejected(self):
        slog, ring, trusted = self.make_signed_log(n=12, marker_seq=5)
        p = self.tmp / "actions.jsonl"
        key, epoch = _active_key()
        manifest = build_manifest(p, key, epoch)
        manifest["markers"]["aid-9"]["leaf"] = "00" * 32  # no re-MAC
        v = check_markers(p, manifest, key)
        self.assertFalse(v["ok"])
        self.assertIn("MAC", v["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
