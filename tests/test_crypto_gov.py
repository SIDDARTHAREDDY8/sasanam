"""Production-path tests for the P2 crypto migration and the literature /
knowledge IMPLEMENT items built on it.

Covers ``gov/ed25519.py``, ``gov/merkle.py``, ``gov/signing.py``,
``gov/anchor.py``, the ``gov/log.py`` signed-checkpoint integration,
``gov/identity.py`` attestation, and the ``gov/verify.py`` CLI:

  * P2 migration: RFC 8032 vectors, per-entry + checkpoint signatures,
    v2 checkpoints, HMAC coexistence (byte-identical default), third-
    party (HMAC-keyless) verification, unknown-key rejection.
  * CT (Laurie/Langley/Kasper): the STH mapping is pinned
    (format_version/tree_size/timestamp/root/signature); forged
    consistency proofs fail; valid append-only extension verifies.
  * Crosby & Wallach: O(log n) inclusion/consistency with no full
    replay and no HMAC key (the bundle + trusted keys suffice).
  * Coker: attestation claim semantics, nonce freshness, bounded
    disclosure, explicit non-claims.
  * A5: k-of-n threshold checkpoint signatures + offline root roster;
    single-key compromise cannot forge a checkpoint (attack situation:
    observe fail -> harden -> pass).
  * K-025: cross-run taint carry-over; tampered marks fail closed.
  * K-049: transparency anchoring incl. equivocation refusal.
  * K-060: queryable/exportable trail; tampered exports fail.

Hermetic: one log per temp dir (the checkpoint sidecar is per-
directory); key env vars are saved/restored and the documented public
dev key is the HMAC attacker model throughout.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import ed25519 as _ed  # noqa: E402
from gov import merkle as _merkle  # noqa: E402
from gov import signing as _signing  # noqa: E402
from gov import anchor as _anchor  # noqa: E402
from gov import identity as _identity  # noqa: E402
from gov import log as _log  # noqa: E402
from gov.egress_ledger import (  # noqa: E402
    EgressLedger, LedgerUnverifiableError,
)
from gov.log import (  # noqa: E402
    ActionLog, verify_chain, _canonical, _compute_mac, _checkpoint_mac,
    _DEV_KEY,
)

_ENV_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _seed(n):
    return bytes([n & 0xFF]) * 32


class CryptoGovBase(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_VARS}
        for k in _ENV_VARS:
            os.environ.pop(k, None)
        self.dirs = []
        # tests/__init__ performs the dev-key double opt-in; the HMAC
        # layer therefore uses the PUBLIC dev key here -- the documented
        # attacker model (a key holder can forge HMAC; signatures must
        # still hold).
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for d in self.dirs:
            import shutil
            shutil.rmtree(d, ignore_errors=True)

    def fresh_dir(self):
        d = tempfile.mkdtemp(prefix="test-crypto-gov-")
        self.dirs.append(d)
        return Path(d)

    def signed_log(self, n=6, signer=None, roster=None, events=None):
        """One signed log per fresh dir (sidecar is per-directory)."""
        d = self.fresh_dir()
        if signer is None:
            signer = _signing.Ed25519Signer(_seed(1))
        lg = ActionLog(str(d / "actions.jsonl"), signer=signer,
                       roster=roster)
        for i in range(1, n + 1):
            evt = (events[i - 1] if events is not None
                   else {"event": "tool_call", "n": i,
                         "principal": "org1", "agent_id": "a1"})
            lg.append(dict(evt))
        return lg, str(d / "actions.jsonl"), signer

    def threshold_setup(self, k=2, n=3):
        signers = [_signing.Ed25519Signer(_seed(10 + i)) for i in range(n)]
        root = _signing.Ed25519Signer(_seed(99))
        roster = _signing.make_roster(signers, k, root)
        ts = _signing.ThresholdSigner(signers, k)
        return signers, root, roster, ts

    def trust_single(self, signer):
        return {signer.key_id: signer.public_key}

    def trust_threshold(self, roster, root):
        return {"roster": roster, "root_pub": root.public_key}


class GovEd25519Tests(CryptoGovBase):
    def test_rfc8032_vectors(self):
        self.assertTrue(_ed.rfc8032_selftest())

    def test_sign_verify_roundtrip_and_tamper(self):
        s = _signing.Ed25519Signer(_seed(7))
        v = _signing.Ed25519Verifier(s.public_key)
        msg = b"checkpoint body"
        sig = s.sign(msg)
        self.assertTrue(v.verify(msg, sig))
        self.assertFalse(v.verify(b"checkpoint bodx", sig))
        bad = bytearray(sig)
        bad[0] ^= 1
        self.assertFalse(v.verify(msg, bytes(bad)))
        # fail-closed on malformed inputs, never raises
        self.assertFalse(v.verify(msg, b"short"))
        self.assertFalse(v.verify("not bytes", sig))

    def test_key_id_matches_keys_py_convention(self):
        s = _signing.Ed25519Signer(_seed(7))
        import hashlib
        self.assertEqual(
            s.key_id, hashlib.sha256(s.public_key).hexdigest()[:16])


class GovMerkleConsistencyTests(CryptoGovBase):
    def _leaves(self, n):
        return [_merkle.leaf_hash(b"leaf-%d" % i) for i in range(n)]

    def test_consistency_valid_pairs(self):
        for n in range(1, 25):
            leaves = self._leaves(n)
            new_root = _merkle.tree_root(leaves)
            for m in range(1, n + 1):
                old_root = _merkle.tree_root(leaves[:m])
                proof = _merkle.consistency_proof(leaves, m)
                self.assertTrue(
                    _merkle.verify_consistency(old_root, new_root, m, n,
                                               proof),
                    "m=%d n=%d" % (m, n))

    def test_consistency_forged_proof_fails(self):
        # CT attack situation, BEFORE hardening: a forged consistency
        # proof must fail verification.
        leaves = self._leaves(10)
        old_root = _merkle.tree_root(leaves[:4])
        new_root = _merkle.tree_root(leaves)
        proof = _merkle.consistency_proof(leaves, 4)
        bad = [bytes(b) for b in proof]
        bad[0] = bytes(b ^ 1 for b in bad[0])
        self.assertFalse(
            _merkle.verify_consistency(old_root, new_root, 4, 10, bad))

    def test_consistency_truncated_and_overlong_fail(self):
        leaves = self._leaves(10)
        old_root = _merkle.tree_root(leaves[:4])
        new_root = _merkle.tree_root(leaves)
        proof = _merkle.consistency_proof(leaves, 4)
        self.assertFalse(_merkle.verify_consistency(
            old_root, new_root, 4, 10, proof[:-1]))
        self.assertFalse(_merkle.verify_consistency(
            old_root, new_root, 4, 10, proof + [b"\x00" * 32]))

    def test_consistency_forked_history_fails(self):
        # A consistency proof for a FORKED history does not verify
        # against the real head: the fork cannot be spliced in.
        leaves = self._leaves(10)
        forked = self._leaves(9) + [_merkle.leaf_hash(b"evil")]
        old_root = _merkle.tree_root(leaves[:4])
        real_new = _merkle.tree_root(leaves)
        proof = _merkle.consistency_proof(forked, 4)
        self.assertFalse(_merkle.verify_consistency(
            old_root, real_new, 4, 10, proof))


class ThresholdUnitTests(CryptoGovBase):
    def test_roster_roundtrip(self):
        signers, root, roster, _ = self.threshold_setup()
        ok, err = _signing.verify_roster(roster, root.public_key)
        self.assertTrue(ok, err)

    def test_roster_wrong_root_fails(self):
        signers, root, roster, _ = self.threshold_setup()
        other = _signing.Ed25519Signer(_seed(100))
        ok, err = _signing.verify_roster(roster, other.public_key)
        self.assertFalse(ok)
        self.assertIn("root", err)

    def test_roster_tampered_threshold_fails(self):
        # Attacker raises k in the roster text: the root signature no
        # longer verifies -> fail closed.
        signers, root, roster, _ = self.threshold_setup()
        tampered = dict(roster)
        tampered["threshold"] = 3
        ok, _ = _signing.verify_roster(tampered, root.public_key)
        self.assertFalse(ok)

    def test_roster_role_separation(self):
        signers, root, roster, _ = self.threshold_setup()
        bad = dict(roster)
        bad["role"] = "root"
        ok, err = _signing.verify_roster(bad, root.public_key)
        self.assertFalse(ok)
        self.assertIn("role", err)

    def test_roster_key_id_mismatch_fails(self):
        signers, root, roster, _ = self.threshold_setup()
        bad = json.loads(json.dumps(roster))
        kid = next(iter(bad["keys"]))
        bad["keys"][kid] = _signing.Ed25519Signer(_seed(200)).public_key.hex()
        ok, _ = _signing.verify_roster(bad, root.public_key)
        self.assertFalse(ok)

    def test_threshold_verify_ok(self):
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        body = b"checkpoint body"
        sigs = ts.sign_all(body)
        ok, err = _signing.verify_threshold(body, sigs, roster,
                                            root.public_key)
        self.assertTrue(ok, err)

    def test_single_key_compromise_cannot_forge(self):
        # A5 attack situation: ONE compromised checkpoint key signs a
        # forged head; k=2 -> the forgery FAILS (observe fail).
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        body = b"forged checkpoint body"
        forged = [{"key_id": signers[0].key_id,
                   "sig": signers[0].sign(body).hex()}]
        ok, err = _signing.verify_threshold(body, forged, roster,
                                            root.public_key)
        self.assertFalse(ok)
        self.assertIn("1/2", err)

    def test_duplicate_key_does_not_double_count(self):
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        body = b"body"
        one = {"key_id": signers[0].key_id,
               "sig": signers[0].sign(body).hex()}
        ok, err = _signing.verify_threshold(body, [one, dict(one)],
                                            roster, root.public_key)
        self.assertFalse(ok)
        self.assertIn("1/2", err)

    def test_unknown_keys_ignored(self):
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        body = b"body"
        outsider = _signing.Ed25519Signer(_seed(200))
        sigs = [{"key_id": signers[0].key_id,
                 "sig": signers[0].sign(body).hex()},
                {"key_id": outsider.key_id,
                 "sig": outsider.sign(body).hex()}]
        ok, err = _signing.verify_threshold(body, sigs, roster,
                                            root.public_key)
        self.assertFalse(ok)  # outsider contributes nothing
        self.assertIn("1/2", err)

    def test_bad_threshold_rejected_at_construction(self):
        s = _signing.Ed25519Signer(_seed(1))
        with self.assertRaises(ValueError):
            _signing.ThresholdSigner([s], 0)
        with self.assertRaises(ValueError):
            _signing.ThresholdSigner([s], 2)
        with self.assertRaises(ValueError):
            _signing.ThresholdSigner([s, s], 2)  # duplicate key ids

    def test_roster_hash_binds_signer_set(self):
        signers, root, roster, _ = self.threshold_setup()
        h1 = _signing.roster_hash(roster)
        rotated = _signing.make_roster(signers[1:], 1, root,
                                       prev_roster_hash=h1)
        self.assertNotEqual(h1, _signing.roster_hash(rotated))
        self.assertEqual(rotated["prev_roster_hash"], h1)

class SignedLogTests(CryptoGovBase):
    def test_v2_checkpoints_written(self):
        lg, path, signer = self.signed_log(n=4)
        cps = _log.signed_checkpoints(path)
        self.assertEqual(len(cps), 4)
        cp = cps[-1]
        # CT STH mapping, pinned: version/tree_size/timestamp/root/sig.
        self.assertEqual(cp["format_version"], 2)
        self.assertEqual(cp["seq"], 4)            # tree_size
        self.assertIn("ts", cp)                  # timestamp
        self.assertEqual(len(bytes.fromhex(cp["merkle_root"])), 32)
        self.assertEqual(cp["threshold"], 1)
        self.assertEqual(len(cp["sigs"]), 1)
        self.assertEqual(cp["sigs"][0]["key_id"], signer.key_id)
        # The HMAC layer is untouched: MAC still verifies.
        self.assertTrue(verify_chain(path)[0])

    def test_hmac_chain_unaffected_by_sig_layer(self):
        # _canonical excludes the sig envelope: chain semantics for an
        # entry are identical with and without signatures.
        entry = {"seq": 1, "event": "x", "hash": "h",
                 "ed_sig": "00" * 64, "sig_key_id": "abc"}
        stripped = {k: v for k, v in entry.items()
                    if k not in ("ed_sig", "sig_key_id")}
        self.assertEqual(_canonical(entry), _canonical(stripped))

    def test_no_signer_byte_identical_default(self):
        d = self.fresh_dir()
        lg = ActionLog(str(d / "actions.jsonl"))
        e = lg.append({"event": "x"})
        self.assertNotIn("ed_sig", e)
        self.assertNotIn("sig_key_id", e)
        cps = _log.signed_checkpoints(str(d / "actions.jsonl"))
        self.assertEqual(cps, [])

    def test_third_party_sig_verification(self):
        # No HMAC key needed: verification uses only the trusted keys.
        lg, path, signer = self.signed_log(n=5)
        verdict = _log.verify_checkpoint_signatures(
            path, trusted_keys=self.trust_single(signer))
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict, {"ok": True, "checked": 5, "valid": 5,
                                  "unsigned": 0, "error": None})

    def test_unknown_signing_key_rejected(self):
        lg, path, signer = self.signed_log(n=3)
        other = _signing.Ed25519Signer(_seed(77))
        verdict = _log.verify_checkpoint_signatures(
            path, trusted_keys=self.trust_single(other))
        self.assertFalse(verdict["ok"])
        self.assertIn("unknown signing key", verdict["error"])

    def test_per_entry_sig_tamper_rejected(self):
        lg, path, signer = self.signed_log(n=3)
        entries = _log._proof_entries(path)
        entry = entries[1][0]
        pub = signer.public_key
        sig = bytes.fromhex(entry["ed_sig"])
        self.assertTrue(_ed.verify(
            pub, _log._entry_sig_body(entry), sig))
        tampered = dict(entry)
        tampered["n"] = 9999
        self.assertFalse(_ed.verify(
            pub, _log._entry_sig_body(tampered), sig))

    def test_unsigned_log_require_signed_fails(self):
        d = self.fresh_dir()
        lg = ActionLog(str(d / "actions.jsonl"))
        lg.append({"event": "x"})
        verdict = _log.verify_checkpoint_signatures(
            str(d / "actions.jsonl"), trusted_keys={},
            require_signed=True)
        self.assertFalse(verdict["ok"])

    def test_mixed_log_counts_unsigned(self):
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p).append({"event": "unsigned"})
        signer = _signing.Ed25519Signer(_seed(3))
        ActionLog(p, signer=signer).append({"event": "signed"})
        verdict = _log.verify_checkpoint_signatures(
            p, trusted_keys=self.trust_single(signer))
        self.assertTrue(verdict["ok"], verdict)
        self.assertEqual(verdict["unsigned"], 1)
        self.assertEqual(verdict["valid"], 1)
        strict = _log.verify_checkpoint_signatures(
            p, trusted_keys=self.trust_single(signer),
            require_signed=True)
        self.assertFalse(strict["ok"])

    def test_sig_stripping_downgrade_documented(self):
        # Stripping the v2 fields turns the checkpoint into v1: the
        # HMAC path still verifies (documented residual), but a third
        # party with require_signed=True rejects the log.
        lg, path, signer = self.signed_log(n=3)
        cp_path = Path(path).parent / "checkpoints.jsonl"
        lines = cp_path.read_text(encoding="utf-8").splitlines()
        stripped = []
        for line in lines:
            cp = json.loads(line)
            for f in ("merkle_root", "threshold", "sigs", "roster_hash",
                      "ts"):
                cp.pop(f, None)
            cp["format_version"] = 1
            stripped.append(json.dumps(cp))
        cp_path.write_text("\n".join(stripped) + "\n", encoding="utf-8")
        self.assertTrue(verify_chain(path)[0])  # HMAC: still fine
        verdict = _log.verify_checkpoint_signatures(
            path, trusted_keys=self.trust_single(signer),
            require_signed=True)
        self.assertFalse(verdict["ok"])  # third party: rejected


class ProofTests(CryptoGovBase):
    """CT auditor flows + Crosby-Wallach: O(log n) proofs, no replay."""

    def test_inclusion_roundtrip_all_entries(self):
        lg, path, signer = self.signed_log(n=9)
        trust = self.trust_single(signer)
        for seq in range(1, 10):
            b = _log.prove_inclusion(path, seq)
            ok, err = _log.verify_inclusion_bundle(b, trust)
            self.assertTrue(ok, "seq %d: %s" % (seq, err))
            self.assertLessEqual(len(b["proof"]), 4)  # O(log n)

    def test_inclusion_bundle_is_offline(self):
        # The auditor needs ONLY the bundle + trusted keys: serialize
        # it (as it would cross a trust boundary) and verify from the
        # serialized form, never touching the log.
        lg, path, signer = self.signed_log(n=6)
        b = json.loads(json.dumps(_log.prove_inclusion(path, 4)))
        ok, err = _log.verify_inclusion_bundle(
            b, self.trust_single(signer))
        self.assertTrue(ok, err)

    def test_inclusion_tampered_entry_fails(self):
        lg, path, signer = self.signed_log(n=6)
        b = _log.prove_inclusion(path, 4)
        b["entry"] = dict(b["entry"])
        b["entry"]["n"] = 12345
        ok, _ = _log.verify_inclusion_bundle(
            b, self.trust_single(signer))
        self.assertFalse(ok)

    def test_inclusion_tampered_proof_fails(self):
        lg, path, signer = self.signed_log(n=6)
        b = _log.prove_inclusion(path, 4)
        bad = [bytes.fromhex(p) for p in b["proof"]]
        bad[0] = bytes(x ^ 1 for x in bad[0])
        b["proof"] = [p.hex() for p in bad]
        ok, _ = _log.verify_inclusion_bundle(
            b, self.trust_single(signer))
        self.assertFalse(ok)

    def test_inclusion_wrong_key_fails(self):
        lg, path, signer = self.signed_log(n=6)
        b = _log.prove_inclusion(path, 4)
        other = _signing.Ed25519Signer(_seed(77))
        ok, _ = _log.verify_inclusion_bundle(
            b, self.trust_single(other))
        self.assertFalse(ok)

    def test_history_rewrite_breaks_proving(self):
        # F70-shaped attack against the signed log: the attacker holds
        # the (public) dev HMAC key, rewrites a pre-tip entry, and
        # recomputes the HMAC suffix AND the checkpoint MACs -- every
        # HMAC-layer check still verifies, but the Ed25519-signed
        # Merkle head cannot be re-signed, so the log REFUSES to prove
        # (fail-loud, never a wrong proof) and the checkpoint
        # signatures no longer verify.
        lg, path, signer = self.signed_log(n=5)
        ok, _ = _log.verify_inclusion_bundle(
            _log.prove_inclusion(path, 3),
            self.trust_single(signer))
        self.assertTrue(ok)
        lines = Path(path).read_text(
            encoding="utf-8").splitlines()
        entries = [json.loads(l) for l in lines]
        entries[1]["n"] = 4242  # rewrite seq 2's content
        prev = entries[0]["hash"]
        new_hash = {entries[0]["seq"]: entries[0]["hash"]}
        for e in entries[1:]:
            # The chain links via the prev_hash FIELD as well as the
            # MAC's prev parameter: both must be re-pointed.
            e["prev_hash"] = prev
            e["hash"] = _compute_mac(_DEV_KEY, "dev", prev,
                                     _canonical(e))
            prev = e["hash"]
            new_hash[e["seq"]] = e["hash"]
        Path(path).write_text(
            "\n".join(json.dumps(e, ensure_ascii=True, default=str)
                      for e in entries) + "\n", encoding="utf-8")
        # The attacker re-MACs the checkpoints too (they hold the dev
        # HMAC key); the signed Merkle roots and sigs stay as-was.
        cp_path = Path(path).parent / "checkpoints.jsonl"
        cps = []
        for line in cp_path.read_text(encoding="utf-8").splitlines():
            cp = json.loads(line)
            cp["hash"] = new_hash[cp["seq"]]
            cp["mac"] = _checkpoint_mac(
                _DEV_KEY, "dev", cp["seq"], cp["hash"])
            cps.append(json.dumps(cp, ensure_ascii=True, default=str))
        cp_path.write_text("\n".join(cps) + "\n", encoding="utf-8")
        self.assertTrue(verify_chain(path)[0])  # HMAC fully fooled
        verdict = _log.verify_checkpoint_signatures(
            path, trusted_keys=self.trust_single(signer))
        self.assertFalse(verdict["ok"])  # sigs do not cover new hash
        with self.assertRaises(ValueError):
            _log.prove_inclusion(path, 3)  # root mismatch: refuse

    def test_consistency_roundtrip(self):
        lg, path, signer = self.signed_log(n=8)
        trust = self.trust_single(signer)
        for old in (1, 3, 7):
            b = _log.prove_consistency(path, old)
            ok, err = _log.verify_consistency_bundle(b, trust)
            self.assertTrue(ok, "old=%d: %s" % (old, err))
            self.assertEqual(b["new_seq"], 8)

    def test_consistency_forged_proof_fails(self):
        # CT attack situation: forged consistency proof fails BEFORE
        # any hardening is even needed (fail-closed by construction);
        # the valid append-only proof passes (hardened state).
        lg, path, signer = self.signed_log(n=8)
        trust = self.trust_single(signer)
        good = _log.prove_consistency(path, 3)
        ok, _ = _log.verify_consistency_bundle(good, trust)
        self.assertTrue(ok)  # valid append-only extension: passes
        forged = json.loads(json.dumps(good))
        proof = [bytes.fromhex(p) for p in forged["proof"]]
        proof[0] = bytes(x ^ 1 for x in proof[0])
        forged["proof"] = [p.hex() for p in proof]
        ok, err = _log.verify_consistency_bundle(forged, trust)
        self.assertFalse(ok)
        self.assertIn("consistency proof", err)

    def test_consistency_truncated_overlong_fail(self):
        lg, path, signer = self.signed_log(n=8)
        trust = self.trust_single(signer)
        for mutate in (lambda p: p[:-1], lambda p: p + ["00" * 32]):
            b = _log.prove_consistency(path, 2)
            b["proof"] = mutate(b["proof"])
            ok, _ = _log.verify_consistency_bundle(b, trust)
            self.assertFalse(ok)

    def test_consistency_forked_new_head_fails(self):
        # True fork: the evil log shares the honest log's first 4 lines
        # VERBATIM (same prefix, same old head), then diverges at entry
        # 5. Splicing the fork's new head into an honest bundle must
        # fail: the old tree is not a prefix of the forked tree.
        lg, path, signer = self.signed_log(n=6)
        trust = self.trust_single(signer)
        d2 = self.fresh_dir()
        p2 = str(d2 / "actions.jsonl")
        honest_lines = Path(path).read_text(
            encoding="utf-8").splitlines()
        Path(p2).write_text(
            "\n".join(honest_lines[:4]) + "\n", encoding="utf-8")
        lg2 = ActionLog(p2, signer=signer)  # continues the true prefix
        lg2.append({"event": "EVIL", "n": 5, "principal": "org1",
                    "agent_id": "a1"})
        lg2.append({"event": "tool_call", "n": 6,
                    "principal": "org1", "agent_id": "a1"})
        honest = _log.prove_consistency(path, 2)
        forged = dict(honest)
        evil_new = _log.signed_checkpoint(p2, 6)
        forged["new_checkpoint"] = evil_new
        forged["new_seq"] = 6
        forged["new_root"] = evil_new["merkle_root"]
        ok, err = _log.verify_consistency_bundle(forged, trust)
        self.assertFalse(ok)
        self.assertIn("not a pure append", err)

    def test_prove_needs_signed_coverage(self):
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p).append({"event": "x"})
        with self.assertRaises(ValueError):
            _log.prove_inclusion(p, 1)
        with self.assertRaises(ValueError):
            _log.prove_consistency(p, 1)

class ThresholdLogTests(CryptoGovBase):
    """A5 end-to-end: k-of-n threshold checkpoints + offline root."""

    def test_threshold_log_verifies(self):
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        lg = ActionLog(p, signer=ts, roster=roster)
        for i in range(4):
            lg.append({"event": "t", "i": i})
        cp = _log.signed_checkpoint(p, 4)
        self.assertEqual(cp["threshold"], 2)
        self.assertEqual(len(cp["sigs"]), 3)
        self.assertEqual(cp["roster_hash"],
                         _signing.roster_hash(roster))
        verdict = _log.verify_checkpoint_signatures(
            p, trusted_keys={}, roster=roster,
            root_pub=root.public_key)
        self.assertTrue(verdict["ok"], verdict)
        b = _log.prove_inclusion(p, 2)
        ok, err = _log.verify_inclusion_bundle(
            b, {}, roster=roster, root_pub=root.public_key)
        self.assertTrue(ok, err)

    def test_single_compromised_key_cannot_forge_checkpoint(self):
        # A5 attack situation, full loop:
        # 1. OBSERVE FAIL: attacker holds ONE checkpoint key, rewrites
        #    history, and forges a checkpoint with their single valid
        #    signature -> verification FAILS (needs k=2).
        # 2. HARDEN: the legitimate 2-of-3 signing happens.
        # 3. PASS: the hardened checkpoint verifies.
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        lg = ActionLog(p, signer=ts, roster=roster)
        for i in range(3):
            lg.append({"event": "t", "i": i})
        cp = _log.signed_checkpoint(p, 3)
        body = _log._sig_body_for_checkpoint(cp)
        forged_sigs = [{"key_id": signers[0].key_id,
                        "sig": signers[0].sign(body).hex()}]
        forged_cp = dict(cp)
        forged_cp["sigs"] = forged_sigs
        ok, err = _log._verify_one_checkpoint_sig(
            forged_cp, {}, roster=roster, root_pub=root.public_key)
        self.assertFalse(ok)  # step 1: fail observed
        self.assertIn("1/2", err)
        ok, err = _log._verify_one_checkpoint_sig(
            cp, {}, roster=roster, root_pub=root.public_key)
        self.assertTrue(ok, err)  # steps 2+3: hardened passes

    def test_roster_substitution_rejected(self):
        # Attacker swaps their key into a copied roster but cannot get
        # the offline root to sign it -> roster rejected -> checkpoint
        # rejected.
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p, signer=ts, roster=roster).append({"event": "t"})
        evil_signer = _signing.Ed25519Signer(_seed(200))
        evil_roster = json.loads(json.dumps(roster))
        victim = signers[0].key_id
        evil_roster["keys"][victim] = evil_signer.public_key.hex()
        # (no valid root signature over the tampered roster)
        cp = _log.signed_checkpoint(p, 1)
        ok, err = _log._verify_one_checkpoint_sig(
            cp, {}, roster=evil_roster, root_pub=root.public_key)
        self.assertFalse(ok)
        self.assertIn("roster", err)

    def test_wrong_root_rejected(self):
        signers, root, roster, ts = self.threshold_setup(k=2, n=3)
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p, signer=ts, roster=roster).append({"event": "t"})
        other_root = _signing.Ed25519Signer(_seed(101))
        verdict = _log.verify_checkpoint_signatures(
            p, trusted_keys={}, roster=roster,
            root_pub=other_root.public_key)
        self.assertFalse(verdict["ok"])

    def test_threshold_without_roster_failfast(self):
        _, _, _, ts = self.threshold_setup(k=2, n=3)
        d = self.fresh_dir()
        with self.assertRaises(ValueError):
            ActionLog(str(d / "actions.jsonl"), signer=ts, roster=None)

    def test_1of1_threshold_needs_no_roster(self):
        s = _signing.Ed25519Signer(_seed(5))
        ts = _signing.ThresholdSigner([s], 1)
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p, signer=ts, roster=None).append({"event": "t"})
        verdict = _log.verify_checkpoint_signatures(
            p, trusted_keys=self.trust_single(s))
        self.assertTrue(verdict["ok"], verdict)


class AttestationTests(CryptoGovBase):
    """Coker et al.: what is attested, freshness, disclosure bounds."""

    def _attester(self):
        return _signing.Ed25519Signer(_seed(60))

    def _identity(self):
        return _identity.AgentIdentity(
            agent_id="scout-01", role="scout", run_id="run-9",
            principal="org1", provenance="provisioned")

    def _claims(self):
        return {"code_digest": "sha256:abc",
                "config_digest": "sha256:def",
                "tool_policy_digest": "sha256:123"}

    def test_roundtrip_with_freshness(self):
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "challenge-1", att_s)
        ok, err = _identity.verify_attestation(
            att, {att_s.key_id: att_s.public_key},
            expected_nonce="challenge-1", max_age_s=3600)
        self.assertTrue(ok, err)

    def test_wrong_nonce_rejected_replay(self):
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "challenge-1", att_s)
        ok, err = _identity.verify_attestation(
            att, {att_s.key_id: att_s.public_key},
            expected_nonce="challenge-2", max_age_s=3600)
        self.assertFalse(ok)
        self.assertIn("nonce", err)

    def test_stale_and_future_rejected(self):
        from datetime import datetime, timedelta, timezone
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "n", att_s)
        trust = {att_s.key_id: att_s.public_key}
        old_now = datetime.now(timezone.utc) + timedelta(hours=2)
        ok, _ = _identity.verify_attestation(
            att, trust, expected_nonce="n", max_age_s=60, now=old_now)
        self.assertFalse(ok)  # stale
        early_now = datetime.now(timezone.utc) - timedelta(hours=2)
        ok, _ = _identity.verify_attestation(
            att, trust, expected_nonce="n", max_age_s=3600 * 5,
            now=early_now)
        self.assertFalse(ok)  # issued in the "future" vs verifier clock

    def test_unknown_attester_rejected(self):
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "n", att_s)
        other = _signing.Ed25519Signer(_seed(61))
        ok, _ = _identity.verify_attestation(
            att, {other.key_id: other.public_key}, expected_nonce="n")
        self.assertFalse(ok)

    def test_tampered_claim_rejected(self):
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "n", att_s)
        tampered = json.loads(json.dumps(att))
        tampered["claims"]["code_digest"] = "sha256:evil"
        ok, _ = _identity.verify_attestation(
            tampered, {att_s.key_id: att_s.public_key},
            expected_nonce="n")
        self.assertFalse(ok)

    def test_nonflat_claims_rejected_at_build(self):
        att_s = self._attester()
        with self.assertRaises(ValueError):
            _identity.build_attestation(
                self._identity(), {"nested": {"a": 1}}, "n", att_s)
        with self.assertRaises(ValueError):
            _identity.build_attestation(
                self._identity(), {}, "n", att_s)

    def test_no_measurement_validation_claimed(self):
        # Explicit non-claim (Coker): the envelope authenticates the
        # ASSERTION, it never validates that a digest is true. Any
        # string digest builds fine -- no hardware measurement implied.
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), {"code_digest": "not-a-real-digest"},
            "n", att_s)
        ok, _ = _identity.verify_attestation(
            att, {att_s.key_id: att_s.public_key}, expected_nonce="n")
        self.assertTrue(ok)

    def test_freshness_optout_is_explicit(self):
        # Without nonce/age inputs the signature still verifies; the
        # caller owns the replay risk (documented, never accidental).
        att_s = self._attester()
        att = _identity.build_attestation(
            self._identity(), self._claims(), "n", att_s)
        ok, err = _identity.verify_attestation(
            att, {att_s.key_id: att_s.public_key})
        self.assertTrue(ok, err)


class AnchorTests(CryptoGovBase):
    """K-049: transparency-log anchoring (fake log test double)."""

    def _anchored(self, n=4):
        lg, path, signer = self.signed_log(n=n)
        tlog = _anchor.FakeTransparencyLog(_seed(50))
        cp = _log.signed_checkpoint(path, n)
        entry, ah = _anchor.anchor_checkpoint(path, n, tlog)
        return path, signer, tlog, cp, entry, ah

    def test_anchor_roundtrip(self):
        path, signer, tlog, cp, entry, ah = self._anchored()
        ok, err = _anchor.verify_anchor(entry, cp, tlog.public_key)
        self.assertTrue(ok, err)
        self.assertEqual(entry["anchor"]["prev_anchor"],
                         _anchor.GENESIS_ANCHOR)

    def test_anchor_chain(self):
        path, signer, tlog, cp, e1, ah1 = self._anchored(n=3)
        lg = ActionLog(path, signer=signer)
        lg.append({"event": "more"})
        cp4 = _log.signed_checkpoint(path, 4)
        e2, ah2 = _anchor.anchor_checkpoint(path, 4, tlog,
                                            prev_anchor_hash=ah1)
        ok, err = _anchor.verify_anchor(e2, cp4, tlog.public_key,
                                        expected_prev=ah1)
        self.assertTrue(ok, err)
        ok, _ = _anchor.verify_anchor(e2, cp4, tlog.public_key,
                                      expected_prev="00" * 32)
        self.assertFalse(ok)

    def test_idempotent_resubmit(self):
        path, signer, tlog, cp, e1, ah1 = self._anchored()
        e1b, ah1b = _anchor.anchor_checkpoint(path, 4, tlog)
        self.assertEqual(e1b["log_index"], e1["log_index"])
        self.assertEqual(len(tlog), 1)

    def test_equivocation_refused_with_evidence(self):
        path, signer, tlog, cp, e1, ah1 = self._anchored(n=3)
        evil = dict(cp)
        evil["merkle_root"] = "ff" * 32
        with self.assertRaises(_anchor.EquivocationError) as ctx:
            tlog.submit(_anchor.build_anchor(evil, tlog.public_key,
                                             ah1))
        first_set, conflicting = ctx.exception.evidence
        self.assertEqual(first_set["log_index"], 0)
        self.assertEqual(conflicting["checkpoint"]["merkle_root"],
                         "ff" * 32)

    def test_wrong_log_rejected(self):
        path, signer, tlog, cp, entry, ah = self._anchored()
        other = _anchor.FakeTransparencyLog(_seed(51))
        ok, _ = _anchor.verify_anchor(entry, cp, other.public_key)
        self.assertFalse(ok)

    def test_tampered_inclusion_proof_rejected(self):
        path, signer, tlog, cp, entry, ah = self._anchored()
        bad = dict(entry)
        bad["inclusion_proof"] = ["00" * 64]
        ok, _ = _anchor.verify_anchor(bad, cp, tlog.public_key)
        self.assertFalse(ok)

    def test_substituted_checkpoint_rejected(self):
        path, signer, tlog, cp, entry, ah = self._anchored(n=3)
        lg = ActionLog(path, signer=signer)
        lg.append({"event": "more"})
        cp4 = _log.signed_checkpoint(path, 4)
        ok, _ = _anchor.verify_anchor(entry, cp4, tlog.public_key)
        self.assertFalse(ok)

    def test_broken_chain_rejected(self):
        path, signer, tlog, cp, e1, ah1 = self._anchored(n=3)
        lg = ActionLog(path, signer=signer)
        lg.append({"event": "more"})
        cp4 = _log.signed_checkpoint(path, 4)
        with self.assertRaises(ValueError):
            tlog.submit(_anchor.build_anchor(cp4, tlog.public_key,
                                             "ff" * 32))

    def test_anchor_needs_signed_checkpoint(self):
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p).append({"event": "x"})
        tlog = _anchor.FakeTransparencyLog(_seed(50))
        with self.assertRaises(ValueError):
            _anchor.anchor_checkpoint(p, 1, tlog)


class ExportTests(CryptoGovBase):
    """K-060: the audit trail as a live, verifiable capability."""

    def _log_with_principals(self):
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        signer = _signing.Ed25519Signer(_seed(8))
        lg = ActionLog(p, signer=signer)
        events = [
            {"event": "tool_call", "principal": "org1", "agent_id": "a1",
             "tool": "read"},
            {"event": "tool_call", "principal": "org2", "agent_id": "a2",
             "tool": "write"},
            {"event": "approval", "principal": "org1", "agent_id": "a1",
             "decision": "APPROVED"},
            {"event": "tool_call", "principal": "org1", "agent_id": "a1",
             "tool": "exec"},
        ]
        for e in events:
            lg.append(dict(e))
        return p, signer

    def test_query_filters(self):
        p, signer = self._log_with_principals()
        self.assertEqual(len(_log.query_log(p, principal="org1")), 3)
        self.assertEqual(len(_log.query_log(p, principal="org2")), 1)
        self.assertEqual(
            len(_log.query_log(p, event="approval")), 1)
        self.assertEqual(
            len(_log.query_log(p, principal="org1", limit=2)), 2)
        self.assertEqual(_log.query_log(p, principal="nobody"), [])

    def test_export_roundtrip(self):
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="org1")
        self.assertEqual(len(bundle["entries"]), 3)
        self.assertEqual(len(bundle["proofs"]), 3)
        self.assertTrue(bundle["checkpoints"])
        ok, err = _log.verify_export_bundle(bundle, trust)
        self.assertTrue(ok, err)

    def test_export_tampered_entry_fails(self):
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="org1")
        bundle["entries"][0] = dict(bundle["entries"][0])
        bundle["entries"][0]["tool"] = "EVIL"
        ok, _ = _log.verify_export_bundle(bundle, trust)
        self.assertFalse(ok)

    def test_export_omission_is_visible_not_cryptographic(self):
        # Honest scope pin: the bundle authenticates INCLUDED entries;
        # it does not prove filter-completeness (an exporter who omits
        # entries is the deployment itself -- K-049's anchor is the
        # control for that). The applied filter is recorded in the
        # bundle's "query" field so the omission is VISIBLE.
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="org1")
        bundle["entries"].pop(1)
        ok, err = _log.verify_export_bundle(bundle, trust)
        self.assertTrue(ok, err)  # included entries still genuine
        self.assertEqual(bundle["query"], {"principal": "org1"})

    def test_export_reordered_fails(self):
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="org1")
        bundle["entries"][0], bundle["entries"][1] = \
            bundle["entries"][1], bundle["entries"][0]
        ok, _ = _log.verify_export_bundle(bundle, trust)
        self.assertFalse(ok)

    def test_export_tampered_proof_fails(self):
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="org1")
        seq = str(bundle["entries"][0]["seq"])
        proof = bundle["proofs"][seq]["proof"]
        if proof:
            bad = [bytes.fromhex(x) for x in proof]
            bad[0] = bytes(x ^ 1 for x in bad[0])
            bundle["proofs"][seq]["proof"] = [x.hex() for x in bad]
        else:
            bundle["proofs"][seq]["proof"] = ["00" * 64]
        ok, _ = _log.verify_export_bundle(bundle, trust)
        self.assertFalse(ok)

    def test_export_empty_verifies(self):
        p, signer = self._log_with_principals()
        trust = {signer.key_id: signer.public_key}
        bundle = _log.export_bundle(p, principal="nobody")
        self.assertEqual(bundle["entries"], [])
        ok, err = _log.verify_export_bundle(bundle, trust)
        self.assertTrue(ok, err)

    def test_export_carries_no_private_key_material(self):
        p, signer = self._log_with_principals()
        bundle = _log.export_bundle(p)
        blob = json.dumps(bundle)
        self.assertNotIn("seed", blob)


class LedgerTaintTests(CryptoGovBase):
    """K-025: cross-run memory/context poisoning protection.

    Characterization of the existing F15/F17 controls (the actionable
    note described an older unkeyed ledger; the current ledger is
    HMAC-authenticated): taint marks carry across runs, and any
    tampering with the marks fails CLOSED -- never silent untaint.
    """

    def _ledger(self, d):
        return EgressLedger(str(Path(d) / "egress.jsonl"))

    def test_taint_carries_across_runs(self):
        d = self.fresh_dir()
        run1 = self._ledger(d)
        run1.taint_mark("org1", "run-N")
        # Run N+1: a FRESH ledger object over the same file inherits
        # the taint (the cross-run context carry-over).
        run2 = self._ledger(d)
        self.assertTrue(run2.taint_active("org1"))
        self.assertFalse(run2.taint_active("org2"))

    def test_taint_expires(self):
        d = self.fresh_dir()
        lg = self._ledger(d)
        lg.taint_mark("org1", "run-N", now=1000.0)
        self.assertTrue(lg.taint_active("org1", now=1000.0 + 10))
        self.assertFalse(
            lg.taint_active("org1", now=1000.0 + 25 * 3600))

    def test_tampered_mark_fails_closed(self):
        # Attack: flip the taint entry's principal in place. The mark
        # must NOT silently clear -- require_verified raises, and
        # taint_active (which verifies first) raises too.
        d = self.fresh_dir()
        lg = self._ledger(d)
        lg.taint_mark("org1", "run-N")
        p = Path(d) / "egress.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        self.assertTrue(lines)
        entry = json.loads(lines[-1])
        entry["principal"] = "orgX"
        lines[-1] = json.dumps(entry)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(LedgerUnverifiableError):
            self._ledger(d).require_verified()
        with self.assertRaises(LedgerUnverifiableError):
            self._ledger(d).taint_active("org1")

    def test_deleted_mark_fails_closed(self):
        # Attack: truncate the taint entry away. Checkpoint-anchored
        # verification rejects the truncation -- fail closed.
        d = self.fresh_dir()
        lg = self._ledger(d)
        lg.taint_mark("org1", "run-N")
        lg.append({"kind": "egress", "principal": "org1",
                   "endpoint": "https://x.synthetic.local/"})
        p = Path(d) / "egress.jsonl"
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")
        with self.assertRaises(LedgerUnverifiableError):
            self._ledger(d).taint_active("org1")

    def test_no_ledger_no_taint(self):
        d = self.fresh_dir()
        self.assertFalse(self._ledger(d).taint_active("org1"))


class VerifyCLITests(CryptoGovBase):
    def test_cli_proof_and_sigs_and_export(self):
        from gov.verify import main as verify_main
        lg, path, signer = self.signed_log(n=4)
        trust_path = str(self.fresh_dir() / "trust.json")
        Path(trust_path).write_text(
            json.dumps({signer.key_id: signer.public_key.hex()}),
            encoding="utf-8")
        self.assertEqual(
            verify_main([path, "--proof", "2", "--sig-trust",
                         trust_path]), 0)
        self.assertEqual(
            verify_main([path, "--sigs", "--sig-trust", trust_path]),
            0)
        self.assertEqual(
            verify_main([path, "--consistency", "1", "--sig-trust",
                         trust_path]), 0)
        self.assertEqual(verify_main([path, "--export"]), 0)

    def test_cli_require_signed_rejects_unsigned(self):
        from gov.verify import main as verify_main
        d = self.fresh_dir()
        p = str(d / "actions.jsonl")
        ActionLog(p).append({"event": "x"})
        self.assertEqual(
            verify_main([p, "--sigs", "--require-signed"]), 1)

    def test_cli_proof_bad_seq_fails(self):
        from gov.verify import main as verify_main
        lg, path, signer = self.signed_log(n=2)
        self.assertEqual(verify_main([path, "--proof", "99"]), 1)


if __name__ == "__main__":
    unittest.main()
