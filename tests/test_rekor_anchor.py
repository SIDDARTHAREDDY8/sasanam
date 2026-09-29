"""Rekor transparency anchoring: focused break/fix tests (wave-194 lane D).

Load-bearing guarantees under test:
1. Rekor entries are digest-existence evidence only -- a receipt can
   NEVER be presented as authority (present_as_authority always raises).
2. verify_inclusion is stale-proof aware: a self-consistent inclusion
   proof against an OLD root is refused, never trusted.
3. The product witness independently recomputes the RFC 6962 root and
   refuses same-size/different-root checkpoints as equivocation.
4. The self-hosted client refuses Sigstore production pins, so a prod
   deployment can never silently depend on the hosted service.

Hermetic: in-memory FakeRekor (dict-contract transport), openssl-
generated ECDSA keys in a tmpdir, real format-2 Sasanam checkpoints
and sealed evidence-bundle manifests, no network, no repo mutation.
Deterministic except wall-clock ts (never asserted on).
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import rekor_anchor as ra  # noqa: E402
from gov import ed25519 as _ed  # noqa: E402
from gov import log as _log  # noqa: E402
from gov import evidence_bundle as _eb  # noqa: E402
from gov import signing as _signing  # noqa: E402


class FakeRekor:
    """Deterministic in-memory Rekor v1 (dict-contract transport).

    Maintains a real RFC 6962 tree over the exact posted entry bytes,
    so inclusion proofs are self-consistent and go stale exactly like
    the live server's when the tree grows.
    """

    def __init__(self):
        self.log_id = "test-log-id-0123456789abcdef"
        self.tree_id = "424242"
        self.bodies = []  # raw posted entry bytes, index order
        self.down = False

    def _root(self):
        return ra._r6962_root(
            [ra._r6962_leaf(b) for b in self.bodies])

    def _entry_for(self, idx):
        leaf_hashes = [ra._r6962_leaf(b) for b in self.bodies]
        proof = ra._r6962_inclusion_proof(leaf_hashes, idx)
        return {
            "body": base64.b64encode(self.bodies[idx]).decode("ascii"),
            "integratedTime": 1700000000 + idx,
            "logIndex": idx,
            "logID": self.log_id,
            "verification": {
                "inclusionProof": {
                    "hashes": [h.hex() for h in proof],
                    "rootHash": self._root().hex(),
                    "treeSize": len(self.bodies),
                    "logIndex": idx,
                    "checkpoint": "fake-checkpoint-%d" % len(self.bodies),
                },
                "signedEntryTimestamp": "fake-set-%d" % idx,
            },
        }

    def __call__(self, request):
        if self.down:
            raise ra.RekorDownError("rekor is down (test)")
        method = request.get("method", "POST")
        url = request["url"]
        if method == "POST" and url.endswith("/api/v1/log/entries"):
            body = request["body"].encode("utf-8")
            self.bodies.append(body)
            idx = len(self.bodies) - 1
            return {"status": 200,
                    "body": json.dumps(
                        {"fakeuuid%06d" % idx: self._entry_for(idx)})}
        if method == "GET" and url.endswith("/api/v1/log"):
            return {"status": 200, "body": json.dumps({
                "treeID": self.tree_id,
                "treeSize": len(self.bodies),
                "rootHash": self._root().hex(),
                "signedTreeHead": "fake-sth"})}
        if method == "GET" and "/api/v1/log/entries/" in url:
            uuid = url.rsplit("/", 1)[1]
            idx = int(uuid.replace("fakeuuid", ""))
            return {"status": 200,
                    "body": json.dumps({uuid: self._entry_for(idx)})}
        raise AssertionError("unexpected request %s %s" % (method, url))


def _openssl(*args, cwd, input=None):
    return subprocess.run(["openssl"] + list(args), cwd=cwd,
                          input=input, capture_output=True, check=True)


class RekorAnchorBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="rekor-anchor-test-")
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout",
                 "-out", "op.key", cwd=cls.tmp)
        _openssl("ec", "-in", "op.key", "-pubout", "-out", "op.pub.pem",
                 cwd=cls.tmp)
        with open(os.path.join(cls.tmp, "op.pub.pem")) as fh:
            cls.pubkey_pem = fh.read()
        assert "BEGIN PUBLIC KEY" in cls.pubkey_pem
        # One real format-2 checkpoint + one sealed bundle manifest.
        cls.log_path = os.path.join(cls.tmp, "audit.log")
        signer = _signing.Ed25519Signer(bytes.fromhex("33" * 32))
        log = _log.ActionLog(cls.log_path, signer=signer,
                             deployment_mode="staging")
        log.append({"event": "policy_loaded", "policy_hash": "p" * 16,
                    "policy_path": "policies/p1.yaml", "pinned": True,
                    "policy_version": "1.0"})
        log.append({"event": "approval_decision", "decision": "approve",
                    "ticket": "T-194"})
        cls.checkpoint = log.write_checkpoint()
        eb = _eb.EvidenceBundle(cls.log_path, operator_id="test-194")
        payload = eb.build()
        cls.manifest = eb.seal(payload, signer=signer)
        assert cls.checkpoint.get("format_version") == 2
        # the real sealed shape: kind + receipt envelope
        assert cls.manifest.get("kind") == "evidence_bundle_manifest"
        assert "receipt" in cls.manifest

    def setUp(self):
        self.fake = FakeRekor()
        self.client = ra.SelfHostedRekor(
            "http://rekor-test.local:3000",
            self.fake.log_id,
            transport=self.fake)

    def _sign(self, digest):
        # Raw ECDSA sign over the 32-byte digest (the shape real Rekor
        # verifies: WithDigest. `dgst -sha256 -sign` would double-hash
        # and be rejected -- see docs/REKOR_RUNBOOK.md).
        r = _openssl("pkeyutl", "-sign", "-inkey", "op.key",
                     cwd=self.tmp, input=bytes(digest))
        return (base64.b64encode(r.stdout).decode("ascii"),
                self.pubkey_pem, "ecdsa-p256-sha256")

    def _anchor(self, digest_hex):
        return self.client.submit(
            digest_hex,
            signature_b64=self._sign(bytes.fromhex(digest_hex))[0],
            pubkey_pem=self.pubkey_pem)


class Rfc6962Tests(RekorAnchorBase):
    def test_verify_proof_matches_anchor_backend(self):
        # The local single-leaf verifier must agree with
        # gov.anchor_backend._rfc6962_root for every tree size/index.
        from gov import anchor_backend as ab
        for n in range(1, 9):
            leaves = [b"leaf-%d" % i for i in range(n)]
            leaf_hashes = [ra._r6962_leaf(l) for l in leaves]
            for idx in range(n):
                proof = ra._r6962_inclusion_proof(leaf_hashes, idx)
                proof_hex = [h.hex() for h in proof]
                mine = ra._r6962_verify_proof(
                    leaves[idx], idx, proof_hex, n)
                theirs = ab._rfc6962_root(
                    leaves[idx], idx, proof_hex, n)
                self.assertEqual(mine, theirs)

    def test_verify_proof_rejects_malformed(self):
        with self.assertRaises(ValueError):
            ra._r6962_verify_proof(b"x", 0, ["zz"], 1)
        with self.assertRaises(ValueError):
            ra._r6962_verify_proof(b"x", 5, [], 1)


class ConfigTests(RekorAnchorBase):
    def test_requires_explicit_url(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor(None, "abc")
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor("", "abc")

    def test_requires_explicit_log_id(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor("http://rekor.local:3000", None)
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor("http://rekor.local:3000", "")

    def test_refuses_sigstore_prod_url(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor("https://rekor.sigstore.dev", "abc")

    def test_refuses_prod_url_variants(self):
        # Case variants and default-port forms still match the pin.
        for url in ("HTTPS://REKOR.SIGSTORE.DEV",
                    "https://rekor.sigstore.dev:443",
                    "https://rekor.sigstore.dev:443/"):
            with self.assertRaises(ra.RekorConfigError):
                ra.SelfHostedRekor(url, "abc")

    def test_refuses_sigstore_prod_log_id(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.SelfHostedRekor("http://rekor.local:3000",
                               ra._ab.REKOR_LOG_ID)


class LayeringTests(RekorAnchorBase):
    def test_receipt_is_digest_existence_only(self):
        receipt = self._anchor("ab" * 32)
        self.assertEqual(receipt["evidentiary_grade"],
                         "digest-existence-only")
        self.assertFalse(receipt["authority_proof"])
        self.assertEqual(ra.grade_receipt(receipt),
                         "digest-existence-only")

    def test_present_as_authority_always_raises(self):
        receipt = self._anchor("ab" * 32)
        with self.assertRaises(ra.RekorLayeringError):
            ra.present_as_authority(receipt)
        # even a hand-forged "perfect" receipt cannot become authority
        forged = dict(receipt)
        forged["authority_proof"] = True
        forged["evidentiary_grade"] = "authority"
        with self.assertRaises(ra.RekorLayeringError):
            ra.present_as_authority(forged)

    def test_submit_refuses_raw_ed25519(self):
        # F203: real Rekor v1.5.4 rejects raw ed25519 (needs Ed25519ph)
        with self.assertRaises(ra.RekorConfigError):
            self.client.submit(
                "ab" * 32, signature_b64=base64.b64encode(b"x" * 64),
                pubkey_pem=self.pubkey_pem, algorithm="ed25519")

    def test_submit_refuses_bad_digest(self):
        with self.assertRaises(ra.RekorConfigError):
            self.client.submit(
                "not-a-digest",
                signature_b64=self._sign(bytes.fromhex("ab" * 32))[0],
                pubkey_pem=self.pubkey_pem)

    def test_rejects_wrong_log_id(self):
        receipt = self._anchor("ab" * 32)
        receipt["log_id"] = "attacker-log"
        ok, reason = ra.verify_inclusion(
            receipt, "ab" * 32, client=self.client)
        self.assertFalse(ok)
        self.assertIn("different transparency log", reason)


class InclusionTests(RekorAnchorBase):
    def test_anchor_and_verify_checkpoint(self):
        ahash, receipt = ra.anchor_checkpoint_sth(
            self.checkpoint, client=self.client, sign=self._sign)
        self.assertEqual(len(ahash), 64)
        ok, reason = ra.verify_inclusion(
            receipt, ahash, client=self.client)
        self.assertTrue(ok, reason)

    def test_anchor_and_verify_sealed_manifest(self):
        ahash, receipt = ra.anchor_bundle_manifest(
            self.manifest, client=self.client, sign=self._sign)
        ok, reason = ra.verify_inclusion(
            receipt, ahash, client=self.client)
        self.assertTrue(ok, reason)

    def test_anchor_refuses_unsigned_checkpoint(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.anchor_checkpoint_sth({"format_version": 1},
                                     client=self.client, sign=self._sign)

    def test_anchor_refuses_unsealed_manifest(self):
        with self.assertRaises(ra.RekorConfigError):
            ra.anchor_bundle_manifest({"bundle_id": "x"},
                                      client=self.client, sign=self._sign)

    def test_digest_mismatch_refused(self):
        receipt = self._anchor("ab" * 32)
        ok, reason = ra.verify_inclusion(
            receipt, "ff" * 32, client=self.client)
        self.assertFalse(ok)
        self.assertIn("different anchor", reason)

    def test_stale_proof_refused(self):
        # Anchor A, then grow the tree with B: A's stored proof is now
        # stale (internally valid for the old root, not the current
        # checkpoint) -- the wave-193 spike's live observation.
        receipt_a = self._anchor("aa" * 32)
        self._anchor("bb" * 32)
        ok, reason = ra.verify_inclusion(
            receipt_a, "aa" * 32, client=self.client)
        self.assertFalse(ok)
        self.assertIn("STALE", reason)

    def test_refreshed_proof_accepted(self):
        # An auditor re-fetches the entry (fresh-proof semantics) and
        # the same artifact then verifies.
        receipt_a = self._anchor("aa" * 32)
        self._anchor("bb" * 32)
        fresh = self.client.get_entry(receipt_a["uuid"])
        receipt_a["inclusion_proof"] = self.client.proof_of(fresh)
        ok, reason = ra.verify_inclusion(
            receipt_a, "aa" * 32, client=self.client)
        self.assertTrue(ok, reason)

    def test_server_down_fails_closed(self):
        receipt = self._anchor("ab" * 32)
        self.fake.down = True
        ok, reason = ra.verify_inclusion(
            receipt, "ab" * 32, client=self.client)
        self.assertFalse(ok)
        self.assertIn("checkpoint", reason)

    def test_future_integrated_time_refused_via_injected_clock(self):
        # The future-integrated_time guard reads the injectable
        # clock (not wall time), so skew is testable.
        receipt = self._anchor("ab" * 32)
        receipt["integrated_time"] = 2000000000
        past_client = ra.SelfHostedRekor(
            "http://rekor-test.local:3000", self.fake.log_id,
            transport=self.fake, clock=lambda: 1000000000)
        ok, reason = ra.verify_inclusion(
            receipt, "ab" * 32, client=past_client)
        self.assertFalse(ok)
        self.assertIn("future", reason)


class WitnessTests(RekorAnchorBase):
    def _rekor_checkpoint_view(self):
        self._anchor("aa" * 32)
        self._anchor("bb" * 32)
        return self.client.fetch_checkpoint(), list(self.fake.bodies)

    def test_witness_cosigns_honest_checkpoint(self):
        checkpoint, leaves = self._rekor_checkpoint_view()
        w = ra.RekorWitness(_ed.generate_seed())
        cosig, reason = w.cosign_checkpoint(checkpoint, leaves)
        self.assertIsNotNone(cosig, reason)
        registry = {w.witness_id: w.pubkey_hex}
        ok, reason = ra.verify_witness_cosignatures(
            checkpoint, [cosig], registry, quorum=1)
        self.assertTrue(ok, reason)

    def test_witness_refuses_equivocation(self):
        # Forged checkpoint: same size, different root, even with a
        # "valid" operator signature story -- the witness recomputes
        # and refuses (wave-193 spike R3).
        checkpoint, leaves = self._rekor_checkpoint_view()
        forged = dict(checkpoint)
        forged["root_hash"] = "ff" * 32
        w = ra.RekorWitness(_ed.generate_seed())
        cosig, reason = w.cosign_checkpoint(forged, leaves)
        self.assertIsNone(cosig)
        self.assertIn("EQUIVOCATION", reason)
        self.assertEqual(len(w.equivocations_seen), 1)
        self.assertEqual(
            w.equivocations_seen[0]["claimed_root"], "ff" * 32)

    def test_witness_rejects_leaf_count_mismatch(self):
        checkpoint, leaves = self._rekor_checkpoint_view()
        w = ra.RekorWitness(_ed.generate_seed())
        cosig, reason = w.cosign_checkpoint(checkpoint, leaves[:-1])
        self.assertIsNone(cosig)
        self.assertIn("never advances blind", reason)

    def test_witness_rejects_malformed_checkpoint(self):
        w = ra.RekorWitness(_ed.generate_seed())
        cosig, reason = w.cosign_checkpoint({"tree_size": "x"}, [])
        self.assertIsNone(cosig)

    def test_quorum_needs_distinct_witnesses(self):
        checkpoint, leaves = self._rekor_checkpoint_view()
        seeds = [_ed.generate_seed() for _ in range(3)]
        ws = [ra.RekorWitness(s) for s in seeds]
        cosigs = []
        for w in ws:
            cosig, reason = w.cosign_checkpoint(checkpoint, leaves)
            self.assertIsNotNone(cosig, reason)
            cosigs.append(cosig)
        registry = {w.witness_id: w.pubkey_hex for w in ws}
        ok, _ = ra.verify_witness_cosignatures(
            checkpoint, cosigs[:2], registry, quorum=2)
        self.assertTrue(ok)
        # same witness twice does not satisfy quorum
        ok, reason = ra.verify_witness_cosignatures(
            checkpoint, [cosigs[0], cosigs[0]], registry, quorum=2)
        self.assertFalse(ok)
        self.assertIn("2 witness", reason)
        # one of two is not enough
        ok, _ = ra.verify_witness_cosignatures(
            checkpoint, cosigs[:1], registry, quorum=2)
        self.assertFalse(ok)
        # unknown witness is ignored
        bad = dict(cosigs[0])
        bad["witness_id"] = "mallory"
        ok, _ = ra.verify_witness_cosignatures(
            checkpoint, [bad, cosigs[1]], registry, quorum=2)
        self.assertFalse(ok)


class OfflineBundleTests(RekorAnchorBase):
    def _bundle(self, with_witness=False):
        ahash, receipt = ra.anchor_checkpoint_sth(
            self.checkpoint, client=self.client, sign=self._sign)
        checkpoint = self.client.fetch_checkpoint()
        leaves = list(self.fake.bodies)
        cosigs = []
        registry = {}
        if with_witness:
            w = ra.RekorWitness(_ed.generate_seed())
            cosig, reason = w.cosign_checkpoint(checkpoint, leaves)
            assert cosig, reason
            cosigs = [cosig]
            registry = {w.witness_id: w.pubkey_hex}
        bundle = ra.build_offline_bundle(
            anchor_hash=ahash, receipt=receipt, checkpoint=checkpoint,
            leaves=leaves, witness_cosigs=cosigs)
        return bundle, registry

    def test_offline_bundle_verifies_with_server_down(self):
        bundle, registry = self._bundle(with_witness=True)
        self.fake.down = True  # server unavailable from here on
        ok, reason = ra.verify_offline_bundle(
            bundle, witness_registry=registry, quorum=1)
        self.assertTrue(ok, reason)

    def test_offline_bundle_requires_quorum(self):
        # The regulator-facing path fails closed without witnesses.
        bundle, registry = self._bundle(with_witness=True)
        ok, reason = ra.verify_offline_bundle(bundle)
        self.assertFalse(ok)
        self.assertIn("registry", reason)
        ok, reason = ra.verify_offline_bundle(
            bundle, witness_registry=registry, quorum=0)
        self.assertFalse(ok)
        self.assertIn("quorum", reason)

    def test_offline_bundle_tampered_leaf_fails(self):
        bundle, registry = self._bundle(with_witness=True)
        bundle["leaves_b64"][0] = base64.b64encode(b"tampered").decode()
        ok, reason = ra.verify_offline_bundle(
            bundle, witness_registry=registry, quorum=1)
        self.assertFalse(ok)
        self.assertIn("root", reason)

    def test_offline_bundle_tampered_checkpoint_fails(self):
        bundle, registry = self._bundle(with_witness=True)
        bundle["checkpoint"]["root_hash"] = "00" * 32
        ok, _ = ra.verify_offline_bundle(
            bundle, witness_registry=registry, quorum=1)
        self.assertFalse(ok)

    def test_offline_bundle_tampered_entry_fails(self):
        bundle, registry = self._bundle(with_witness=True)
        body = json.loads(base64.b64decode(bundle["receipt"]["body"]))
        body["spec"]["data"]["hash"]["value"] = "ff" * 32
        bundle["receipt"]["body"] = base64.b64encode(
            json.dumps(body).encode()).decode()
        ok, _ = ra.verify_offline_bundle(
            bundle, witness_registry=registry, quorum=1)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
