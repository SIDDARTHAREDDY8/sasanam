#!/usr/bin/env python3
"""Unit tests for gov/checkpoints.py (wave-229 lane A).

Peak vectors are computed with an independent inline MMR walk (plain
hashlib, no checkpoints module) so the expected values do not come
from the code under test.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import unittest

from gov import checkpoints as cp
from gov.alg_registry import default_registry

ED = "ed25519-rfc8032"
MAC = "hmac-sha256-mac"

_DOM = b"gov-checkpoints/v1\x00"


def _leaf(d):
    return hashlib.sha256(_DOM + b"leaf\x00" + bytes.fromhex(d)).hexdigest()


def _node(left, right):
    return hashlib.sha256(_DOM + b"node\x00" + bytes.fromhex(left)
                          + bytes.fromhex(right)).hexdigest()


def _independent_peaks(digests):
    stack = []
    for d in digests:
        h, node = 0, _leaf(d)
        while stack and stack[-1][0] == h:
            _, left = stack.pop()
            node = _node(left, node)
            h += 1
        stack.append((h, node))
    return [n for _, n in stack]


def _d(i):
    return hashlib.sha256(("e%d" % i).encode()).hexdigest()


class TestMMRStructure(unittest.TestCase):
    def test_peak_counts_match_independent_walk(self):
        for n in (1, 2, 3, 4, 5, 7, 8, 15, 16, 23):
            digests = [_d(i) for i in range(n)]
            mmr = cp.MerkleMountainRange()
            for d in digests:
                mmr.append(d)
            self.assertEqual(mmr.peaks(), _independent_peaks(digests),
                             "n=%d" % n)
            self.assertEqual(mmr.count(), n)

    def test_known_peak_counts(self):
        mmr = cp.MerkleMountainRange()
        for i in range(7):
            mmr.append(_d(i))
        self.assertEqual(len(mmr.peaks()), 3)  # 4 + 2 + 1
        mmr.append(_d(7))
        self.assertEqual(len(mmr.peaks()), 1)  # perfect 8

    def test_malformed_append_refused(self):
        mmr = cp.MerkleMountainRange()
        with self.assertRaises(cp.CheckpointError) as ctx:
            mmr.append("not-hex")
        self.assertEqual(ctx.exception.code, "checkpoint-malformed")


class TestCheckpointRoundTrip(unittest.TestCase):
    def _signed(self, n=5, alg=ED):
        reg = default_registry()
        secret, pub = reg.keygen(alg)
        digests = [_d(i) for i in range(n)]
        mmr = cp.MerkleMountainRange()
        for d in digests:
            mmr.append(d)
        checkpoint = mmr.checkpoint(alg, secret, "k-unit")
        return digests, checkpoint, pub

    def test_ed25519_round_trip(self):
        digests, checkpoint, pub = self._signed(5, ED)
        out = cp.verify_checkpoint(checkpoint, digests, pub)
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 5)
        self.assertTrue(out["non_repudiation"])

    def test_mac_round_trip_honest_label(self):
        reg = default_registry()
        secret, _ = reg.keygen(MAC)
        digests = [_d(i) for i in range(3)]
        mmr = cp.MerkleMountainRange()
        for d in digests:
            mmr.append(d)
        checkpoint = mmr.checkpoint(MAC, secret, "k-mac")
        # expect_alg pins the symmetric tier: the caller declares the
        # key a shared secret (algorithm-confusion guard, CWE-347).
        out = cp.verify_checkpoint(checkpoint, digests, secret,
                                   expect_alg=MAC)
        self.assertTrue(out["ok"])
        self.assertFalse(out["non_repudiation"])

    def test_substituted_content_refused(self):
        digests, checkpoint, pub = self._signed(5)
        tampered = list(digests)
        tampered[0] = _d(1000)
        with self.assertRaises(cp.CheckpointError) as ctx:
            cp.verify_checkpoint(checkpoint, tampered, pub)
        self.assertEqual(ctx.exception.code, "checkpoint-log-reordered")

    def test_chain_break_on_gap(self):
        reg = default_registry()
        seed, pub = reg.keygen(ED)
        mmr = cp.MerkleMountainRange()
        chain = []
        prev = None
        for i in range(3):
            mmr.append(_d(i))
            checkpoint = mmr.checkpoint(ED, seed, "k", prev_checkpoint=prev)
            chain.append(checkpoint)
            prev = checkpoint
        out = cp.verify_checkpoint_chain(chain, [pub] * 3)
        self.assertTrue(out["ok"])
        self.assertEqual(out["checked"], 3)
        with self.assertRaises(cp.CheckpointError) as ctx:
            cp.verify_checkpoint_chain(chain[::2], [pub] * 2)
        self.assertEqual(ctx.exception.code, "checkpoint-chain-broken")


class TestEvidence(unittest.TestCase):
    def test_evidence_tamper_evident(self):
        reg = default_registry()
        seed, pub = reg.keygen(ED)
        mmr = cp.MerkleMountainRange()
        mmr.append(_d(0))
        checkpoint = mmr.checkpoint(ED, seed, "k")
        ev = cp.checkpoint_evidence(checkpoint)
        before = cp.evidence_digest(ev)
        ev2 = dict(ev)
        ev2["peaks_digest"] = "ff" * 32
        self.assertNotEqual(cp.evidence_digest(ev2), before)
        with self.assertRaises(cp.CheckpointError) as ctx:
            cp.evidence_as_authority(ev)
        self.assertEqual(ctx.exception.code,
                         "checkpoint-evidence-not-authorization")


if __name__ == "__main__":
    unittest.main()
