"""Unit tests for gov/vsa_threshold (wave-324 lane 3).

Multi-verifier threshold VSA decision packets. Deterministic (fixed
seeds); stdlib only.
"""

import copy
import unittest

from gov import vsa_threshold as vt
from gov.signing import Ed25519Signer

SEED_V1 = bytes(range(32))
SEED_V2 = bytes([255 - i for i in range(32)])
SEED_V3 = bytes([(i * 7) % 256 for i in range(32)])
SEED_EVIL = bytes([(i * 29 + 5) % 256 for i in range(32)])

DECISION = "a" * 64
NOW = 1798765432.0  # 2027-01-01T01:03:52Z
FRESH = "2027-01-01T00:30:00Z"


def _inputs(policy_version=5):
    return {
        "policy": {
            "uri": "sasanam:policy/governance/v5",
            "digest": "c" * 64,
            "policy_id": "governance",
            "version": policy_version,
        },
        "artifact_digests": {"decision-packet": DECISION},
        "evidence_references": ["sasanam:bundle/abc123"],
    }


def _verification(vid, **kw):
    v = {
        "verifier_id": vid,
        "verdict": "PASSED",
        "verified_levels": ["decision-evidence-complete"],
        "inputs": _inputs(),
        "time_verified": FRESH,
    }
    v.update(kw)
    return v


def _signer_objs(*pairs):
    return [{"verifier_id": vid, "key_id": s.key_id, "sign": s.sign}
            for vid, s in pairs]


def _trust(*signers, **kw):
    vids = kw.pop("vids", ["v1", "v2", "v3"])
    trust = {
        "verifier_registry": {vid: [s.public_key.hex()]
                              for vid, s in zip(vids, signers)},
        "expected_subject_digest": DECISION,
        "required_level": "decision-evidence-complete",
        "max_age_seconds": 3600.0,
        "now": NOW,
        "policy_currency": {"policy_id": "governance", "min_version": 5},
    }
    trust.update(kw)
    return trust


class IssueTests(unittest.TestCase):
    def setUp(self):
        self.s1 = Ed25519Signer(SEED_V1)
        self.s2 = Ed25519Signer(SEED_V2)
        self.s3 = Ed25519Signer(SEED_V3)

    def _issue(self, threshold=2, vids=("v1", "v2")):
        signers = {"v1": self.s1, "v2": self.s2, "v3": self.s3}
        verifs = [_verification(v) for v in vids]
        objs = _signer_objs(*[(v, signers[v]) for v in vids])
        return vt.issue_vsa(DECISION, verifs, objs, threshold)

    def test_round_trip(self):
        packet = self._issue()
        self.assertEqual(packet["type"], "sasanam-threshold-vsa/1")
        self.assertEqual(len(packet["attestations"]), 2)
        self.assertTrue(all(len(a["signature"]) == 128
                            for a in packet["attestations"]))

    def test_decision_dict_input(self):
        from gov import decision_packet as dp
        fake = {"decision": {"value": "allow", "producer": "x",
                             "producer_version": "1"},
                "other": 1}
        digest = dp.packet_digest(fake)
        packet = vt.issue_vsa(
            fake, [_verification("v1")],
            _signer_objs(("v1", self.s1)), 1)
        self.assertEqual(packet["subject"]["decision_digest"], digest)

    def test_disagreement_refuses(self):
        verifs = [_verification("v1"),
                  _verification("v2", verdict="FAILED")]
        objs = _signer_objs(("v1", self.s1), ("v2", self.s2))
        with self.assertRaises(ValueError):
            vt.issue_vsa(DECISION, verifs, objs, 2)

    def test_input_disagreement_refuses(self):
        other_inputs = _inputs()
        other_inputs["artifact_digests"] = {"decision-packet": "d" * 64}
        verifs = [_verification("v1"),
                  _verification("v2", inputs=other_inputs)]
        objs = _signer_objs(("v1", self.s1), ("v2", self.s2))
        with self.assertRaises(ValueError):
            vt.issue_vsa(DECISION, verifs, objs, 2)

    def test_duplicate_verifier_refused_at_issue(self):
        verifs = [_verification("v1"), _verification("v1")]
        objs = _signer_objs(("v1", self.s1), ("v1", self.s1))
        with self.assertRaises(ValueError):
            vt.issue_vsa(DECISION, verifs, objs, 2)

    def test_threshold_bounds(self):
        verifs = [_verification("v1"), _verification("v2")]
        objs = _signer_objs(("v1", self.s1), ("v2", self.s2))
        with self.assertRaises(ValueError):
            vt.issue_vsa(DECISION, verifs, objs, 0)
        with self.assertRaises(ValueError):
            vt.issue_vsa(DECISION, verifs, objs, 3)

    def test_deterministic(self):
        self.assertEqual(
            vt._canonical(self._issue()), vt._canonical(self._issue()))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.s1 = Ed25519Signer(SEED_V1)
        self.s2 = Ed25519Signer(SEED_V2)
        self.s3 = Ed25519Signer(SEED_V3)
        self.evil = Ed25519Signer(SEED_EVIL)

    def _packet(self, threshold=2, vids=("v1", "v2")):
        signers = {"v1": self.s1, "v2": self.s2, "v3": self.s3}
        verifs = [_verification(v) for v in vids]
        objs = _signer_objs(*[(v, signers[v]) for v in vids])
        return vt.issue_vsa(DECISION, verifs, objs, threshold)

    def _trust123(self, **kw):
        return _trust(self.s1, self.s2, self.s3, **kw)

    def test_honest_quorum(self):
        claims = vt.verify_vsa(self._packet(), self._trust123())
        self.assertTrue(claims["ok"] is True)
        self.assertEqual(claims["subject_digest"], DECISION)
        self.assertEqual(claims["verifier_ids"], ["v1", "v2"])
        self.assertEqual(claims["threshold"], 2)
        self.assertNotIn("verdict", claims)  # never an authorization verdict
        self.assertNotIn("PASSED", claims)

    def test_threshold_shape_zero_malformed(self):
        # White-box: the threshold<1 shape branch cannot be reached
        # through issue_vsa (it refuses), so exercise the validator.
        packet = self._packet()
        packet["threshold"] = 0
        with self.assertRaises(vt.VSAThresholdError) as ctx:
            vt._check_packet_shape(packet)
        self.assertEqual(ctx.exception.code, "vsa-packet-malformed")

    def test_error_carries_code(self):
        packet = self._packet()
        packet["attestations"][0]["signature"] = "00" * 64
        with self.assertRaises(vt.VSAThresholdError) as ctx:
            vt.verify_vsa(packet, self._trust123())
        self.assertEqual(ctx.exception.code,
                         "vsa-threshold-signature-invalid")
        self.assertTrue(ctx.exception.detail)

    def test_key_id_binding(self):
        # The attestation key_id must name a pinned key: swapping in the
        # evil key_id (whose signature would verify under the evil key)
        # refuses at the pinning step.
        packet = self._packet()
        evil_sig = self.evil.sign(
            vt.attestation_signing_input(packet,
                                         packet["attestations"][0]))
        packet["attestations"][0]["key_id"] = self.evil.key_id
        packet["attestations"][0]["signature"] = evil_sig.hex()
        with self.assertRaises(vt.VSAThresholdError) as ctx:
            vt.verify_vsa(packet, self._trust123())
        self.assertEqual(ctx.exception.code, "vsa-threshold-signer-unpinned")

    def test_min_threshold_enforced(self):
        packet = self._packet(threshold=2)
        trust = self._trust123(min_threshold=3)
        with self.assertRaises(vt.VSAThresholdError) as ctx:
            vt.verify_vsa(packet, trust)
        self.assertEqual(ctx.exception.code, "vsa-threshold-below-quorum")

    def test_missing_policy_currency_is_caller_error(self):
        # Fail-closed: the consumer must name its currency floor
        # explicitly. There is no silent accept of stale policy.
        packet = self._packet()
        trust = self._trust123()
        del trust["policy_currency"]
        with self.assertRaises(ValueError):
            vt.verify_vsa(packet, trust)

    def test_future_time_verified_refuses(self):
        # time_verified is part of the signed descriptor, so the future
        # time must be set at issuance, not tampered after.
        signers = {"v1": self.s1, "v2": self.s2}
        verifs = [_verification("v1", time_verified="2027-01-01T02:00:00Z"),
                  _verification("v2", time_verified="2027-01-01T02:00:00Z")]
        objs = _signer_objs(("v1", self.s1), ("v2", self.s2))
        packet = vt.issue_vsa(DECISION, verifs, objs, 2)
        with self.assertRaises(vt.VSAThresholdError) as ctx:
            vt.verify_vsa(packet, self._trust123())
        self.assertEqual(ctx.exception.code, "vsa-packet-window-invalid")

    def test_trust_caller_errors(self):
        packet = self._packet()
        with self.assertRaises(ValueError):
            vt.verify_vsa(packet, "not-a-dict")
        bad = self._trust123()
        del bad["verifier_registry"]
        with self.assertRaises(ValueError):
            vt.verify_vsa(packet, bad)

    def test_malformed_inputs(self):
        for bad_packet in (None, [], {"type": "sasanam-threshold-vsa/1"}):
            with self.assertRaises(vt.VSAThresholdError) as ctx:
                vt.verify_vsa(bad_packet, self._trust123())
            self.assertEqual(ctx.exception.code, "vsa-packet-malformed")


if __name__ == "__main__":
    unittest.main()
