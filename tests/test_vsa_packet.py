"""Unit tests for gov/vsa_packet.py — SLSA v1.2 decision VSAs.

TDD red: this file is written BEFORE the module exists. Every test must
FAIL (ImportError) until gov/vsa_packet.py lands, then go green one by one.
"""

import base64
import hashlib
import json
import unittest

SEED_A = "aa" * 32  # verifier A's packet-signing seed (test-local, not a secret)
SEED_B = "bb" * 32  # verifier B's seed

DECISION_DIGEST = hashlib.sha256(b"decision-packet-fixture").hexdigest()
POLICY_DIGEST = hashlib.sha256(b"policy-fixture").hexdigest()
REPORT_DIGEST_SEED = hashlib.sha256(b"report-fixture").hexdigest()

VERIFIER_A = "test-verifier-a"
VERIFIER_B = "test-verifier-b"

NOW = 1790000000  # fixed consumer "now" (2026-09-…); timeVerified < NOW


def _valid_report(**over):
    rep = {
        "status": "VALID",
        "verificationResult": "PASSED",
        "verifier": {"id": "sasanam-offline-verifier", "version": "1.0.0"},
        "timeVerified": "2026-09-20T12:00:00Z",
        "timeSource": {"name": "test-clock"},
        "resourceUri": "sha256:" + DECISION_DIGEST,
        "policy": {
            "uri": "sasanam:policy/unit-test",
            "digest": {"sha256": POLICY_DIGEST},
            "expires": "2027-09-20T12:00:00Z",
        },
        "inputAttestations": [
            {"uri": "dsse-envelope", "digest": {"sha256": REPORT_DIGEST_SEED}},
        ],
        "witness": None,
        "checks": [{"step": "x", "result": "pass", "detail": "y"}],
    }
    rep.update(over)
    return rep


def _pubkey_hex(seed_hex):
    from gov import ed25519 as _ed
    return _ed.publickey(bytes.fromhex(seed_hex)).hex()


class TestIssue(unittest.TestCase):
    def test_issue_happy_path(self):
        import gov.vsa_packet as vp
        signer = vp.packet_key_signer(SEED_A)
        env = vp.issue_decision_vsa(
            decision_digest=DECISION_DIGEST,
            report=_valid_report(),
            verified_levels=["SLSA_BUILD_LEVEL_1"],
            signer=signer)
        self.assertEqual(env["payloadType"], vp.VSA_PAYLOAD_TYPE)
        self.assertEqual(len(env["signatures"]), 1)
        stmt = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["predicateType"], vp.SLSA_VSA_PREDICATE)
        pred = stmt["predicate"]
        self.assertEqual(pred["verificationResult"], "PASSED")
        self.assertEqual(pred["resourceUri"],
                         "sasanam:decision-packet/" + DECISION_DIGEST)
        self.assertEqual(pred["verifier"]["id"], "sasanam-offline-verifier")
        self.assertEqual(pred["policy"]["digest"]["sha256"], POLICY_DIGEST)
        # the decision digest is pinned in subject AND input attestations
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"],
                         DECISION_DIGEST)
        uris = [a["uri"] for a in pred["inputAttestations"]]
        self.assertIn("sasanam:decision-packet/" + DECISION_DIGEST, uris)

    def test_issue_deterministic(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        kw = dict(decision_digest=DECISION_DIGEST, report=_valid_report(),
                  verified_levels=["SLSA_BUILD_LEVEL_1"], signer=s)
        self.assertEqual(vp.issue_decision_vsa(**kw),
                         vp.issue_decision_vsa(**kw))

    def test_issue_refuses_non_valid_report(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        bad = _valid_report(status="INVALID", verificationResult="FAILED")
        with self.assertRaises(ValueError):
            vp.issue_decision_vsa(decision_digest=DECISION_DIGEST,
                                  report=bad,
                                  verified_levels=["SLSA_BUILD_LEVEL_1"],
                                  signer=s)

    def test_issue_refuses_bad_digest(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        with self.assertRaises(ValueError):
            vp.issue_decision_vsa(decision_digest="not-hex",
                                  report=_valid_report(),
                                  verified_levels=["SLSA_BUILD_LEVEL_1"],
                                  signer=s)

    def test_issue_refuses_unknown_level(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        with self.assertRaises(ValueError):
            vp.issue_decision_vsa(decision_digest=DECISION_DIGEST,
                                  report=_valid_report(),
                                  verified_levels=["BOGUS_LEVEL"],
                                  signer=s)

    def test_issue_refuses_hostile_non_dict_shapes(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        kw = dict(decision_digest=DECISION_DIGEST,
                  verified_levels=["SLSA_BUILD_LEVEL_1"], signer=s)
        for mutate in (
                lambda r: r.update(timeSource="not-a-dict"),
                lambda r: r["policy"].update(digest="not-a-dict"),
                lambda r: r["inputAttestations"][0].update(
                    digest="not-a-dict")):
            rep = _valid_report()
            mutate(rep)
            with self.assertRaises(ValueError):
                vp.issue_decision_vsa(report=rep, **kw)

    def test_packet_key_signer_rejects_non_str_seed(self):
        import gov.vsa_packet as vp
        with self.assertRaises(ValueError):
            vp.packet_key_signer(12345)

    def test_parse_rfc3339_rejects_impossible_dates(self):
        import gov.vsa_packet as vp
        self.assertIsNone(vp._parse_rfc3339("2026-02-31T00:00:00Z"))
        self.assertIsNone(vp._parse_rfc3339("2026-10-03T25:00:00Z"))
        self.assertIsNotNone(vp._parse_rfc3339("2026-10-03T12:00:00Z"))

    def test_packet_key_signer_convention(self):
        import gov.vsa_packet as vp
        s = vp.packet_key_signer(SEED_A)
        pub = bytes.fromhex(_pubkey_hex(SEED_A))
        self.assertEqual(s.key_id, hashlib.sha256(pub).digest()[:16].hex())

    def test_levels_for_report(self):
        import gov.vsa_packet as vp
        self.assertEqual(vp.levels_for_report(_valid_report()),
                         ["SLSA_BUILD_LEVEL_1"])
        wit = _valid_report(witness={"log_index": 3})
        self.assertIn("sasanam/evidence-chain/witnessed",
                      vp.levels_for_report(wit))


class TestConsume(unittest.TestCase):
    def _issued(self, seed=SEED_A, **over):
        import gov.vsa_packet as vp
        signer = vp.packet_key_signer(seed)
        return vp.issue_decision_vsa(
            decision_digest=DECISION_DIGEST, report=_valid_report(),
            verified_levels=["SLSA_BUILD_LEVEL_1"], signer=signer, **over)

    def _expected(self, **over):
        exp = {
            "subject_digest": DECISION_DIGEST,
            "resource_uri": "sasanam:decision-packet/" + DECISION_DIGEST,
            "verifier_id": "sasanam-offline-verifier",
            "required_level": "SLSA_BUILD_LEVEL_1",
            "signer_registry": {"sasanam-offline-verifier":
                                [_pubkey_hex(SEED_A)]},
            "now": NOW,
            "max_age_seconds": 86400 * 30,
        }
        exp.update(over)
        return exp

    def test_consume_happy_path(self):
        import gov.vsa_packet as vp
        out = vp.consume_vsa(self._issued(), expected=self._expected())
        self.assertTrue(out["ok"])
        self.assertEqual(out["subject_digest"], DECISION_DIGEST)
        # PASSED != ALLOW: the consumer returns verified claims, never a verdict
        self.assertNotIn("verdict", out)
        self.assertNotIn("allow", out)
        self.assertNotIn("decision", out)

    def test_consume_subject_mismatch(self):
        import gov.vsa_packet as vp
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(),
                           expected=self._expected(
                               subject_digest="cc" * 32))
        self.assertEqual(cm.exception.code, "vsa-packet-subject-mismatch")

    def test_consume_signer_unpinned(self):
        import gov.vsa_packet as vp
        # signed by B's key; registry pins only A
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(seed=SEED_B),
                           expected=self._expected())
        self.assertEqual(cm.exception.code, "vsa-packet-signer-unpinned")

    def test_consume_verifier_mismatch(self):
        import gov.vsa_packet as vp
        # key IS pinned, but for a different verifier id than the statement's
        exp = self._expected(signer_registry={VERIFIER_A: [_pubkey_hex(SEED_A)],
                                              VERIFIER_B: [_pubkey_hex(SEED_B)]},
                            verifier_id=VERIFIER_A)
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(), expected=exp)
        self.assertEqual(cm.exception.code, "vsa-packet-verifier-mismatch")

    def test_consume_resource_mismatch(self):
        import gov.vsa_packet as vp
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(),
                           expected=self._expected(
                               resource_uri="sasanam:decision-packet/" + "dd" * 32))
        self.assertEqual(cm.exception.code, "vsa-packet-resource-mismatch")

    def test_consume_levels_missing(self):
        import gov.vsa_packet as vp
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(),
                           expected=self._expected(
                               required_level="SLSA_BUILD_LEVEL_3"))
        self.assertEqual(cm.exception.code, "vsa-packet-levels-missing")

    def test_consume_window_invalid(self):
        import gov.vsa_packet as vp
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(self._issued(),
                           expected=self._expected(now=NOW + 86400 * 365))
        self.assertEqual(cm.exception.code, "vsa-packet-window-invalid")

    def test_consume_malformed_envelope(self):
        import gov.vsa_packet as vp
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa({"not": "an envelope"},
                           expected=self._expected())
        self.assertEqual(cm.exception.code, "vsa-packet-malformed")

    def test_consume_hostile_subject_digest_shape(self):
        import base64
        import json
        import gov.vsa_packet as vp
        env = self._issued()
        stmt = json.loads(base64.b64decode(env["payload"]))
        stmt["subject"][0]["digest"] = "not-a-dict"  # hostile shape
        resealed = vp._dsse().seal(
            vp._canonical(stmt), vp.VSA_PAYLOAD_TYPE,
            [vp.packet_key_signer(SEED_A)])
        with self.assertRaises(vp.VSAPacketError) as cm:
            vp.consume_vsa(resealed, expected=self._expected())
        self.assertEqual(cm.exception.code, "vsa-packet-malformed")

    def test_consume_rejects_infinite_window(self):
        import gov.vsa_packet as vp
        with self.assertRaises(ValueError):
            vp.consume_vsa(self._issued(),
                           expected=self._expected(
                               max_age_seconds=float("inf")))

    def test_error_code_closed_vocabulary(self):
        import gov.vsa_packet as vp
        with self.assertRaises(ValueError):
            vp.VSAPacketError("no-such-code", "x")


if __name__ == "__main__":
    unittest.main()
