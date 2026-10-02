"""Unit tests for gov/runtime_posture.py (wave-288 lane 8).

EAT JSON-profile (RFC 9711) runtime posture attestation records:
nonce floor, submod anti-substitution, endorsement slots, operator
signatures, anchoring, and the trust-vector appraisal seam.
"""

import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519 as _ed25519
from gov import runtime_posture as rp


def _endorsements():
    slot = {"log_id": "log-1", "log_index": 0,
            "expected_digest": "01" * 32, "source_id": "auditor"}
    return {c: dict(slot) for c in ("software_id", "config_digest",
                                    "submods")}


def _issue(seed=None, nonce=None, submods=None, endorsements=None,
           keyid="op-1", software_id="sasanam-agent/1.0",
           config_digest=None, tsa_token=None, producer_id="operator"):
    seed = seed if seed is not None else secrets.token_bytes(32)
    submods = submods if submods is not None else {
        "sandbox": {"digest": "ab" * 32},
        "toolpolicy": {"digest": "cd" * 32},
    }
    endorsements = (endorsements if endorsements is not None
                    else _endorsements())
    return rp.issue_posture(
        operator_seed=seed, operator_keyid=keyid,
        eat_nonce=nonce if nonce is not None else secrets.token_bytes(8),
        submods=submods, software_id=software_id,
        config_digest=config_digest or "aa" * 32,
        endorsements=endorsements, tsa_token=tsa_token,
        producer_id=producer_id), seed


class IssueTest(unittest.TestCase):

    def test_round_trip(self):
        rec, seed = _issue()
        pub = _ed25519.publickey(seed).hex()
        payload = rp.verify_posture(
            rec, pub,
            expected_nonce=bytes.fromhex(rec["payload"]["eat_nonce"]))
        self.assertEqual(payload["software_id"], "sasanam-agent/1.0")
        self.assertIn("sandbox", payload["submods"])

    def test_nonce_floor_enforced(self):
        for bad in (b"", b"\x00" * 7, b"\x01" * 4):
            with self.assertRaises(rp.PostureError) as cm:
                _issue(nonce=bad)
            self.assertEqual(cm.exception.code, "posture-nonce-invalid")

    def test_eight_bytes_accepted(self):
        rec, _ = _issue(nonce=b"\xde\xad\xbe\xef" * 2)
        self.assertEqual(len(rec["payload"]["eat_nonce"]), 16)

    def test_missing_endorsement_slot_refused(self):
        ends = _endorsements()
        del ends["submods"]
        with self.assertRaises(rp.PostureError) as cm:
            _issue(endorsements=ends)
        self.assertEqual(cm.exception.code, "posture-endorsement-missing")

    def test_self_sourced_endorsement_refused(self):
        ends = _endorsements()
        ends["software_id"]["source_id"] = "operator"
        with self.assertRaises(rp.PostureError) as cm:
            _issue(endorsements=ends, producer_id="operator")
        self.assertEqual(cm.exception.code,
                         "posture-endorsement-not-independent")

    def test_bad_submod_digest_refused(self):
        with self.assertRaises(rp.PostureError) as cm:
            _issue(submods={"sandbox": {"digest": "not-hex"}})
        self.assertEqual(cm.exception.code, "posture-submod-invalid")

    def test_empty_submods_refused(self):
        with self.assertRaises(rp.PostureError) as cm:
            _issue(submods={})
        self.assertEqual(cm.exception.code, "posture-submod-invalid")

    def test_seed_must_be_32_bytes(self):
        with self.assertRaises(rp.PostureError) as cm:
            _issue(seed=b"short")
        self.assertEqual(cm.exception.code, "posture-invalid-shape")


class VerifyTest(unittest.TestCase):

    def test_tampered_payload_refused(self):
        rec, seed = _issue()
        pub = _ed25519.publickey(seed).hex()
        evil = json.loads(json.dumps(rec))
        evil["payload"]["config_digest"] = "ff" * 32
        with self.assertRaises(rp.PostureError) as cm:
            rp.verify_posture(evil, pub)
        self.assertEqual(cm.exception.code, "posture-signature-invalid")

    def test_verify_return_is_exact_bool_contract(self):
        # ed25519.verify returns True/False; module checks `is not True`.
        rec, seed = _issue()
        pub = _ed25519.publickey(seed).hex()
        payload = rp.verify_posture(rec, pub)
        self.assertIsInstance(payload, dict)

    def test_wrong_operator_key_refused(self):
        rec, _ = _issue()
        other = _ed25519.publickey(secrets.token_bytes(32)).hex()
        with self.assertRaises(rp.PostureError) as cm:
            rp.verify_posture(rec, other)
        self.assertEqual(cm.exception.code, "posture-signature-invalid")

    def test_nonce_mismatch_refused(self):
        rec, seed = _issue()
        pub = _ed25519.publickey(seed).hex()
        with self.assertRaises(rp.PostureError) as cm:
            rp.verify_posture(rec, pub,
                              expected_nonce=secrets.token_bytes(8))
        self.assertEqual(cm.exception.code, "posture-nonce-invalid")

    def test_unsigned_record_refused(self):
        with self.assertRaises(rp.PostureError) as cm:
            rp.verify_posture({"posture_format": "x"}, "00" * 64)
        self.assertIn(cm.exception.code,
                      ("posture-invalid-shape", "posture-signature-invalid"))

    def test_malformed_shape_refused(self):
        with self.assertRaises(rp.PostureError) as cm:
            rp.verify_posture("not-a-dict", "00" * 64)
        self.assertEqual(cm.exception.code, "posture-invalid-shape")


class AnchorTest(unittest.TestCase):

    def test_anchor_round_trip(self):
        from gov import evidence_anchor as ea
        rec, _ = _issue()
        d = tempfile.mkdtemp(prefix="w288-eat-anchor-")
        log = ea.TransparencyLog(d, origin="test",
                                 signer_keyid="op",
                                 signer_seed=secrets.token_bytes(32))
        receipt = rp.anchor_posture(log, rec)
        self.assertEqual(receipt["bundle_digest"], rp.posture_digest(rec))
        self.assertIn("inclusion_proof", receipt)

    def test_digest_stable(self):
        rec, _ = _issue()
        self.assertEqual(rp.posture_digest(rec), rp.posture_digest(rec))
        self.assertEqual(len(rp.posture_digest(rec)), 64)


class SeamTest(unittest.TestCase):

    def test_scheme_registered_once(self):
        from gov import trust_vector as tv
        self.assertIn(rp.SCHEME_ID, tv.registered_schemes())
        # Re-import must not raise duplicate-scheme.
        import importlib
        importlib.reload(rp)
        self.assertIn(rp.SCHEME_ID, tv.registered_schemes())

    def test_seam_shape(self):
        from gov import trust_vector as tv
        rec, _ = _issue()
        claim_digest, scheme_id, endorsements = rp.as_appraisal_evidence(
            rec, producer_id="operator")
        self.assertEqual(scheme_id, rp.SCHEME_ID)
        self.assertEqual(len(claim_digest), 64)
        names = {e["claim_name"] for e in endorsements}
        self.assertEqual(names, {"software_id", "config_digest",
                                 "submods_digest"})
        for e in endorsements:
            self.assertIn("expected_value", e)
            self.assertIn("source_id", e)

    def test_end_to_end_appraisal(self):
        from gov import trust_vector as tv
        rec, _ = _issue()
        claim_digest, scheme_id, endorsements = rp.as_appraisal_evidence(
            rec, producer_id="operator")
        ev = tv.submit_evidence(
            scheme_id,
            {"posture_digest": claim_digest,
             "software_id": rec["payload"]["software_id"],
             "config_digest": rec["payload"]["config_digest"],
             "submods_digest": hashlib.sha256(
                 json.dumps(rec["payload"]["submods"],
                            sort_keys=True).encode()).hexdigest()},
            producer_id="operator")
        ends = []
        for e in endorsements:
            ends.append(tv.endorse(ev, e["claim_name"], e["expected_value"],
                                   e["source_id"]))
        self.assertEqual(len(ends), 3)


class TaxonomyTest(unittest.TestCase):

    def test_new_codes_present(self):
        from gov import decision_codes as dc
        for code in ("posture-invalid-shape", "posture-signature-invalid",
                     "posture-nonce-invalid", "posture-submod-invalid",
                     "posture-endorsement-missing",
                     "posture-endorsement-not-independent"):
            self.assertIn(code, dc.TAXONOMY)
            self.assertEqual(dc.TAXONOMY[code]["domain"], "posture")


if __name__ == "__main__":
    unittest.main()
