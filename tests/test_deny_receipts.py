"""Unit tests for gov/deny_receipts.py (wave-230 lane A).

Pin tests assert the refusal-code strings and receipt field shape
against known literals (independent source of truth: the refusal
vocabulary), not by recomputing the module's own logic.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import deny_receipts as dr  # noqa: E402
from gov import alg_registry as ar  # noqa: E402


def _d(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _decision(**over):
    d = {
        "verdict": "deny",
        "rule_path": "policy/default/deny-write",
        "token_digest": _d("tok"),
        "policy_bundle_digest": _d("bundle"),
        "intent_digest": _d("intent"),
        "jurisdiction_profile": "default",
    }
    d.update(over)
    return d


def _signer(alg=ar.ED25519_RFC8032, key_id="unit-receipt-key"):
    reg = ar.default_registry()
    secret, pub = reg.keygen(alg)
    return dr.Signer(alg=alg, secret=secret, key_id=key_id), pub


class ShapeTest(unittest.TestCase):
    def test_receipt_has_exact_fields(self):
        signer, _pub = _signer()
        rec = dr.emit(_decision(), signer=signer)
        self.assertEqual(
            set(rec),
            {"v", "kind", "verdict", "class", "rule_path",
             "token_digest", "policy_bundle_digest", "intent_digest",
             "jurisdiction_profile", "alg", "key_id",
             "non_repudiation", "signature"})
        self.assertEqual(rec["v"], 1)
        self.assertEqual(rec["kind"], "deny-receipt")

    def test_permit_class_ok_deny_class_violation(self):
        signer, _pub = _signer()
        permit = dr.emit(_decision(verdict="permit"), signer=signer)
        self.assertEqual(permit["verdict"], "PERMIT")
        self.assertEqual(permit["class"], "ok")
        deny = dr.emit(_decision(verdict="deny"), signer=signer)
        self.assertEqual(deny["verdict"], "DENY")
        self.assertEqual(deny["class"], "violation")

    def test_mac_tier_honestly_non_repudiation_false(self):
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        rec = dr.emit(_decision(), signer=signer)
        self.assertFalse(rec["non_repudiation"])
        ed, _pub2 = _signer()
        rec2 = dr.emit(_decision(), signer=ed)
        self.assertTrue(rec2["non_repudiation"])


class RefusalCodeTest(unittest.TestCase):
    def test_missing_field_refuses_taxonomy_receipt_missing(self):
        signer, _pub = _signer()
        d = _decision()
        del d["intent_digest"]
        with self.assertRaises(dr.DenyReceiptMissing) as ctx:
            dr.emit(d, signer=signer)
        self.assertEqual(ctx.exception.code, "taxonomy-receipt-missing")

    def test_raw_pii_refuses_hashes_only(self):
        signer, _pub = _signer()
        d = _decision(token_digest="alice@example.com")
        with self.assertRaises(dr.DenyReceiptMissing) as ctx:
            dr.emit(d, signer=signer)
        self.assertEqual(ctx.exception.code, "taxonomy-receipt-missing")

    def test_unavailable_as_permit_refused(self):
        signer, _pub = _signer()
        with self.assertRaises(dr.DenyReceiptUnavailableAsPermit) as ctx:
            dr.emit(_decision(verdict="permit", outage=True), signer=signer)
        self.assertEqual(ctx.exception.code,
                         "deny-receipt-unavailable-as-permit")

    def test_outage_receipt_class_unavailable(self):
        signer, pub = _signer()
        rec = dr.emit(_decision(outage=True), signer=signer)
        out = dr.verify(rec, key=pub)
        self.assertEqual(out["class"], "unavailable")

    def test_tamper_refuses_signature_invalid(self):
        signer, pub = _signer()
        rec = dr.emit(_decision(), signer=signer)
        rec["rule_path"] = "policy/tampered/allow"
        with self.assertRaises(dr.DenyReceiptInvalid) as ctx:
            dr.verify(rec, key=pub)
        self.assertEqual(ctx.exception.code,
                         "deny-receipt-signature-invalid")

    def test_malformed_receipt_refused(self):
        _signer_pub = _signer()[1]
        with self.assertRaises(dr.DenyReceiptMalformed) as ctx:
            dr.verify({"kind": "deny-receipt"}, key=_signer_pub)
        self.assertEqual(ctx.exception.code, "deny-receipt-malformed")

    def test_receipt_not_authority(self):
        signer, _pub = _signer()
        rec = dr.emit(_decision(), signer=signer)
        with self.assertRaises(dr.DenyReceiptNotAuthority) as ctx:
            dr.receipt_as_authority(rec)
        self.assertEqual(ctx.exception.code,
                         "deny-receipt-not-authorization")

    def test_unknown_fields_rejected(self):
        signer, pub = _signer()
        rec = dr.emit(_decision(), signer=signer)
        rec["extra"] = "smuggled"
        with self.assertRaises(dr.DenyReceiptMalformed):
            dr.verify(rec, key=pub)


class EvidenceTest(unittest.TestCase):
    def test_evidence_digest_stable_and_tamper_evident(self):
        signer, _pub = _signer()
        rec = dr.emit(_decision(), signer=signer)
        ev = dr.receipt_evidence(rec)
        self.assertEqual(ev["kind"], "deny-receipt-evidence")
        self.assertEqual(ev["digest"], dr.receipt_evidence(rec)["digest"])
        bad = dict(ev)
        bad["verdict"] = "PERMIT"
        self.assertNotEqual(dr.evidence_digest(bad),
                            dr.evidence_digest(ev))


class EnvelopeTest(unittest.TestCase):
    # Wave-232 lane C: opt-in DSSE envelope on denial receipts.
    def test_envelope_opt_in_round_trip(self):
        signer, pub = _signer(alg=ar.HMAC_SHA256_MAC)
        r = dr.emit(_decision(), signer=signer,
                    envelope=dr.DENY_RECEIPT_ENVELOPE_TYPE)
        self.assertEqual(r["envelope"]["payloadType"],
                         dr.DENY_RECEIPT_ENVELOPE_TYPE)
        # Wave-246 lane 5 (CWE-347): pin expect_alg to the HMAC tier — the signer is a legitimate shared secret, not a public key.
        out = dr.verify(r, key=signer.secret,
                                     expect_alg=ar.HMAC_SHA256_MAC)
        self.assertTrue(out["ok"])

    def test_envelope_absent_by_default(self):
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        r = dr.emit(_decision(), signer=signer)
        self.assertNotIn("envelope", r)

    def test_generic_envelope_type_refused_at_build(self):
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        with self.assertRaises(dr.DenyReceiptMalformed) as ctx:
            dr.emit(_decision(), signer=signer, envelope="application/json")
        self.assertIn("dsse-payload-type-refused", str(ctx.exception))

    def test_vendored_but_wrong_envelope_type_refused_at_build(self):
        # verify() binds the expected type, so minting under any other
        # type would produce a permanently-unverifiable receipt.
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        with self.assertRaises(dr.DenyReceiptMalformed) as ctx:
            dr.emit(_decision(), signer=signer,
                    envelope="application/vnd.sasanam.other+json")
        self.assertIn("dsse-payload-type-refused", str(ctx.exception))

    def test_envelope_transplant_refused(self):
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        r1 = dr.emit(_decision(), signer=signer,
                     envelope=dr.DENY_RECEIPT_ENVELOPE_TYPE)
        r2 = dr.emit(_decision(rule_path="policy/other/deny"),
                     signer=signer,
                     envelope=dr.DENY_RECEIPT_ENVELOPE_TYPE)
        r2x = dict(r2)
        r2x["envelope"] = r1["envelope"]
        with self.assertRaises(dr.DenyReceiptInvalid) as ctx:
            # Wave-246 lane 5 (CWE-347): pin expect_alg to the HMAC tier — the signer is a legitimate shared secret, not a public key.
            dr.verify(r2x, key=signer.secret,
                                         expect_alg=ar.HMAC_SHA256_MAC)
        self.assertIn("dsse-signature-invalid", str(ctx.exception))

    def test_envelope_forgery_refused(self):
        import copy
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        r = dr.emit(_decision(), signer=signer,
                    envelope=dr.DENY_RECEIPT_ENVELOPE_TYPE)
        bad = copy.deepcopy(r)
        bad["envelope"]["signatures"][0]["sig"] = "00" * 64
        with self.assertRaises(dr.DenyReceiptInvalid) as ctx:
            # Wave-246 lane 5 (CWE-347): pin expect_alg to the HMAC tier — the signer is a legitimate shared secret, not a public key.
            dr.verify(bad, key=signer.secret,
                                         expect_alg=ar.HMAC_SHA256_MAC)
        self.assertIn("dsse-signature-invalid", str(ctx.exception))

    def test_envelope_wrong_expected_type_refused(self):
        # Wave-233: a receipt envelope re-typed under the decision-packet
        # payloadType is a cross-module transplant, so verify() now names
        # it dsse-envelope-transplant (the wave-232 pin
        # dsse-payload-type-refused is obsolete: that code still exists
        # for the legacy expect_payload_type path, but the receipt
        # verifier binds the expected module domain).
        import copy
        signer, _pub = _signer(alg=ar.HMAC_SHA256_MAC)
        r = dr.emit(_decision(), signer=signer,
                    envelope=dr.DENY_RECEIPT_ENVELOPE_TYPE)
        bad = copy.deepcopy(r)
        bad["envelope"]["payloadType"] = \
            "application/vnd.sasanam.decision-packet+json"
        with self.assertRaises(dr.DenyReceiptInvalid) as ctx:
            # Wave-246 lane 5 (CWE-347): pin expect_alg to the HMAC tier — the signer is a legitimate shared secret, not a public key.
            dr.verify(bad, key=signer.secret,
                                         expect_alg=ar.HMAC_SHA256_MAC)
        self.assertIn("dsse-envelope-transplant", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
