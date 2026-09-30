"""Unit tests for gov/admission.py and gov/bundle_inspection.py.

Wave-221 lane C: artifact-admission gate (Harbor pull-time
content-trust pattern) + bundle inspection discipline (in-toto
inspection pattern, prose re-derived). Tests at the public seams;
expected values are independent literals, never recomputed the way
the code does.
"""

import hashlib
import unittest

from gov import admission as adm
from gov import bundle_inspection as bi
from gov import ed25519 as _ed


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _keypair(tag):
    seed = hashlib.sha256(b"w221-unit-%s" % tag.encode()).digest()
    return seed, _ed.publickey(seed)


def _sign(seed, digest):
    return _ed.sign(seed, adm.SIGN_DOMAIN + digest.encode("ascii"))


class PolicyAuthoringTests(unittest.TestCase):
    def test_bad_digest_pin(self):
        _, pub = _keypair("a")
        with self.assertRaises(adm.AdmissionPolicyAuthoringError):
            adm.AdmissionPolicy(digest_pin="not-hex", issuer_pin=pub,
                                bundle_format="f")
        with self.assertRaises(adm.AdmissionPolicyAuthoringError):
            adm.AdmissionPolicy(digest_pin="ab" * 10, issuer_pin=pub,
                                bundle_format="f")

    def test_bad_issuer_pin(self):
        with self.assertRaises(adm.AdmissionPolicyAuthoringError):
            adm.AdmissionPolicy(digest_pin=_sha(b"x"),
                                issuer_pin=b"short",
                                bundle_format="f")

    def test_bad_format(self):
        _, pub = _keypair("a")
        with self.assertRaises(adm.AdmissionPolicyAuthoringError):
            adm.AdmissionPolicy(digest_pin=_sha(b"x"), issuer_pin=pub,
                                bundle_format="")

    def test_bad_require_inspection(self):
        _, pub = _keypair("a")
        with self.assertRaises(adm.AdmissionPolicyAuthoringError):
            adm.AdmissionPolicy(digest_pin=_sha(b"x"), issuer_pin=pub,
                                bundle_format="f", require_inspection="yes")


class AdmitTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.pub = _keypair("a")
        self.payload = b"unit bundle payload"
        self.digest = _sha(self.payload)
        self.policy = adm.AdmissionPolicy(
            digest_pin=self.digest, issuer_pin=self.pub,
            bundle_format="evidence-bundle/1")

    def _artifact(self, **kw):
        base = {"format": "evidence-bundle/1",
                "payload_digest": self.digest,
                "signature": _sign(self.seed, self.digest),
                "payload": self.payload}
        base.update(kw)
        return base

    def test_honest_admits(self):
        rec = self.policy.admit(self._artifact())
        self.assertTrue(rec["admissible"])
        self.assertEqual(rec["payload_digest"], self.digest)
        self.assertEqual(rec["format"], "evidence-bundle/1")
        self.assertEqual(rec["issuer_fingerprint"], _sha(self.pub))
        self.assertFalse(rec["inspection_verified"])

    def test_tampered_payload_refused(self):
        art = self._artifact(payload=b"unit bundle payload EVIL")
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(art)
        self.assertEqual(ctx.exception.code, "admission-digest-mismatch")

    def test_swapped_digest_refused(self):
        art = self._artifact(payload_digest=_sha(b"other"))
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(art)
        self.assertEqual(ctx.exception.code, "admission-digest-mismatch")

    def test_foreign_signature_refused(self):
        evil_seed, _ = _keypair("evil")
        art = self._artifact(signature=_sign(evil_seed, self.digest))
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(art)
        self.assertEqual(ctx.exception.code, "admission-issuer-untrusted")

    def test_unsigned_is_unverifiable(self):
        art = self._artifact(signature=None)
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(art)
        self.assertEqual(ctx.exception.code, "admission-unverifiable")

    def test_unknown_format_refused(self):
        art = self._artifact(format="something-else/9")
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(art)
        self.assertEqual(ctx.exception.code, "admission-format-unknown")

    def test_malformed_artifact(self):
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit({"format": "evidence-bundle/1"})
        self.assertEqual(ctx.exception.code, "admission-malformed")
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(dict(self._artifact(), extra="field"))
        self.assertEqual(ctx.exception.code, "admission-malformed")

    def test_admission_error_carries_code_and_detail(self):
        err = adm.AdmissionError("admission-digest-mismatch", "d")
        self.assertEqual(err.code, "admission-digest-mismatch")
        self.assertIn("admission-digest-mismatch", str(err))


class InspectionWiringTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.pub = _keypair("a")
        self.payload = b"inspected bundle"
        self.digest = _sha(self.payload)
        self.policy = adm.AdmissionPolicy(
            digest_pin=self.digest, issuer_pin=self.pub,
            bundle_format="evidence-bundle/1", require_inspection=True)
        self.script = b"#!/bin/sh\necho ok\n"

    def _artifact(self):
        return {"format": "evidence-bundle/1",
                "payload_digest": self.digest,
                "signature": _sign(self.seed, self.digest),
                "payload": self.payload}

    def test_missing_inspection_refused(self):
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(self._artifact())
        self.assertEqual(ctx.exception.code, "admission-inspection-missing")

    def test_foreign_bundle_link_refused(self):
        other = bi.BundleInspectionLog("v1", _sha(b"other"))
        link = other.admit("scan", self.script, _sha(self.script), 0, b"ok")
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(self._artifact(), inspection=(other, link))
        self.assertEqual(ctx.exception.code,
                         "admission-inspection-bundle-mismatch")

    def test_honest_inspected_admits(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        link = log.admit("scan", self.script, _sha(self.script), 0, b"ok")
        rec = self.policy.admit(self._artifact(), inspection=(log, link))
        self.assertTrue(rec["admissible"])
        self.assertTrue(rec["inspection_verified"])

    def test_tampered_link_surfaces_link_code(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        link = log.admit("scan", self.script, _sha(self.script), 0, b"ok")
        forged = dict(link)
        forged["outputs_digest"] = _sha(b"forged")
        with self.assertRaises(adm.AdmissionError) as ctx:
            self.policy.admit(self._artifact(), inspection=(log, forged))
        self.assertEqual(ctx.exception.code, "bundle-link-unverifiable")


class BundleInspectionTests(unittest.TestCase):
    def setUp(self):
        self.digest = _sha(b"the bundle")
        self.script = b"#!/bin/sh\necho ok\n"

    def test_bad_constructor(self):
        with self.assertRaises(bi.BundleInspectionError):
            bi.BundleInspectionLog("", self.digest)
        with self.assertRaises(bi.BundleInspectionError):
            bi.BundleInspectionLog("v1", "not-hex")

    def test_attributed_link_binds_bundle(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        link = log.admit("scan", self.script, _sha(self.script), 0, b"ok")
        self.assertTrue(link["verifier_attributed"])
        self.assertEqual(link["verifier_id"], "v1")
        self.assertEqual(link["bundle_digest"], self.digest)
        self.assertTrue(log.verify_link(link))
        self.assertTrue(log.verify())

    def test_unattributed_link_refused(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        link = log.admit("scan", self.script, _sha(self.script), 0, b"ok")
        stripped = dict(link)
        stripped["verifier_attributed"] = False
        with self.assertRaises(bi.BundleInspectionError) as ctx:
            log.verify_link(stripped)
        self.assertEqual(ctx.exception.code, "bundle-link-unverifiable")

    def test_wrong_bundle_link_refused(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        link = log.admit("scan", self.script, _sha(self.script), 0, b"ok")
        wrong = dict(link)
        wrong["bundle_digest"] = _sha(b"another bundle")
        with self.assertRaises(bi.BundleInspectionError) as ctx:
            log.verify_link(wrong)
        self.assertEqual(ctx.exception.code, "bundle-link-unverifiable")

    def test_nonzero_exit_halts_with_named_code(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        with self.assertRaises(bi.BundleInspectionError) as ctx:
            log.admit("scan", self.script, _sha(self.script), 3, b"partial")
        self.assertEqual(ctx.exception.code, "inspection-failed")

    def test_records_emitted_in_order(self):
        log = bi.BundleInspectionLog("v1", self.digest)
        log.admit("scan1", self.script, _sha(self.script), 0, b"one")
        log.admit("scan2", self.script, _sha(self.script), 0, b"two")
        recs = log.records()
        self.assertEqual(len(recs), 2)
        self.assertLess(recs[0]["evidence_seq"], recs[1]["evidence_seq"])

    def test_cross_verifier_link_refused(self):
        log_a = bi.BundleInspectionLog("va", self.digest)
        log_b = bi.BundleInspectionLog("vb", self.digest)
        link = log_a.admit("scan", self.script, _sha(self.script), 0, b"ok")
        with self.assertRaises(bi.BundleInspectionError) as ctx:
            log_b.verify_link(link)
        self.assertEqual(ctx.exception.code, "bundle-link-unverifiable")


if __name__ == "__main__":
    unittest.main()
