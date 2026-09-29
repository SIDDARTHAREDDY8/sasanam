"""Unit tests for gov.vc_bundle (VC-shaped evidence emission).

Wave-208 Lane A. These test the public seams of the module; the
break-first adversarial battery lives in evals/vc_bundle_probes.py.
"""

import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import vc_bundle as vcb  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_SEED_ISSUER = bytes.fromhex("71" * 32)
_SEED_HOLDER = bytes.fromhex("72" * 32)
_SEED_OTHER = bytes.fromhex("73" * 32)

NOW = "2026-06-01T00:00:00Z"


def _emit(signer, **kw):
    args = dict(
        issuer="sasanam:issuer:test-1",
        subject_id="sha256:abcdef",
        subject_claims={"audit_log_tip": "sha256:010203"},
        evidence=[{"type": "AttestationReport",
                   "attester": "tpm-quote", "verdict": "pass"}],
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2027-01-01T00:00:00Z",
        signer=signer,
    )
    args.update(kw)
    return vcb.emit_credential(**args)


class TestEmit(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer(_SEED_ISSUER)
        self.verifier = Ed25519Verifier(self.signer.public_key)

    def test_emit_shape(self):
        doc = _emit(self.signer)
        self.assertEqual(doc["@context"],
                         ["https://www.w3.org/ns/credentials/v2"])
        self.assertEqual(doc["type"],
                         ["VerifiableCredential",
                          "SasanamEvidenceCredential"])
        self.assertEqual(doc["issuer"], "sasanam:issuer:test-1")
        self.assertEqual(doc["credentialSubject"]["id"], "sha256:abcdef")
        self.assertEqual(doc["credentialSubject"]["audit_log_tip"],
                         "sha256:010203")
        self.assertIn("proves", doc["claimBounds"])
        self.assertIn("doesNotProve", doc["claimBounds"])
        proof = doc["proof"]
        self.assertEqual(proof["type"], "SasanamDSSEProof")
        self.assertEqual(proof["cryptosuite"], vcb.CRYPTO_SUITE)
        self.assertEqual(proof["payloadType"] if "payloadType" in proof
                         else None, None)  # payloadType lives in envelope
        self.assertEqual(proof["envelope"]["payloadType"],
                         vcb.PAYLOAD_TYPE)

    def test_emit_cryptosuite_is_ours_not_w3c(self):
        # Honest non-claim of interop: the cryptosuite label is ours.
        self.assertEqual(vcb.CRYPTO_SUITE,
                         "sasanam-dsse-pae-ed25519-v1")

    def test_emit_refuses_empty_issuer(self):
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, issuer="")

    def test_emit_refuses_inverted_validity(self):
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, valid_from="2027-01-01T00:00:00Z",
                   valid_until="2026-01-01T00:00:00Z")

    def test_emit_refuses_empty_subject_claims(self):
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, subject_claims={})

    def test_emit_refuses_evidence_without_type(self):
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, evidence=[{"attester": "x"}])

    def test_emit_refuses_bool_threshold(self):
        # True == 1 in Python; a bool threshold must be refused.
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, threshold=True)

    def test_emit_refuses_threshold_above_one(self):
        # emit seals with one signer: a document claiming a higher
        # quorum could never verify at it, yet would mislead an auditor
        # reading proof["threshold"].
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, threshold=2)

    def test_emit_refuses_reserved_subject_id_key(self):
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, subject_claims={"id": "spoofed"})

    def test_emit_refuses_non_json_native_claim(self):
        class O(object):
            def __str__(self):
                return "same"
        with self.assertRaises(vcb.VCBundleError):
            _emit(self.signer, subject_claims={"k": O()})


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer(_SEED_ISSUER)
        self.verifier = Ed25519Verifier(self.signer.public_key)
        self.other = Ed25519Verifier(
            Ed25519Signer(_SEED_OTHER).public_key)

    def test_verify_ok(self):
        doc = _emit(self.signer)
        detail = vcb.verify_credential(doc, verifiers=[self.verifier],
                                       now=NOW)
        self.assertTrue(detail["valid"])
        self.assertEqual(detail["issuer"], "sasanam:issuer:test-1")
        self.assertFalse(detail["redacted"])
        self.assertEqual(detail["evidence_count"], 1)

    def test_verify_wrong_key_refused(self):
        doc = _emit(self.signer)
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.other], now=NOW)

    def test_verify_context_url_never_resolved(self):
        # The @context URL is an identifier: verification must not
        # attempt to resolve it. Sockets are blocked for the duration.
        import socket
        doc = _emit(self.signer)
        real = socket.socket

        def _blocked(*a, **k):
            raise AssertionError("network access attempted")

        socket.socket = _blocked
        try:
            detail = vcb.verify_credential(doc,
                                           verifiers=[self.verifier],
                                           now=NOW)
        finally:
            socket.socket = real
        self.assertTrue(detail["valid"])

    def test_verify_rejects_extra_top_level_field(self):
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        doc["extra"] = "nope"
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)

    def test_verify_requires_claim_bounds(self):
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        del doc["claimBounds"]
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)

    def test_verify_rejects_foreign_cryptosuite(self):
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        doc["proof"]["cryptosuite"] = "DataIntegrityProof"
        with self.assertRaises(vcb.VCBundleError) as ctx:
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)
        self.assertIn("cryptosuite", str(ctx.exception).lower())

    def test_verify_rejects_sd_claim_in_notice(self):
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        doc["redactionNotice"] = {"method": "selective-disclosure",
                                  "note": "x", "derivedFrom": "y"}
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)

    def test_verify_refuses_none_verifiers_as_vc_error(self):
        # The public seam speaks one fail-closed vocabulary: a bare
        # TypeError must not leak.
        doc = _emit(self.signer)
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=None, now=NOW)

    def test_verify_refuses_unknown_proof_field(self):
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        doc["proof"]["evil"] = 1
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)

    def test_verify_wraps_unserializable_key(self):
        # A non-str dict key inside credentialSubject breaks
        # sort_keys with a bare TypeError; the seam must wrap it.
        import copy
        doc = copy.deepcopy(_emit(self.signer))
        doc["credentialSubject"][1] = "non-str key"
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(doc, verifiers=[self.verifier],
                                  now=NOW)


class TestRedact(unittest.TestCase):
    def setUp(self):
        self.issuer = Ed25519Signer(_SEED_ISSUER)
        self.holder = Ed25519Signer(_SEED_HOLDER)
        self.iv = Ed25519Verifier(self.issuer.public_key)
        self.hv = Ed25519Verifier(self.holder.public_key)

    def test_redact_round_trip(self):
        doc = _emit(
            self.issuer,
            subject_claims={"audit_log_tip": "sha256:010203",
                            "secret": "sha256:deadbeef"},
            evidence=[{"type": "AttestationReport", "verdict": "pass"},
                      {"type": "BreakBatteryResult", "held": 10}])
        red = vcb.redact_copy(
            doc, keep_subject_fields={"audit_log_tip"},
            keep_evidence_types={"AttestationReport"},
            holder_issuer="sasanam:holder:test-2", signer=self.holder,
            verifiers=[self.iv], valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z", now=NOW)
        self.assertEqual(red["credentialSubject"]["audit_log_tip"],
                         "sha256:010203")
        self.assertNotIn("secret", red["credentialSubject"])
        self.assertEqual([e["type"] for e in red["evidence"]],
                         ["AttestationReport"])
        notice = red["redactionNotice"]
        self.assertEqual(notice["method"], "redaction-by-copy")
        self.assertIn("NOT", notice["note"])
        detail = vcb.verify_credential(red, verifiers=[self.hv],
                                       now=NOW)
        self.assertTrue(detail["valid"])
        self.assertTrue(detail["redacted"])
        # The holder's re-issue does not verify under the issuer.
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(red, verifiers=[self.iv], now=NOW)

    def test_redact_verifies_source_first(self):
        doc = _emit(self.issuer)
        tampered = dict(doc)
        tampered["issuer"] = ""
        with self.assertRaises(vcb.VCBundleError):
            vcb.redact_copy(
                tampered, keep_subject_fields=set(),
                keep_evidence_types=set(),
                holder_issuer="sasanam:holder:test-2",
                signer=self.holder, verifiers=[self.iv],
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z", now=NOW)

    def test_redact_notice_bound_by_proof(self):
        # Tampering the notice after re-issue breaks the proof.
        import copy
        doc = _emit(self.issuer)
        red = vcb.redact_copy(
            doc, keep_subject_fields=set(), keep_evidence_types=set(),
            holder_issuer="sasanam:holder:test-2", signer=self.holder,
            verifiers=[self.iv], valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z", now=NOW)
        bad = copy.deepcopy(red)
        bad["redactionNotice"]["method"] = "selective-disclosure"
        with self.assertRaises(vcb.VCBundleError):
            vcb.verify_credential(bad, verifiers=[self.hv], now=NOW)


if __name__ == "__main__":
    unittest.main()
