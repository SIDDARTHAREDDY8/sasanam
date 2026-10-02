#!/usr/bin/env python3
"""Unit tests for per-bundle Verification Summary Attestations
(wave-279): ``gov.bundle_vsa`` (issue / verify / attach), the
trust-labeled ``input_attestations`` extension on
``VSAIssuer.issue``, and the seal-time wiring in
``gov.evidence_bundle_v2.seal_evidence``.

Conventions: staging default; fixtures through the audited
evidence-cert ceremony (fixed seeds, independent literals); the
refusal lattice asserts each code at its exact trigger point;
``verify`` results asserted with ``is True`` (wave-243); hostile
shapes must refuse machine-coded, never as raw exceptions (F245).
"""

import base64
import copy
import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key: tests/__init__ provisions one on package
# import; setdefault covers direct-script runs.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w279-bundle-vsa-ut")

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov import bundle_vsa as bvsa  # noqa: E402
from gov import provenance_policy as pp  # noqa: E402

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
ISSUER = "https://issuer.example.com"
SEALER_ID = "sasanam-evidence-sealer/test"
SEALER_SEED = bytes([0x5E]) * 32
VSA_POLICY = "sasanam-evidence-seal/v1"
VSA_TTL = 86400


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _sealer():
    return pp.VSAIssuer(SEALER_ID, SEALER_SEED)


def _digest(b=b"bundle"):
    return hashlib.sha256(b).hexdigest()


def _good_vsa(**over):
    issuer = over.pop("issuer", _sealer())
    return bvsa.issue_bundle_vsa(
        issuer=issuer, bundle_digest=over.pop("bundle_digest", _digest()),
        policy_id=over.pop("policy_id", VSA_POLICY),
        verified_level=over.pop("verified_level", "SLSA_BUILD_LEVEL_1"),
        input_attestations=over.pop("input_attestations", []),
        issued_at=over.pop("issued_at", NOW),
        ttl_seconds=over.pop("ttl_seconds", VSA_TTL), **over)


def _verify(vsa, digest=None, **over):
    issuer = over.pop("issuer", _sealer())
    return bvsa.verify_bundle_vsa(
        vsa, verifier_pubkey_hex=over.pop(
            "verifier_pubkey_hex", issuer.public_key_hex),
        expected_bundle_digest=over.pop(
            "expected_bundle_digest",
            _digest() if digest is None else digest),
        now=over.pop("now", NOW), **over)


class IssueTests(unittest.TestCase):
    def test_round_trip_fields(self):
        receipts = [{"kind": "signature-attestation",
                     "digest": _digest(b"att"),
                     "trust": "platform-supplied"}]
        vsa = _good_vsa(input_attestations=receipts)
        self.assertEqual(vsa["format"], "sasanam-vsa/1")
        self.assertEqual(vsa["subject"]["digest"]["sha256"], _digest())
        self.assertEqual(vsa["policy_id"], VSA_POLICY)
        self.assertEqual(vsa["verifier"]["id"], SEALER_ID)
        self.assertEqual(vsa["verified_level"], "SLSA_BUILD_LEVEL_1")
        self.assertEqual(vsa["input_attestations"], receipts)
        self.assertEqual(vsa["issued_at"], float(NOW))
        self.assertEqual(vsa["expires_at"], float(NOW) + VSA_TTL)
        checked = _verify(vsa)
        self.assertIs(checked, vsa)

    def test_omitted_receipts_keep_historical_body(self):
        # input_attestations=None keeps the VSAIssuer.issue body
        # byte-identical to the pre-wave-279 shape.
        issuer = _sealer()
        via_lane = bvsa.issue_bundle_vsa(
            issuer=issuer, bundle_digest=_digest(), policy_id=VSA_POLICY,
            verified_level="SLSA_BUILD_LEVEL_1", issued_at=NOW,
            ttl_seconds=VSA_TTL)
        direct = issuer.issue(_digest(), VSA_POLICY, "SLSA_BUILD_LEVEL_1",
                              NOW, VSA_TTL)
        self.assertNotIn("input_attestations", via_lane)
        self.assertNotIn("input_attestations", direct)
        self.assertEqual(
            {k: v for k, v in via_lane.items() if k != "signature"},
            {k: v for k, v in direct.items() if k != "signature"})

    def test_receipts_are_signed(self):
        # The receipts ride INSIDE the signed body: swapping them
        # after issue breaks the signature.
        vsa = _good_vsa(input_attestations=[
            {"kind": "r", "digest": _digest(b"a"),
             "trust": "platform-supplied"}])
        tampered = copy.deepcopy(vsa)
        tampered["input_attestations"][0]["digest"] = _digest(b"b")
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(tampered)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_unlabeled_receipt_refused(self):
        with self.assertRaises(ValueError):
            _good_vsa(input_attestations=[
                {"kind": "r", "digest": _digest()}])

    def test_mislabeled_receipt_refused(self):
        with self.assertRaises(ValueError):
            _good_vsa(input_attestations=[
                {"kind": "r", "digest": _digest(), "trust": "maybe"}])

    def test_receipt_without_digest_refused(self):
        with self.assertRaises(ValueError):
            _good_vsa(input_attestations=[
                {"kind": "r", "trust": "platform-supplied"}])

    def test_non_issuer_refused(self):
        with self.assertRaises(ValueError):
            bvsa.issue_bundle_vsa(
                issuer="not-an-issuer", bundle_digest=_digest(),
                policy_id=VSA_POLICY,
                verified_level="SLSA_BUILD_LEVEL_1", issued_at=NOW)

    def test_bad_ttl_refused(self):
        with self.assertRaises(ValueError):
            _good_vsa(ttl_seconds=0)
        with self.assertRaises(ValueError):
            _good_vsa(ttl_seconds="x")

    def test_bad_issued_at_refused(self):
        with self.assertRaises(ValueError):
            _good_vsa(issued_at=float("nan"))
        with self.assertRaises(ValueError):
            _good_vsa(issued_at=True)

    def test_issuer_issue_extension_validates(self):
        issuer = _sealer()
        with self.assertRaises(ValueError):
            issuer.issue(_digest(), VSA_POLICY, "SLSA_BUILD_LEVEL_1",
                         NOW, VSA_TTL,
                         input_attestations=[{"kind": "r",
                                              "digest": _digest()}])

    def test_signature_domain_shared(self):
        # Issuer and verifier share one domain: no drift between the
        # signing seam and the verification seam.
        self.assertEqual(bvsa._VSA_DOMAIN, pp._VSA_DOMAIN)  # noqa: SLF001
        self.assertEqual(bvsa.VSA_FORMAT, pp.VSA_FORMAT)


class VerifyTests(unittest.TestCase):
    def test_forged_signature_refused(self):
        vsa = _good_vsa()
        bad = copy.deepcopy(vsa)
        raw = bytearray(bytes.fromhex(bad["signature"]["sig"]))
        raw[-1] ^= 0x01
        bad["signature"]["sig"] = bytes(raw).hex()
        # The ed25519 contract returns False on forgery (wave-243);
        # the verifier checks the False and refuses coded.
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(bad)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_wrong_key_refused(self):
        vsa = _good_vsa()
        other = pp.VSAIssuer("other", bytes([0x09]) * 32)
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(vsa, verifier_pubkey_hex=other.public_key_hex)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_digest_mismatch_refused(self):
        vsa = _good_vsa(bundle_digest=_digest(b"a"))
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(vsa, expected_bundle_digest=_digest(b"b"))
        self.assertEqual(cm.exception.code, "provenance-subject-refused")

    def test_expired_refused(self):
        vsa = _good_vsa(issued_at=NOW - 7200, ttl_seconds=3600)
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(vsa)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_not_yet_valid_refused(self):
        vsa = _good_vsa(issued_at=NOW + 3600)
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(vsa)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_unknown_level_refused(self):
        # The level gate must fire on a CORRECTLY-SIGNED VSA carrying
        # an unknown level (defense in depth against a foreign
        # issuer): build the body by hand and sign it with the
        # sealer seed under the shared domain.
        issuer = _sealer()
        body = {
            "format": "sasanam-vsa/1",
            "subject": {"digest": {"sha256": _digest()}},
            "policy_id": VSA_POLICY,
            "verified_level": "SLSA_BUILD_LEVEL_9",
            "verifier": {"id": SEALER_ID},
            "issued_at": float(NOW),
            "expires_at": float(NOW) + VSA_TTL,
        }
        sig = ed.sign(SEALER_SEED,
                      pp._VSA_DOMAIN + pp.canonical_bytes(body))  # noqa: SLF001
        body["signature"] = {"key_id": issuer.public_key_hex,
                             "sig": sig.hex()}
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            _verify(body)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")
        self.assertIn("not a known rank", cm.exception.detail)

    def test_hostile_shapes_refused_coded(self):
        hostiles = [None, "x", [], b"vsa", 42,
                    {"format": "sasanam-statement/9"},
                    {"format": pp.VSA_FORMAT},
                    {"format": pp.VSA_FORMAT, "signature": {"sig": "zz"}},
                    {"format": pp.VSA_FORMAT, "signature": "not-a-dict"},
                    {"format": pp.VSA_FORMAT,
                     "signature": {"sig": "00" * 64},
                     "subject": "not-a-dict"},
                    {"format": pp.VSA_FORMAT,
                     "signature": {"sig": "00" * 64},
                     "subject": {"digest": {"sha256": ["unhashable"]}},
                     "issued_at": NOW, "expires_at": NOW + 1,
                     "verified_level": ["unhashable"]}]
        allowed = {"provenance-vsa-refused", "provenance-subject-refused"}
        for h in hostiles:
            with self.assertRaises(bvsa.BundleVSAError,
                                   msg="hostile %r" % (type(h).__name__,)):
                _verify(h)
            try:
                _verify(h)
            except bvsa.BundleVSAError as exc:
                self.assertIn(exc.code, allowed)

    def test_bad_clock_refused_coded(self):
        vsa = _good_vsa()
        for bad_now in (True, "x", float("nan"), float("inf")):
            with self.assertRaises(bvsa.BundleVSAError) as cm:
                _verify(vsa, now=bad_now)
            self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_malformed_pinned_key_refused(self):
        vsa = _good_vsa()
        for bad_key in ("zz", "00" * 16, None, ["x"]):
            with self.assertRaises(bvsa.BundleVSAError) as cm:
                _verify(vsa, verifier_pubkey_hex=bad_key)
            self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_error_codes_are_closed_vocabulary(self):
        with self.assertRaises(ValueError):
            bvsa.BundleVSAError("not-a-real-code", "x")


class AttachTests(unittest.TestCase):
    def test_attach_files_vsa(self):
        sealed = {"kind": "evidence-bundle.v2", "artifact": {}}
        vsa = _good_vsa()
        filed = bvsa.attach_bundle_vsa(sealed, vsa)
        self.assertIs(filed["vsa"], vsa)
        self.assertNotIn("vsa", sealed)  # the input is not mutated

    def test_double_attach_refused(self):
        sealed = {"kind": "evidence-bundle.v2",
                  "vsa": _good_vsa()}
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            bvsa.attach_bundle_vsa(sealed, _good_vsa())
        self.assertEqual(cm.exception.code, "evbundle-malformed")

    def test_non_dict_sealed_refused(self):
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            bvsa.attach_bundle_vsa(["x"], _good_vsa())
        self.assertEqual(cm.exception.code, "evbundle-malformed")

    def test_non_vsa_refused(self):
        with self.assertRaises(bvsa.BundleVSAError) as cm:
            bvsa.attach_bundle_vsa({}, {"format": "nope"})
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")

    def test_default_receipts_platform_supplied(self):
        att = {"artifact_digest": _digest(), "cert_digest": _digest(b"c")}
        receipts = bvsa.bundle_input_attestations(att)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["kind"], "signature-attestation")
        self.assertEqual(receipts[0]["trust"], "platform-supplied")
        self.assertEqual(receipts[0]["digest"],
                         hashlib.sha256(
                             _canonical(att)).hexdigest())

    def test_default_receipts_non_dict_refused(self):
        with self.assertRaises(ValueError):
            bvsa.bundle_input_attestations("x")


class SealWiringTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bundle-vsa-ut-")
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")

    def make_ca(self, **over):
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
        kw = dict(kms_provider=over.pop("kms_provider", self.fake),
                  ca_key_id="ca-key-1",
                  ca_public_key=self.fake.test_signing_public_key(
                      "ca-key-1"),
                  issuers=[ISSUER],
                  approval_lookup=approvals.get,
                  audit_log_path=over.pop("audit_log_path",
                                          self.audit_path),
                  anchor_reachable=lambda: True,
                  oid_arc=ARC,
                  now=lambda: NOW)
        kw.update(over)
        return ec.EvidenceCA(**kw)

    def issue_cert(self, ca, seed_byte=0x01, approval_id=APPROVAL):
        seed, pub = _keypair(seed_byte)
        chal = (POP_DOMAIN + approval_id.encode("utf-8")
                + hashlib.sha256(pub).digest())
        req = {"identity_assertion": {"iss": ISSUER, "sub": "alice",
                                      "exp": NOW + 3600},
               "ephemeral_pub": pub,
               "pop_sig": ed.sign(seed, chal),
               "approval_id": approval_id,
               "intent_digest": INTENT}
        cert, _entry = ca.issue(**req)
        return cert, seed, pub

    def seal_kwargs(self, cert, seed, ca_pub, body=None):
        body = {"decision": "deny"} if body is None else body
        sig = ed.sign(seed, _canonical(body))
        return dict(artifact_body=body, cert=cert,
                    artifact_signature=bytes(sig),
                    approval_id=APPROVAL, intent_digest=INTENT,
                    ca_public_key=bytes(ca_pub), verify_time=NOW)

    def test_seal_without_issuer_has_no_vsa(self):
        ca = self.make_ca()
        cert, seed, _pub = self.issue_cert(ca)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        self.assertNotIn("vsa", sealed)
        self.assertEqual(set(sealed),
                         {"kind", "artifact", "signature_attestation",
                          "cert", "cert_digest"})

    def test_seal_with_issuer_carries_verifying_vsa(self):
        ca = self.make_ca()
        cert, seed, _pub = self.issue_cert(ca, seed_byte=0x02)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        issuer = _sealer()
        sealed = eb2.seal_evidence(
            vsa_issuer=issuer, vsa_policy_id=VSA_POLICY,
            vsa_issued_at=NOW,
            **self.seal_kwargs(cert, seed, ca_pub))
        vsa = sealed["vsa"]
        self.assertEqual(
            vsa["subject"]["digest"]["sha256"],
            sealed["artifact"]["artifact_digest"])
        checked = bvsa.verify_bundle_vsa(
            vsa, verifier_pubkey_hex=issuer.public_key_hex,
            expected_bundle_digest=sealed["artifact"]["artifact_digest"],
            now=NOW)
        self.assertIs(checked, vsa)
        # The default receipts name the seal's own attestation.
        self.assertEqual(len(vsa["input_attestations"]), 1)
        self.assertEqual(vsa["input_attestations"][0]["trust"],
                         "platform-supplied")

    def test_seal_with_custom_receipts(self):
        ca = self.make_ca()
        cert, seed, _pub = self.issue_cert(ca, seed_byte=0x03)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        issuer = _sealer()
        receipts = [{"kind": "human-corroboration",
                     "digest": _digest(b"hc"),
                     "trust": "agent-supplied"}]
        sealed = eb2.seal_evidence(
            vsa_issuer=issuer, vsa_input_attestations=receipts,
            vsa_issued_at=NOW,
            **self.seal_kwargs(cert, seed, ca_pub))
        self.assertEqual(sealed["vsa"]["input_attestations"], receipts)

    def test_sealed_bundle_still_verifies(self):
        # The additive "vsa" key must not break the seal verification
        # path (verify_sealed_bundle reads named keys only).
        ca = self.make_ca()
        cert, seed, _pub = self.issue_cert(ca, seed_byte=0x04)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        issuer = _sealer()
        sealed = eb2.seal_evidence(
            vsa_issuer=issuer, vsa_issued_at=NOW,
            **self.seal_kwargs(cert, seed, ca_pub))
        out = eb2.verify_sealed_bundle(
            sealed=sealed, audit_log_path=self.audit_path,
            ca_public_key=bytes(ca_pub), verify_time=NOW)
        self.assertIs(out["verified"], True)


class InteropTests(unittest.TestCase):
    def test_lane_vsa_admits_under_provenance_policy(self):
        # The seal-issued VSA must admit under the EXISTING
        # admission-time consumer with the sealer pinned.
        issuer = _sealer()
        vsa = bvsa.issue_bundle_vsa(
            issuer=issuer, bundle_digest=_digest(), policy_id=VSA_POLICY,
            verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
            issued_at=NOW, ttl_seconds=VSA_TTL)
        policy = pp.ProvenancePolicy(
            name=VSA_POLICY, allowed_sources=["unrecorded"],
            allowed_builders=[SEALER_ID],
            tag_policy={"mode": "any"}, expected_inputs={},
            require_signed_statement=False, statement_signers={},
            trusted_verifiers={SEALER_ID: issuer.public_key_hex},
            vsa_max_age_seconds=86400,
            vsa_required_level="SLSA_BUILD_LEVEL_1")
        self.assertIs(policy.admit_vsa(vsa, VSA_POLICY, _digest(),
                                       now=NOW), True)

    def test_vsa_for_other_policy_does_not_admit(self):
        issuer = _sealer()
        vsa = bvsa.issue_bundle_vsa(
            issuer=issuer, bundle_digest=_digest(),
            policy_id="some-other-policy",
            verified_level="SLSA_BUILD_LEVEL_1", input_attestations=[],
            issued_at=NOW, ttl_seconds=VSA_TTL)
        policy = pp.ProvenancePolicy(
            name=VSA_POLICY, allowed_sources=["unrecorded"],
            allowed_builders=[SEALER_ID],
            tag_policy={"mode": "any"}, expected_inputs={},
            require_signed_statement=False, statement_signers={},
            trusted_verifiers={SEALER_ID: issuer.public_key_hex},
            vsa_max_age_seconds=86400,
            vsa_required_level="SLSA_BUILD_LEVEL_1")
        with self.assertRaises(pp.ProvenancePolicyError) as cm:
            policy.admit_vsa(vsa, VSA_POLICY, _digest(), now=NOW)
        self.assertEqual(cm.exception.code, "provenance-vsa-refused")


if __name__ == "__main__":
    unittest.main()
