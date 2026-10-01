"""Unit tests for the SLSA-shaped producer-authorization claim seam.

gov.evidence_bundle_v2: Fulcio-shaped identity tokens, an
application-scope registry with deny-by-default exact matching, and
SLSA-shaped producer claims that the evidence-cert ceremony must
carry on the claim path. gov.evidence_certs: the CA verifies the
claim at issuance and embeds it byte-identically into the
``evidence-cert-issued`` attestation; the legacy path (no claim) is
byte-identical to before.

Fixed clock and fixed key bytes keep these deterministic.
"""

import base64
import hashlib
import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519  # noqa: E402
from gov import evidence_certs as evidence_certs  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import kms as kms_mod  # noqa: E402

NOW = 1791000000
ISSUER = "https://issuer.example.com"
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
SCOPE = "payments/refunds"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed25519.publickey(seed)


ISSUER_SEED, ISSUER_PUB = _keypair(0x10)
CLAIM_SEED, CLAIM_PUB = _keypair(0x20)
ADMIN_SEED, ADMIN_PUB = _keypair(0x30)


class ProdauthTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="prodauth-ut-")
        self.audit = os.path.join(self.tmp, "audit.jsonl")
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        self.ca_pub = bytes(self.fake.test_signing_public_key("ca-key-1"))

    def make_ca(self, **over):
        kw = dict(kms_provider=self.fake, ca_key_id="ca-key-1",
                  ca_public_key=self.fake.test_signing_public_key("ca-key-1"),
                  issuers=[ISSUER],
                  approval_lookup={APPROVAL: {"decider": "alice",
                                              "state": "pending"}}.get,
                  audit_log_path=self.audit,
                  anchor_reachable=lambda: True, oid_arc=ARC,
                  now=lambda: NOW, claim_public_key=CLAIM_PUB)
        kw.update(over)
        return evidence_certs.EvidenceCA(**kw)

    def registry(self, **over):
        kw = dict(entries={"alice": [SCOPE]})
        kw.update(over)
        return eb2.ProducerRegistry(**kw)

    def token(self, sub="alice", **over):
        kw = dict(issuer_signing_key=ISSUER_SEED, sub=sub, now=lambda: NOW)
        kw.update(over)
        return eb2.mint_identity_token(**kw)

    def keypair(self, byte=0x01):
        seed, pub = _keypair(byte)
        key_id = hashlib.sha256(pub).hexdigest()[:16]
        return seed, pub, key_id

    def claim(self, reg=None, tok=None, seed=None, pub=None, key_id=None,
              **over):
        seed = ISSUER_SEED if seed is None else seed
        if key_id is None:
            _, pub, key_id = self.keypair()
        kw = dict(registry=self.registry() if reg is None else reg,
                  identity_token=self.token() if tok is None else tok,
                  identity_issuer_public_key=ISSUER_PUB,
                  requested_scope=SCOPE, subject_key_id=key_id,
                  approval_id=APPROVAL, claim_signing_key=CLAIM_SEED,
                  now=lambda: NOW)
        kw.update(over)
        return eb2.issue_producer_claim(**kw), key_id

    def issue_cert(self, ca, claim, seed, pub):
        chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8") \
            + hashlib.sha256(pub).digest()
        return ca.issue(
            identity_assertion={"iss": ISSUER, "sub": "alice",
                                "exp": NOW + 3600},
            ephemeral_pub=pub, pop_sig=ed25519.sign(seed, chal),
            approval_id=APPROVAL, intent_digest=INTENT,
            producer_authz_claim=claim)


# ---------------------------------------------------------------------------
# Registry discipline
# ---------------------------------------------------------------------------

class RegistryTests(ProdauthTestBase):
    def test_exact_scope_match(self):
        reg = self.registry()
        self.assertIs(reg.check("alice", SCOPE), True)

    def test_unknown_producer_denied(self):
        reg = self.registry()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.check("mallory", SCOPE)
        self.assertEqual(cm.exception.code, "prodauth-producer-unknown")

    def test_unregistered_scope_denied(self):
        reg = self.registry()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.check("alice", "admin/root")
        self.assertEqual(cm.exception.code, "prodauth-scope-not-authorized")

    def test_wildcard_scope_denied(self):
        reg = eb2.ProducerRegistry(entries={"alice": ["*"]})
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.check("alice", "payments/refunds")
        self.assertEqual(cm.exception.code, "prodauth-scope-not-authorized")

    def test_prefix_scope_denied(self):
        reg = self.registry()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.check("alice", "payments")
        self.assertEqual(cm.exception.code, "prodauth-scope-not-authorized")

    def test_admin_registration(self):
        reg = eb2.ProducerRegistry(admin_public_key=ADMIN_PUB,
                                   now=lambda: NOW)
        body = {"format": "prodauth-registry-statement.v1",
                "producer": "bob", "scopes": ["data/read"],
                "exp": NOW + 600}
        stmt = {"statement": body,
                "signature": base64.b64encode(
                    ed25519.sign(ADMIN_SEED, _canonical(body)))
                .decode("ascii")}
        self.assertEqual(reg.register(statement=stmt, now=lambda: NOW),
                         "bob")
        self.assertIs(reg.check("bob", "data/read"), True)

    def test_forged_registration_dishonored(self):
        reg = eb2.ProducerRegistry(admin_public_key=ADMIN_PUB,
                                   now=lambda: NOW)
        body = {"format": "prodauth-registry-statement.v1",
                "producer": "bob", "scopes": ["data/read"],
                "exp": NOW + 600}
        stmt = {"statement": body,
                "signature": base64.b64encode(b"0" * 64).decode("ascii")}
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.register(statement=stmt, now=lambda: NOW)
        self.assertEqual(cm.exception.code,
                         "prodauth-registry-unauthorized")
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm2:
            reg.check("bob", "data/read")
        self.assertEqual(cm2.exception.code, "prodauth-producer-unknown")

    def test_registration_without_admin_refused(self):
        reg = self.registry()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            reg.register(statement={"statement": {}, "signature": "x"},
                         now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-registry-unauthorized")

    def test_registry_accepts_int_now(self):
        # Constructor `now` accepts None/int/callable (repo
        # convention); an int must not break register()'s clock call.
        reg = eb2.ProducerRegistry(admin_public_key=ADMIN_PUB, now=NOW)
        body = {"format": "prodauth-registry-statement.v1",
                "producer": "carol", "scopes": ["data/read"],
                "exp": NOW + 600}
        stmt = {"statement": body,
                "signature": base64.b64encode(
                    ed25519.sign(ADMIN_SEED, _canonical(body)))
                .decode("ascii")}
        self.assertEqual(reg.register(statement=stmt, now=NOW), "carol")
        self.assertIs(reg.check("carol", "data/read"), True)


# ---------------------------------------------------------------------------
# Identity tokens (Fulcio-shaped)
# ---------------------------------------------------------------------------

class TokenTests(ProdauthTestBase):
    def test_mint_verify_round_trip(self):
        tok = eb2.mint_identity_token(issuer_signing_key=ISSUER_SEED,
                                      sub="alice", iss=ISSUER,
                                      now=lambda: NOW)
        out = eb2.verify_identity_token(tok, issuer_public_key=ISSUER_PUB,
                                        now=lambda: NOW)
        self.assertEqual(out["producer"], "alice")
        self.assertEqual(out["iss"], ISSUER)

    def test_audience_pinned(self):
        tok = self.token()
        self.assertEqual(tok["token"]["aud"], "sasanam-evcert-ca")
        tok["token"]["aud"] = "some-other-system"
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_identity_token(tok, issuer_public_key=ISSUER_PUB,
                                      now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-token-invalid")

    def test_forged_signature(self):
        tok = self.token()
        tok["token_signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_identity_token(tok, issuer_public_key=ISSUER_PUB,
                                      now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-token-invalid")

    def test_expired(self):
        tok = eb2.mint_identity_token(issuer_signing_key=ISSUER_SEED,
                                      sub="alice", ttl_s=60,
                                      now=lambda: NOW)
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_identity_token(tok, issuer_public_key=ISSUER_PUB,
                                      now=lambda: NOW + 3600)
        self.assertEqual(cm.exception.code, "prodauth-token-expired")

    def test_malformed(self):
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_identity_token({"nope": 1},
                                      issuer_public_key=ISSUER_PUB,
                                      now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-token-invalid")


# ---------------------------------------------------------------------------
# Producer claims (SLSA-shaped)
# ---------------------------------------------------------------------------

class ClaimTests(ProdauthTestBase):
    def test_issue_verify_round_trip(self):
        claim, key_id = self.claim()
        out = eb2.verify_producer_claim(
            claim, claim_public_key=CLAIM_PUB, approval_id=APPROVAL,
            subject_key_id=key_id, verify_time=NOW)
        self.assertEqual(out, {"producer": "alice", "scope": SCOPE})

    def test_slsa_shape(self):
        claim, _ = self.claim()
        stmt = claim["statement"]
        self.assertEqual(stmt["_type"],
                         "https://sasanam.dev/producer-authorization/v1")
        self.assertIn("subject", stmt)
        self.assertIn("predicate", stmt)
        self.assertEqual(stmt["predicateType"],
                         "https://sasanam.dev/"
                         "producer-authorization/predicate/v1")
        self.assertEqual(stmt["predicate"]["authorizedScope"], SCOPE)
        self.assertEqual(stmt["predicate"]["producer"]["identity"], "alice")

    def test_unknown_producer_issue_refused(self):
        reg = self.registry()
        tok = self.token(sub="mallory")
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.issue_producer_claim(
                registry=reg, identity_token=tok,
                identity_issuer_public_key=ISSUER_PUB,
                requested_scope=SCOPE, subject_key_id="ab" * 8,
                approval_id=APPROVAL, claim_signing_key=CLAIM_SEED,
                now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-producer-unknown")

    def test_scope_not_authorized_issue_refused(self):
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            self.claim(requested_scope="admin/root")
        self.assertEqual(cm.exception.code, "prodauth-scope-not-authorized")

    def test_approval_join_failure(self):
        claim, key_id = self.claim()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_producer_claim(
                claim, claim_public_key=CLAIM_PUB, approval_id="b" * 32,
                subject_key_id=key_id, verify_time=NOW)
        self.assertEqual(cm.exception.code, "prodauth-claim-mismatch")

    def test_subject_key_join_failure(self):
        claim, _ = self.claim()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_producer_claim(
                claim, claim_public_key=CLAIM_PUB, approval_id=APPROVAL,
                subject_key_id="ff" * 8, verify_time=NOW)
        self.assertEqual(cm.exception.code, "prodauth-claim-mismatch")

    def test_forged_signature(self):
        claim, key_id = self.claim()
        claim["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_producer_claim(
                claim, claim_public_key=CLAIM_PUB, approval_id=APPROVAL,
                subject_key_id=key_id, verify_time=NOW)
        self.assertEqual(cm.exception.code, "prodauth-claim-invalid")

    def test_expired(self):
        claim, key_id = self.claim()
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.verify_producer_claim(
                claim, claim_public_key=CLAIM_PUB, approval_id=APPROVAL,
                subject_key_id=key_id, verify_time=NOW + 3600)
        self.assertEqual(cm.exception.code, "prodauth-claim-expired")


# ---------------------------------------------------------------------------
# ed25519 verify contract (wave-243): exact bools, never truthiness
# ---------------------------------------------------------------------------

class VerifyContractTests(ProdauthTestBase):
    def test_good_signature_is_true(self):
        seed, _ = _keypair(0x01)
        msg = b"contract"
        self.assertIs(ed25519.verify(ed25519.publickey(seed), msg,
                                     ed25519.sign(seed, msg)), True)

    def test_forged_signature_is_false(self):
        seed, _ = _keypair(0x01)
        msg = b"contract"
        self.assertIs(ed25519.verify(ed25519.publickey(seed), msg,
                                     b"0" * 64), False)


# ---------------------------------------------------------------------------
# CA issuance with claim; legacy path byte-identical
# ---------------------------------------------------------------------------

class IssuanceTests(ProdauthTestBase):
    def test_claim_embedded_byte_identically(self):
        ca = self.make_ca()
        seed, pub, key_id = self.keypair()
        claim, _ = self.claim(key_id=key_id)
        _cert, entry = self.issue_cert(ca, claim, seed, pub)
        self.assertEqual(entry["producer_authz_claim"], claim)
        self.assertEqual(entry["producer_authz_claim"]["statement"]
                         ["predicate"]["producer"]["identity"], "alice")

    def test_forged_claim_refused_at_issuance(self):
        ca = self.make_ca()
        seed, pub, key_id = self.keypair()
        claim, _ = self.claim(key_id=key_id)
        claim["signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        with self.assertRaises(evidence_certs.EvidenceCertError) as cm:
            self.issue_cert(ca, claim, seed, pub)
        self.assertEqual(cm.exception.code, "prodauth-claim-invalid")

    def test_legacy_issue_has_no_claim_key(self):
        ca = self.make_ca()
        seed, pub, _ = self.keypair(byte=0x07)
        chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8") \
            + hashlib.sha256(pub).digest()
        _cert, entry = ca.issue(
            identity_assertion={"iss": ISSUER, "sub": "alice",
                                "exp": NOW + 3600},
            ephemeral_pub=pub, pop_sig=ed25519.sign(seed, chal),
            approval_id=APPROVAL, intent_digest=INTENT)
        self.assertNotIn("producer_authz_claim", entry)

    def test_ca_without_claim_key_rejects_claim(self):
        ca = self.make_ca(claim_public_key=None)
        seed, pub, key_id = self.keypair()
        claim, _ = self.claim(key_id=key_id)
        with self.assertRaises(evidence_certs.EvidenceCertError) as cm:
            self.issue_cert(ca, claim, seed, pub)
        self.assertEqual(cm.exception.code, "prodauth-claim-invalid")


# ---------------------------------------------------------------------------
# Orchestration: claim-path submit + verify
# ---------------------------------------------------------------------------

class OrchestrationTests(ProdauthTestBase):
    def _claim_fixture(self):
        ca = self.make_ca()
        seed, pub, key_id = self.keypair()
        claim, _ = self.claim(key_id=key_id)
        cert, _entry = self.issue_cert(ca, claim, seed, pub)
        body = {"decision": "deny"}
        sig = bytes(ed25519.sign(seed, _canonical(body)))
        return ca, seed, pub, cert, body, sig

    def test_claim_path_round_trip(self):
        _ca, _seed, _pub, cert, body, sig = self._claim_fixture()
        tlog = eb2.make_log(
            producer_auth_verifier=eb2.default_producer_auth_verifier,
            now=lambda: NOW)
        sub = eb2.submit_evidence_with_producer_claim(
            artifact_body=body, cert=cert, artifact_signature=sig,
            approval_id=APPROVAL, intent_digest=INTENT,
            audit_log_path=self.audit, ca_public_key=self.ca_pub,
            verify_time=NOW, identity_token=self.token(),
            identity_issuer_public_key=ISSUER_PUB,
            producer_registry=self.registry(), requested_scope=SCOPE,
            claim_public_key=CLAIM_PUB, transparency_log=tlog,
            now=lambda: NOW)
        self.assertEqual(sub["kind"], "evidence-submission.v2")
        out = eb2.verify_submission(
            submission=sub, audit_log_path=self.audit,
            ca_public_key=self.ca_pub, verify_time=NOW,
            transparency_log=tlog, require_producer_claim=True,
            claim_public_key=CLAIM_PUB)
        self.assertIs(out["verified"], True)
        self.assertEqual(out["producer_authz"],
                         {"producer": "alice", "scope": SCOPE})

    def test_legacy_verify_submission_untouched(self):
        # Legacy path: the return dict must be byte-identical to
        # before -- no producer_authz key at all.
        ca = self.make_ca(claim_public_key=None)
        seed, pub, _ = self.keypair(byte=0x07)
        chal = b"evcert-pop-v1" + APPROVAL.encode("utf-8") \
            + hashlib.sha256(pub).digest()
        cert, _entry = ca.issue(
            identity_assertion={"iss": ISSUER, "sub": "alice",
                                "exp": NOW + 3600},
            ephemeral_pub=pub, pop_sig=ed25519.sign(seed, chal),
            approval_id=APPROVAL, intent_digest=INTENT)
        body = {"x": 1}
        tlog = eb2.make_log(
            producer_auth_verifier=eb2.default_producer_auth_verifier,
            now=lambda: NOW)
        sub = eb2.submit_evidence(
            artifact_body=body, cert=cert,
            artifact_signature=bytes(ed25519.sign(seed, _canonical(body))),
            approval_id=APPROVAL, intent_digest=INTENT,
            audit_log_path=self.audit, ca_public_key=self.ca_pub,
            verify_time=NOW, transparency_log=tlog, now=lambda: NOW)
        out = eb2.verify_submission(
            submission=sub, audit_log_path=self.audit,
            ca_public_key=self.ca_pub, verify_time=NOW,
            transparency_log=tlog)
        self.assertIs(out["verified"], True)
        self.assertNotIn("producer_authz", out)

    def test_forged_token_never_reaches_log(self):
        _ca, _seed, _pub, cert, body, sig = self._claim_fixture()
        bad = dict(self.token())
        bad["token_signature"] = base64.b64encode(b"0" * 64).decode("ascii")
        with self.assertRaises(eb2.EvidenceBundleV2Error) as cm:
            eb2.submit_evidence_with_producer_claim(
                artifact_body=body, cert=cert, artifact_signature=sig,
                approval_id=APPROVAL, intent_digest=INTENT,
                audit_log_path=self.audit, ca_public_key=self.ca_pub,
                verify_time=NOW, identity_token=bad,
                identity_issuer_public_key=ISSUER_PUB,
                producer_registry=self.registry(), requested_scope=SCOPE,
                claim_public_key=CLAIM_PUB, now=lambda: NOW)
        self.assertEqual(cm.exception.code, "prodauth-token-invalid")


if __name__ == "__main__":
    unittest.main()
