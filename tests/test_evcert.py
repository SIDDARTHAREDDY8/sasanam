#!/usr/bin/env python3
"""Unit tests for the evidence-cert ceremony (gov/evidence_certs.py),
the KMS ``sign`` seam (gov/kms.py, gov/kms_vault.py), and the 14
``evcert-*`` decision codes.

Conventions: staging default; spec vectors are independent literals
(fixed seeds / fixed keys), never recomputed through the code under
test; ``verify`` results asserted with ``is True`` / ``is False``
(wave-243); the lane-local taxonomy pin is asserted on raw source
literals, never ``len(dict)`` (wave-260); ``tests/test_decision_codes.py``
keeps the pre-lane global pin at 1299 for the merge coordinator.
"""

import base64
import hashlib
import json
import os
import secrets
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key: tests/__init__ provisions one on package
# import; setdefault covers direct-script runs.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w269-evcert-ut")

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module
ARC = "1.3.6.1.4.1.99999"


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


class CABase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="evcert-ut-")

    def make_ca(self, **over):
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {"a" * 32: {"decider": "alice", "state": "pending"},
                     "b" * 32: {"decider": "alice", "state": "approved"}}
        kw = dict(kms_provider=over.pop("kms_provider", self.fake),
                  ca_key_id="ca-key-1",
                  ca_public_key=self.fake.test_signing_public_key(
                      "ca-key-1"),
                  issuers=["https://issuer.example.com"],
                  approval_lookup=approvals.get,
                  audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
                  anchor_reachable=lambda: True,
                  oid_arc=ARC,
                  now=lambda: NOW)
        kw.update(over)
        return ec.EvidenceCA(**kw)

    def good_req(self, seed_byte=0x01, approval_id="a" * 32,
                 iss="https://issuer.example.com", sub="alice", exp=None,
                 lifetime_s=None):
        seed, pub = _keypair(seed_byte)
        chal = (POP_DOMAIN + approval_id.encode("utf-8")
                + hashlib.sha256(pub).digest())
        req = {"identity_assertion":
               {"iss": iss, "sub": sub,
                "exp": NOW + 3600 if exp is None else exp},
               "ephemeral_pub": pub,
               "pop_sig": ed.sign(seed, chal),
               "approval_id": approval_id,
               "intent_digest": "d" * 64}
        if lifetime_s is not None:
            req["lifetime_s"] = lifetime_s
        return req, seed, pub

    def assertRefuses(self, fn, code):
        try:
            fn()
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, code,
                             "wrong refusal code: %r" % (e.code,))
            return
        self.fail("expected refusal %s, but the call succeeded" % code)


class RefusalLatticeTests(CABase):
    def test_malformed_request_shapes(self):
        ca = self.make_ca()
        req, _, _ = self.good_req()
        bad = dict(req, ephemeral_pub=b"short")
        self.assertRefuses(lambda: ca.issue(**bad),
                           "evcert-malformed-request")
        bad = dict(req, pop_sig=b"short")
        self.assertRefuses(lambda: ca.issue(**bad),
                           "evcert-malformed-request")
        bad = dict(req, approval_id="not-hex")
        self.assertRefuses(lambda: ca.issue(**bad),
                           "evcert-malformed-request")
        bad = dict(req, intent_digest="abc")
        self.assertRefuses(lambda: ca.issue(**bad),
                           "evcert-malformed-request")
        bad = dict(req, identity_assertion={"iss": "", "sub": "alice",
                                            "exp": NOW + 1})
        self.assertRefuses(lambda: ca.issue(**bad),
                           "evcert-malformed-request")

    def test_unknown_issuer(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(iss="https://evil.example/")
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-unknown-issuer")

    def test_assertion_expired(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(exp=NOW - 1)
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-assertion-expired")
        # an assertion with no expiry is expired by policy
        req2, _, _ = self.good_req()
        del req2["identity_assertion"]["exp"]
        self.assertRefuses(lambda: ca.issue(**req2),
                           "evcert-assertion-expired")

    def test_unknown_approval(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(approval_id="c" * 32)
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-unknown-approval")
        # resolved approvals are not issuable
        req2, _, _ = self.good_req(seed_byte=0x02, approval_id="b" * 32)
        self.assertRefuses(lambda: ca.issue(**req2),
                           "evcert-unknown-approval")

    def test_identity_not_decider(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(sub="mallory")
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-identity-not-decider")

    def test_pop_invalid_wrong_key(self):
        ca = self.make_ca()
        req, _, pub = self.good_req()
        evil_seed, _ = _keypair(0xE1)
        chal = (POP_DOMAIN + req["approval_id"].encode("utf-8")
                + hashlib.sha256(pub).digest())
        req["pop_sig"] = ed.sign(evil_seed, chal)
        self.assertRefuses(lambda: ca.issue(**req), "evcert-pop-invalid")

    def test_pop_invalid_wrong_challenge(self):
        ca = self.make_ca()
        req, seed, pub = self.good_req()
        other_chal = (POP_DOMAIN + ("f" * 32).encode("utf-8")
                      + hashlib.sha256(pub).digest())
        req["pop_sig"] = ed.sign(seed, other_chal)
        self.assertRefuses(lambda: ca.issue(**req), "evcert-pop-invalid")

    def test_key_reused(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(seed_byte=0x0A)
        ca.issue(**req)
        req2, _, _ = self.good_req(seed_byte=0x0A, approval_id="a" * 32)
        # same key, same approval: still reuse
        self.assertRefuses(lambda: ca.issue(**req2), "evcert-key-reused")

    def test_anchor_unavailable(self):
        ca = self.make_ca(anchor_reachable=lambda: False)
        req, _, _ = self.good_req()
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-anchor-unavailable")

    def test_anchor_exception_propagates(self):
        def _boom():
            raise RuntimeError("anchor exploded")
        ca = self.make_ca(anchor_reachable=_boom)
        req, _, _ = self.good_req()
        with self.assertRaises(RuntimeError):
            ca.issue(**req)

    def test_lifetime_exceeded(self):
        ca = self.make_ca()
        req, _, _ = self.good_req(lifetime_s=7200)
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-lifetime-exceeded")
        req2, _, _ = self.good_req(seed_byte=0x02, lifetime_s=10)
        self.assertRefuses(lambda: ca.issue(**req2),
                           "evcert-lifetime-exceeded")

    def test_kms_cannot_sign(self):
        class EnvelopeOnly(kms_mod.KmsProvider):
            provider_name = "envelope-only"

            def wrap_data_key(self, key_id, plaintext):
                return b"w"

            def unwrap_data_key(self, key_id, wrapped):
                return b"u"

            def describe_key(self, key_id):
                return kms_mod.KeyDescription(key_id, "envelope-only")

        ca = self.make_ca(kms_provider=EnvelopeOnly())
        req, _, _ = self.good_req()
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-kms-cannot-sign")


class IssuerAllowlistTests(CABase):
    def test_exact_and_wildcard(self):
        ca = self.make_ca(issuers=["https://issuer.example.com",
                                   "https://*.dept.example.com"])
        req, _, _ = self.good_req(seed_byte=0x11,
                                   iss="https://eng.dept.example.com")
        cert, _ = ca.issue(**req)
        self.assertEqual(cert["extensions"][ARC + ".1.8"],
                         "https://eng.dept.example.com")

    def test_wildcard_cannot_span_labels(self):
        ca = self.make_ca(issuers=["https://*.dept.example.com"])
        req, _, _ = self.good_req(iss="https://a.b.dept.example.com")
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-unknown-issuer")

    def test_wildcard_suffix_confusion(self):
        ca = self.make_ca(issuers=["https://*.dept.example.com"])
        req, _, _ = self.good_req(
            iss="https://dept.example.com.evil.com")
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-unknown-issuer")

    def test_non_https_never_matches(self):
        ca = self.make_ca(issuers=["https://*.dept.example.com"])
        req, _, _ = self.good_req(
            iss="http://eng.dept.example.com")
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-unknown-issuer")

class HappyPathTests(CABase):
    def test_issue_and_verify_round_trip(self):
        ca = self.make_ca()
        req, seed, pub = self.good_req()
        cert, stored = ca.issue(**req)
        # shape
        self.assertEqual(cert["format"], "sasanam-evidence-cert/v1")
        self.assertEqual(cert["eku"], "evidence-signing")
        self.assertEqual(cert["subject_key_id"],
                         hashlib.sha256(pub).hexdigest()[:16])
        self.assertEqual(cert["not_before"], NOW)
        self.assertEqual(cert["not_after"], NOW + 600)
        self.assertEqual(cert["extensions"]["approval_id"], "a" * 32)
        self.assertEqual(cert["extensions"]["principal"], "alice")
        self.assertIn("honest_limits", cert)
        # CA signature verifies under the configured CA key (exact True)
        body = {k: v for k, v in cert.items() if k != "ca_signature"}
        canonical = json.dumps(body, sort_keys=True,
                               separators=(",", ":")).encode()
        sig = base64.b64decode(cert["ca_signature"])
        digest = hashlib.sha256(canonical).digest()
        self.assertIs(
            ed.verify(self.fake.test_signing_public_key("ca-key-1"),
                      digest, sig), True)
        # audit entry stored
        self.assertEqual(stored["kind"], "evidence-cert-issued")
        self.assertEqual(stored["cert_digest"],
                         hashlib.sha256(canonical).hexdigest())
        # registry persisted
        with open(os.path.join(self.tmp, "evcert-seen-keys.json")) as f:
            reg = json.load(f)
        self.assertIn(cert["subject_key_id"], reg)
        # chain verifies at issuance time
        chain = ec.verify_cert_chain(
            cert, self.fake.test_signing_public_key("ca-key-1"), NOW + 1)
        self.assertEqual(chain["subject_key_id"], cert["subject_key_id"])
        # evidence signature verifies: chain-then-binding
        artifact = b"decision-packet-bytes"
        art_sig = ed.sign(seed, artifact)
        out = ec.verify_evidence_signature(
            cert=cert, artifact_bytes=artifact,
            artifact_signature=art_sig, approval_id="a" * 32,
            intent_digest="d" * 64,
            ca_public_key=self.fake.test_signing_public_key("ca-key-1"),
            verify_time=NOW + 2)
        self.assertTrue(out["verified"])
        self.assertEqual(out["cert_digest"], stored["cert_digest"])
        # artifact attestation joins on cert_digest, carries no issuance
        # metadata
        att = ec.make_signature_attestation(
            cert, hashlib.sha256(artifact).hexdigest(),
            base64.b64encode(art_sig).decode())
        self.assertEqual(att["cert_digest"], stored["cert_digest"])
        for leaked in ("approval_id", "principal", "ca_signature",
                       "not_before", "issuer_key_id"):
            self.assertNotIn(leaked, att)

    def test_deterministic_issuance(self):
        import shutil
        tmp2 = tempfile.mkdtemp(prefix="evcert-ut2-")
        self.addCleanup(shutil.rmtree, tmp2, True)
        ca1 = self.make_ca()
        req1, _, _ = self.good_req(seed_byte=0x30)
        cert1, _ = ca1.issue(**req1)
        old_tmp = self.tmp
        self.tmp = tmp2
        try:
            ca2 = self.make_ca()
            req2, _, _ = self.good_req(seed_byte=0x30)
            cert2, _ = ca2.issue(**req2)
        finally:
            self.tmp = old_tmp
        self.assertEqual(json.dumps(cert1, sort_keys=True),
                         json.dumps(cert2, sort_keys=True))

    def test_verify_rejects_tampered_chain(self):
        ca = self.make_ca()
        req, _, _ = self.good_req()
        cert, _ = ca.issue(**req)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        # tampered CA signature
        bad = dict(cert)
        sig = bytearray(base64.b64decode(bad["ca_signature"]))
        sig[0] ^= 0xFF
        bad["ca_signature"] = base64.b64encode(bytes(sig)).decode()
        self.assertRefuses(
            lambda: ec.verify_cert_chain(bad, ca_pub, NOW + 1),
            "evcert-chain-invalid")
        # extra field
        bad2 = dict(cert, extra_field=1)
        self.assertRefuses(
            lambda: ec.verify_cert_chain(bad2, ca_pub, NOW + 1),
            "evcert-malformed-cert")
        # wrong EKU
        bad3 = dict(cert, eku="code-signing")
        self.assertRefuses(
            lambda: ec.verify_cert_chain(bad3, ca_pub, NOW + 1),
            "evcert-malformed-cert")
        # expired / not-yet-valid
        self.assertRefuses(
            lambda: ec.verify_cert_chain(cert, ca_pub,
                                         cert["not_after"] + 1),
            "evcert-cert-expired")
        self.assertRefuses(
            lambda: ec.verify_cert_chain(cert, ca_pub,
                                         cert["not_before"] - 1),
            "evcert-cert-expired")

    def test_verify_evidence_binding_failures(self):
        ca = self.make_ca()
        req, seed, _ = self.good_req()
        cert, _ = ca.issue(**req)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        artifact = b"decision-packet-bytes"
        kw = dict(cert=cert, artifact_bytes=artifact,
                  approval_id="a" * 32, intent_digest="d" * 64,
                  ca_public_key=ca_pub, verify_time=NOW + 2)
        evil_seed, _ = _keypair(0xE2)
        self.assertRefuses(
            lambda: ec.verify_evidence_signature(
                artifact_signature=ed.sign(evil_seed, artifact), **kw),
            "evcert-binding-invalid")
        self.assertRefuses(
            lambda: ec.verify_evidence_signature(
                artifact_signature=ed.sign(seed, artifact),
                approval_id="f" * 32, intent_digest="d" * 64,
                cert=cert, artifact_bytes=artifact,
                ca_public_key=ca_pub, verify_time=NOW + 2),
            "evcert-binding-invalid")
        self.assertRefuses(
            lambda: ec.verify_evidence_signature(
                artifact_signature=ed.sign(seed, artifact),
                approval_id="a" * 32, intent_digest="e" * 64,
                cert=cert, artifact_bytes=artifact,
                ca_public_key=ca_pub, verify_time=NOW + 2),
            "evcert-binding-invalid")
        # expired cert fails at the chain step, not the binding step
        kw_expired = dict(kw, verify_time=cert["not_after"] + 1)
        self.assertRefuses(
            lambda: ec.verify_evidence_signature(
                artifact_signature=ed.sign(seed, artifact), **kw_expired),
            "evcert-cert-expired")


class ConstructorTests(CABase):
    def _kw(self, **over):
        fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        kw = dict(kms_provider=fake, ca_key_id="ca-key-1",
                  ca_public_key=fake.test_signing_public_key("ca-key-1"),
                  issuers=["https://issuer.example.com"],
                  approval_lookup=lambda _a: None,
                  audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
                  anchor_reachable=lambda: True, oid_arc=ARC,
                  now=lambda: NOW)
        kw.update(over)
        return kw

    def test_lifetime_over_24h_needs_status_list(self):
        with self.assertRaises(ValueError):
            ec.EvidenceCA(**self._kw(max_lifetime_s=90000))
        # with a status list it is allowed
        ec.EvidenceCA(**self._kw(max_lifetime_s=90000,
                                 status_list_url="https://x.example/sl"))

    def test_bad_configurations(self):
        with self.assertRaises(ValueError):
            ec.EvidenceCA(**self._kw(oid_arc="not-an-oid"))
        with self.assertRaises(ValueError):
            ec.EvidenceCA(**self._kw(ca_public_key=b"short"))
        with self.assertRaises(ValueError):
            ec.EvidenceCA(**self._kw(issuers=[]))
        with self.assertRaises(TypeError):
            ec.EvidenceCA(**self._kw(kms_provider=object()))
        with self.assertRaises(TypeError):
            ec.EvidenceCA(**self._kw(anchor_reachable=None))


class RegistryTests(CABase):
    def test_registry_survives_restart(self):
        ca1 = self.make_ca()
        req, _, _ = self.good_req(seed_byte=0x40)
        ca1.issue(**req)
        # brand-new CA object, same paths: reuse still refused
        ca2 = self.make_ca()
        req2, _, _ = self.good_req(seed_byte=0x40,
                                    approval_id="a" * 32)
        self.assertRefuses(lambda: ca2.issue(**req2),
                           "evcert-key-reused")

    def test_registry_prunes_after_expiry_plus_skew(self):
        ca1 = self.make_ca()
        req, _, _ = self.good_req(seed_byte=0x41, lifetime_s=60)
        cert, _ = ca1.issue(**req)
        # far past not_after + skew: the key is usable again
        ca2 = self.make_ca(
            now=lambda: cert["not_after"] + ec.REGISTRY_SKEW_S + 1)
        req2, _, _ = self.good_req(seed_byte=0x41,
                                    approval_id="a" * 32)
        cert2, _ = ca2.issue(**req2)
        self.assertEqual(cert2["subject_key_id"],
                         cert["subject_key_id"])

    def test_audit_failure_rolls_back_registry(self):
        ca = self.make_ca()
        req, seed, pub = self.good_req(seed_byte=0x42)
        key_id = hashlib.sha256(pub).hexdigest()[:16]
        with mock.patch("gov.log.open_audit_log",
                        side_effect=RuntimeError("disk on fire")):
            with self.assertRaises(RuntimeError):
                ca.issue(**req)
        with open(os.path.join(self.tmp, "evcert-seen-keys.json")) as f:
            reg = json.load(f)
        self.assertNotIn(key_id, reg)
        # the key was never burned: issuance now succeeds
        cert, _ = ca.issue(**req)
        self.assertEqual(cert["subject_key_id"], key_id)

    def test_corrupt_registry_fails_closed(self):
        with open(os.path.join(self.tmp, "evcert-seen-keys.json"),
                  "w") as f:
            f.write("{not json")
        ca = self.make_ca()
        req, _, _ = self.good_req()
        self.assertRefuses(lambda: ca.issue(**req),
                           "evcert-anchor-unavailable")

class KmsSignSeamTests(unittest.TestCase):
    def test_provider_can_sign(self):
        fake = kms_mod.FakeKmsProvider(["k1"])
        self.assertTrue(kms_mod.provider_can_sign(fake))

        class EnvelopeOnly(kms_mod.KmsProvider):
            provider_name = "envelope-only"

            def wrap_data_key(self, key_id, plaintext):
                return b"w"

            def unwrap_data_key(self, key_id, wrapped):
                return b"u"

            def describe_key(self, key_id):
                return kms_mod.KeyDescription(key_id, "envelope-only")

        self.assertFalse(kms_mod.provider_can_sign(EnvelopeOnly()))
        with self.assertRaises(TypeError):
            kms_mod.provider_can_sign(object())

    def test_abc_default_sign_fails_closed(self):
        class EnvelopeOnly(kms_mod.KmsProvider):
            provider_name = "envelope-only"

            def wrap_data_key(self, key_id, plaintext):
                return b"w"

            def unwrap_data_key(self, key_id, wrapped):
                return b"u"

            def describe_key(self, key_id):
                return kms_mod.KeyDescription(key_id, "envelope-only")

        with self.assertRaises(kms_mod.KmsError):
            EnvelopeOnly().sign("k1", b"\x00" * 32)

    def test_fake_sign_deterministic_and_verifiable(self):
        f1 = kms_mod.FakeKmsProvider(["ca-key-1"])
        f2 = kms_mod.FakeKmsProvider(["ca-key-1"])
        digest = hashlib.sha256(b"cert-body").digest()
        s1 = f1.sign("ca-key-1", digest)
        s2 = f2.sign("ca-key-1", digest)
        self.assertEqual(len(s1), 64)
        self.assertEqual(s1, s2)  # deterministic across instances
        pub = f1.test_signing_public_key("ca-key-1")
        self.assertEqual(len(pub), 32)
        self.assertIs(ed.verify(pub, digest, s1), True)
        self.assertIs(ed.verify(pub, b"\x00" * 32, s1), False)
        self.assertEqual(("sign", "ca-key-1"),
                         f1.calls[-1][:2])

    def test_fake_sign_refusals(self):
        f = kms_mod.FakeKmsProvider(["ca-key-1"])
        with self.assertRaises(kms_mod.KmsError):
            f.sign("ca-key-1", b"short")
        with self.assertRaises(kms_mod.KmsError):
            f.sign("no-such-key", b"\x00" * 32)
        f.outage = True
        with self.assertRaises(kms_mod.KmsError):
            f.sign("ca-key-1", b"\x00" * 32)
        f.outage = False
        f.disable_key("ca-key-1")
        with self.assertRaises(kms_mod.KmsError):
            f.sign("ca-key-1", b"\x00" * 32)


class VaultSignTests(unittest.TestCase):
    def _provider(self, canned):
        from gov import kms_vault as kv

        class StubTransport(kv.VaultTransport):
            def __init__(self):
                self.calls = []

            def request(self, method, path, headers, body):
                self.calls.append((method, path, json.loads(body)))
                status, doc = canned(path, json.loads(body))
                return status, json.dumps(doc).encode()

        t = StubTransport()
        return kv.VaultKmsProvider(t, token="test-token"), t

    def test_vault_sign_happy_path(self):
        seed = b"\x55" * 32
        pub = ed.publickey(seed)
        digest = hashlib.sha256(b"body").digest()
        sig = ed.sign(seed, digest)
        payload = "vault:v1:" + base64.b64encode(sig).decode()

        def canned(path, body):
            self.assertEqual(path, "/v1/transit/sign/ca-key")
            self.assertTrue(body["prehashed"])
            self.assertEqual(body["signature_algorithm"], "ed25519")
            return 200, {"data": {"signature": payload}}

        p, t = self._provider(canned)
        self.assertTrue(kms_mod.provider_can_sign(p))
        out = p.sign("ca-key", digest)
        self.assertEqual(out, sig)
        self.assertIs(ed.verify(pub, digest, out), True)

    def test_vault_sign_malformed_responses(self):
        digest = b"\x00" * 32
        cases = [
            {"data": {}},                                    # missing sig
            {"data": {"signature": "bogus:v1:AAAA"}},        # bad prefix
            {"data": {"signature": "vault:v1:!!!!"}},        # bad b64
            {"data": {"signature": "vault:v1:"
                                   + base64.b64encode(b"tiny").decode()}},
        ]
        for doc in cases:
            def canned(path, body, _doc=doc):
                return 200, _doc
            p, _ = self._provider(canned)
            with self.assertRaises(kms_mod.KmsError):
                p.sign("ca-key", digest)

    def test_vault_sign_http_error_and_bad_digest(self):
        def canned(path, body):
            return 400, {"errors": ["nope"]}
        p, _ = self._provider(canned)
        with self.assertRaises(kms_mod.KmsError):
            p.sign("ca-key", b"\x00" * 32)
        p2, _ = self._provider(lambda path, body: (200, {}))
        with self.assertRaises(kms_mod.KmsError):
            p2.sign("ca-key", b"short")


class DecisionCodeTests(unittest.TestCase):
    EXPECTED = {
        'evcert-anchor-unavailable': 'medium',
        'evcert-assertion-expired': 'medium',
        'evcert-binding-invalid': 'high',
        'evcert-cert-expired': 'medium',
        'evcert-chain-invalid': 'high',
        'evcert-identity-not-decider': 'high',
        'evcert-key-reused': 'high',
        'evcert-kms-cannot-sign': 'medium',
        'evcert-lifetime-exceeded': 'medium',
        'evcert-malformed-cert': 'medium',
        'evcert-malformed-request': 'medium',
        'evcert-pop-invalid': 'high',
        'evcert-provisioner-policy-violated': 'medium',
        'evcert-unknown-approval': 'medium',
        'evcert-unknown-issuer': 'medium',
    }

    def test_all_evcert_codes_present_and_shaped(self):
        for code, severity in self.EXPECTED.items():
            entry = TAXONOMY.get(code)
            self.assertIsNotNone(entry, "missing decision code %s" % code)
            self.assertEqual(entry["domain"], "evcert")
            self.assertEqual(entry["severity"], severity)
            for field in ("human", "evidence_kinds_required",
                          "reverify_steps"):
                self.assertTrue(entry[field], "%s.%s" % (code, field))

    def test_lane_pin_on_raw_literals(self):
        # Wave-260: duplicates are invisible to len(TAXONOMY); assert on
        # the raw source literals instead.
        import gov.decision_codes as dc
        with open(dc.__file__, encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(src.count("\"code\": '"), 1802)  # Wave-279 lane 2: pin 1493 -> 1494 (+1 evbundle-contract-refused); prior Wave-271 merge: pin 1372 -> 1411.; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 3: pin 1742 -> 1745 (+3 toolcall-predicate-*); Wave-295 merge: pin 1745 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        for code in self.EXPECTED:
            self.assertEqual(src.count("\"code\": '%s'" % code), 1,
                             "code literal %s must appear exactly once"
                             % code)


class VerifyContractTests(unittest.TestCase):
    def test_ed25519_verify_returns_exact_bool(self):
        # Wave-243: never assume verify() raises; pin the contract.
        seed, pub = _keypair(0x99)
        msg = b"contract"
        sig = ed.sign(seed, msg)
        self.assertIs(ed.verify(pub, msg, sig), True)
        self.assertIs(ed.verify(pub, b"other", sig), False)


if __name__ == "__main__":
    unittest.main()
