#!/usr/bin/env python3
"""Unit tests for the OIDC four-claim gate ceremony
(gov/evidence_certs.py OidcGate + EvidenceCA wiring, wave-272).

Conventions: staging default; spec vectors are independent literals
(fixed seeds), never recomputed through the code under test; the
lane-local taxonomy pin is asserted on raw source literals, never
``len(dict)`` (wave-260); ``tests/test_decision_codes.py`` keeps the
pre-lane global pin for the merge coordinator.
"""

import base64
import hashlib
import json
import os
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w272-oidc-ut")

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

NOW = 1790860000
ARC = "1.3.6.1.4.1.99999"
ISSUER = "https://oidc.test.example"
AUDIENCE = "sasanam-evcert-ceremony"
FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                       "evals", "fixtures", "oidc_test_jwks.json")

FIXTURE_SEED = bytes([0xA0]) * 32
FIXTURE_PUB = ed.publickey(FIXTURE_SEED)

# Wave-272 merge pin: 1411 (wave-271 merge) + 32 new codes = 1443.
LANE_PIN = 1945 # Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-290 merge: pin 1706 -> 1710 (+4 provenance-rebuild-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*) ; Wave-295 lane 4: pin 1742 -> 1746 (+4 coord-state-*); Wave-295 merge: pin 1746 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def load_jwks():
    with open(FIXTURE, "r", encoding="utf-8") as f:
        return json.load(f)


def mint(seed, claims, kid="test-key-1", alg="EdDSA", raw_payload=None,
         raw_header=None):
    header = {"alg": alg, "typ": "JWT"} if raw_header is None else raw_header
    if kid is not None and raw_header is None:
        header["kid"] = kid
    hb = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    pb = _b64u(raw_payload if raw_payload is not None
               else json.dumps(claims, separators=(",", ":")).encode())
    sig = b"" if alg == "none" else ed.sign(seed,
                                            (hb + "." + pb).encode("ascii"))
    return hb + "." + pb + "." + _b64u(sig)


def good_claims(**over):
    c = {"iss": ISSUER, "aud": AUDIENCE, "sub": "alice",
         "exp": NOW + 600}
    c.update(over)
    return c


class GateConstructionTests(unittest.TestCase):
    def test_ok(self):
        g = ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                        jwks=load_jwks(), now=lambda: NOW)
        self.assertEqual(g._keys.keys(), {"test-key-1"})

    def test_default_skew(self):
        g = ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                        jwks=load_jwks())
        self.assertEqual(g._skew, ec.OIDC_DEFAULT_CLOCK_SKEW_S)

    def test_bad_configs(self):
        jwks = load_jwks()
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer="", audience=AUDIENCE, jwks=jwks)
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer=ISSUER, audience="", jwks=jwks)
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                        jwks={"keys": []})
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                        jwks={"keys": [{"kty": "RSA"}]})
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                        jwks={"keys": [{"kty": "OKP", "crv": "Ed25519",
                                        "kid": "k",
                                        "x": "!!!not-b64!!!"}]})
        with self.assertRaises(ValueError):
            ec.OidcGate(issuer=ISSUER, audience=AUDIENCE, jwks=jwks,
                        clock_skew_s=-1)

    def test_fixture_key_matches_seed(self):
        # The fixture's x is the fixed seed's public key (independent
        # literal check: recompute from the seed, not from the module).
        x = load_jwks()["keys"][0]["x"]
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
        self.assertEqual(raw, FIXTURE_PUB)


class GateVerifyTests(unittest.TestCase):
    def setUp(self):
        self.g = ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                             jwks=load_jwks(), now=lambda: NOW)

    def refuses(self, token):
        try:
            self.g.verify_token(token)
        except ec.EvidenceCertError as e:
            return e.code
        self.fail("token accepted: %r" % (token,))

    def test_happy_path_claims(self):
        claims = self.g.verify_token(mint(FIXTURE_SEED, good_claims()))
        self.assertEqual(claims, {"iss": ISSUER, "sub": "alice",
                                  "exp": NOW + 600})

    def test_verify_signature_exact_bool(self):
        # Wave-243: the seam returns exact True/False, never truthy.
        si = b"header.payload"
        sig = ed.sign(FIXTURE_SEED, si)
        self.assertIs(self.g._verify_signature(si, sig, FIXTURE_PUB),
                      True)
        self.assertIs(self.g._verify_signature(si, b"\x00" * 64,
                                              FIXTURE_PUB), False)

    def test_wrong_issuer(self):
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED,
                              good_claims(iss="https://evil.example"))),
            "oidc-issuer-mismatch")

    def test_issuer_prefix_confusion(self):
        # Exact match: a superstring issuer must not pass.
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED,
                              good_claims(iss=ISSUER + ".evil.com"))),
            "oidc-issuer-mismatch")

    def test_wrong_audience(self):
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED, good_claims(aud="other"))),
            "oidc-audience-mismatch")

    def test_aud_list_without_expected(self):
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED,
                              good_claims(aud=["a", "b"]))),
            "oidc-audience-mismatch")

    def test_expired(self):
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED,
                              good_claims(exp=NOW - 301))),
            "oidc-token-expired")

    def test_within_skew_valid(self):
        claims = self.g.verify_token(mint(FIXTURE_SEED,
                                          good_claims(exp=NOW - 300)))
        self.assertEqual(claims["sub"], "alice")

    def test_missing_claims(self):
        for missing in ("iss", "aud", "sub", "exp"):
            c = good_claims()
            del c[missing]
            self.assertEqual(self.refuses(mint(FIXTURE_SEED, c)),
                             "oidc-missing-claim", missing)

    def test_ambiguous_sub(self):
        raw = ('{"iss":"%s","aud":"%s","sub":"a","sub":"b","exp":%d}'
               % (ISSUER, AUDIENCE, NOW + 600)).encode()
        self.assertEqual(self.refuses(mint(FIXTURE_SEED, None,
                                           raw_payload=raw)),
                         "oidc-ambiguous-subject")

    def test_forged_signature(self):
        atk = bytes([0xB0]) * 32
        self.assertEqual(
            self.refuses(mint(atk, good_claims(), kid="test-key-1")),
            "oidc-signature-invalid")

    def test_tampered_payload(self):
        tok = mint(FIXTURE_SEED, good_claims())
        hb, pb, sb = tok.split(".")
        evil_pb = _b64u(json.dumps(good_claims(sub="mallory"),
                                   separators=(",", ":")).encode())
        self.assertEqual(self.refuses(hb + "." + evil_pb + "." + sb),
                         "oidc-signature-invalid")

    def test_malformed_shapes(self):
        for bad in ("", "a.b", "a.b.c.d", "..", "a..c",
                    "not-json-payload.x.y"):
            self.assertEqual(self.refuses(bad), "oidc-malformed-token",
                             bad)

    def test_non_string_token(self):
        for bad in (None, b"a.b.c", 123):
            self.assertEqual(self.refuses(bad), "oidc-malformed-token")

    def test_header_not_object(self):
        hb = _b64u(b"[1,2]")
        tok = hb + "." + _b64u(b"{}") + "." + _b64u(b"\x00" * 64)
        self.assertEqual(self.refuses(tok), "oidc-malformed-token")

    def test_exp_bool_is_malformed(self):
        self.assertEqual(
            self.refuses(mint(FIXTURE_SEED, good_claims(exp=True))),
            "oidc-malformed-token")

    def test_non_object_payloads_malformed(self):
        # Signed hostile payloads must refuse as malformed, never leak
        # a raw TypeError (spec review: _loads_no_dup contract).
        for raw in (b"[1,2,3]", b'["ab"]', b"42", b'"str"',
                    b"[1,2]", b"null"):
            tok = mint(FIXTURE_SEED, None, raw_payload=raw)
            try:
                self.g.verify_token(tok)
            except ec.EvidenceCertError as e:
                self.assertEqual(e.code, "oidc-malformed-token", raw)
                continue
            except Exception as e:  # noqa: BLE001
                self.fail("non-ceremony exception leaked: %r" % (e,))
            self.fail("non-object payload accepted: %r" % (raw,))

    def test_duplicate_non_required_claim_malformed(self):
        raw = ('{"iss":"%s","aud":"%s","sub":"alice","exp":%d,'
               '"nbf":1,"nbf":2}' % (ISSUER, AUDIENCE, NOW + 600)).encode()
        self.assertEqual(self.refuses(mint(FIXTURE_SEED, None,
                                           raw_payload=raw)),
                         "oidc-malformed-token")


class CAWiringTests(unittest.TestCase):
    def setUp(self):
        os.makedirs("/var/tmp", exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="oidc-ca-ut-", dir="/var/tmp")

    def make_ca(self, gate=None):
        fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {"a" * 32: {"decider": "alice", "state": "pending"}}
        return ec.EvidenceCA(
            kms_provider=fake, ca_key_id="ca-key-1",
            ca_public_key=fake.test_signing_public_key("ca-key-1"),
            issuers=[ISSUER], approval_lookup=approvals.get,
            audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
            anchor_reachable=lambda: True, oid_arc=ARC,
            now=lambda: NOW, oidc_gate=gate)

    def pop_req(self, seed_byte=0x01):
        seed = bytes([seed_byte & 0xFF]) * 32
        pub = ed.publickey(seed)
        chal = (b"evcert-pop-v1" + b"a" * 32 + hashlib.sha256(pub).digest())
        return {"ephemeral_pub": pub, "pop_sig": ed.sign(seed, chal),
                "approval_id": "a" * 32, "intent_digest": "d" * 64}

    def test_gate_type_checked(self):
        with self.assertRaises(TypeError):
            self.make_ca(gate="not-a-gate")

    def test_token_required(self):
        ca = self.make_ca(gate=ec.OidcGate(
            issuer=ISSUER, audience=AUDIENCE, jwks=load_jwks(),
            now=lambda: NOW))
        req = self.pop_req()
        req["identity_assertion"] = {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600}
        try:
            ca.issue(**req)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "oidc-token-required")
            return
        self.fail("issued without a token")

    def test_e2e_issues_and_records_producer_identity(self):
        gate = ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                           jwks=load_jwks(), now=lambda: NOW)
        ca = self.make_ca(gate=gate)
        tok = mint(FIXTURE_SEED, good_claims())
        cert, stored = ca.issue(oidc_token=tok, **self.pop_req())
        # Cert wire shape unchanged.
        self.assertEqual(set(cert.keys()),
                         {"format", "subject_public_key", "subject_key_id",
                          "issuer_key_id", "not_before", "not_after", "eku",
                          "extensions", "honest_limits", "ca_signature"})
        self.assertEqual(cert["extensions"]["principal"], "alice")
        # Producer identity is the verified (iss, sub) pair.
        self.assertIs(stored["oidc_verified"], True)
        self.assertEqual(stored["producer_identity"],
                         {"iss": ISSUER, "sub": "alice"})
        # The minted cert still verifies through the normal chain.
        chain = ec.verify_cert_chain(
            cert, ca._ca_public_key, NOW, oid_arc=ARC)
        self.assertEqual(chain["extensions"]["principal"], "alice")

    def test_e2e_forged_token_refused(self):
        gate = ec.OidcGate(issuer=ISSUER, audience=AUDIENCE,
                           jwks=load_jwks(), now=lambda: NOW)
        ca = self.make_ca(gate=gate)
        atk = bytes([0xB0]) * 32
        bad = mint(atk, good_claims(), kid="test-key-1")
        try:
            ca.issue(oidc_token=bad, **self.pop_req())
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "oidc-signature-invalid")
            return
        self.fail("forged token issued")

    def test_legacy_path_unchanged(self):
        ca = self.make_ca()
        req = self.pop_req()
        req["identity_assertion"] = {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600}
        cert, stored = ca.issue(**req)
        self.assertEqual(set(cert.keys()),
                         {"format", "subject_public_key", "subject_key_id",
                          "issuer_key_id", "not_before", "not_after", "eku",
                          "extensions", "honest_limits", "ca_signature"})
        self.assertIs(stored["oidc_verified"], False)
        self.assertNotIn("producer_identity", stored)

    def test_unexpected_token_on_legacy_ca(self):
        ca = self.make_ca()
        req = self.pop_req()
        req["identity_assertion"] = {"iss": ISSUER, "sub": "alice",
                                     "exp": NOW + 3600}
        try:
            ca.issue(oidc_token=mint(FIXTURE_SEED, good_claims()), **req)
        except ec.EvidenceCertError as e:
            self.assertEqual(e.code, "evcert-malformed-request")
            return
        self.fail("token honored by a non-OIDC CA")


class PinTests(unittest.TestCase):
    def test_lane_pin_on_raw_literals(self):
        import re
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "gov", "decision_codes.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        codes = re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(codes), LANE_PIN)  # Wave-272 OIDC lane
        self.assertEqual(len(set(codes)), len(codes))
        oidc = sorted(c for c in codes if c.startswith("oidc-"))
        self.assertEqual(len(oidc), 8)
        self.assertEqual(oidc, sorted(oidc))
        for code in oidc:
            self.assertEqual(TAXONOMY[code]["domain"], "oidc")


if __name__ == "__main__":
    unittest.main()
