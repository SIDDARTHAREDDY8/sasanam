#!/usr/bin/env python3
"""Unit tests for gov/workload_identity.py (wave-319 lane 2).

Tests the public seams only: mint_document / DocumentVerifier.verify /
the policy and federation value objects. Adversarial documents are data,
never exceptions.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import ed25519 as _ed  # noqa: E402
from gov import workload_identity as wi  # noqa: E402

_NOW = 1785000000
_DOMAIN = "prod.sasanam.example"
_BINARY_HASH = "ab" * 32
_CHAIN = "cd" * 32


def _selectors(**over):
    s = {"binary_hash": _BINARY_HASH, "invocation_chain": _CHAIN,
         "deployment_mode": "production"}
    s.update(over)
    return s


def _issuer(seed_byte=3):
    seed = bytes([seed_byte]) * 32
    return seed, _ed.publickey(seed)


def _policy(domain=_DOMAIN):
    return wi.AttestationPolicy(recognized=[(_BINARY_HASH, "production")],
                                trust_domain=domain)


class MintTests(unittest.TestCase):
    def test_roundtrip_shape(self):
        seed, _pub = _issuer()
        doc = wi.mint_document(seed, "/agent/a", _selectors(),
                               "tool:x", 600, _NOW, _policy())
        self.assertEqual(doc["spiffe_id"],
                         "spiffe://%s/agent/a" % _DOMAIN)
        self.assertEqual(doc["schema"], wi.SCHEMA)
        self.assertEqual(doc["not_before"], _NOW)
        self.assertEqual(doc["not_after"], _NOW + 600)
        self.assertIn("signature", doc)

    def test_unrecognized_selectors_refuse(self):
        seed, _pub = _issuer()
        with self.assertRaises(wi.MintRefusal) as ctx:
            wi.mint_document(seed, "/agent/a",
                             _selectors(binary_hash="ff" * 32),
                             "tool:x", 600, _NOW, _policy())
        self.assertEqual(ctx.exception.code, "identity-mint-refused")

    def test_empty_audience_refuses(self):
        seed, _pub = _issuer()
        with self.assertRaises(wi.MintRefusal):
            wi.mint_document(seed, "/agent/a", _selectors(), "", 600,
                             _NOW, _policy())

    def test_excessive_ttl_refuses(self):
        seed, _pub = _issuer()
        with self.assertRaises(wi.MintRefusal):
            wi.mint_document(seed, "/agent/a", _selectors(), "tool:x",
                             wi.MAX_TTL_SECONDS + 1, _NOW, _policy())

    def test_max_ttl_accepted(self):
        seed, _pub = _issuer()
        doc = wi.mint_document(seed, "/agent/a", _selectors(), "tool:x",
                               wi.MAX_TTL_SECONDS, _NOW, _policy())
        self.assertEqual(doc["not_after"] - doc["not_before"],
                         wi.MAX_TTL_SECONDS)

    def test_bad_agent_path_refuses(self):
        seed, _pub = _issuer()
        for bad in ("", "no-slash", "/has space", "/\ttab"):
            with self.assertRaises(wi.MintRefusal, msg=bad):
                wi.mint_document(seed, bad, _selectors(), "tool:x", 600,
                                 _NOW, _policy())

    def test_closed_deployment_modes(self):
        seed, _pub = _issuer()
        for mode in ("prod", "PRODUCTION", "", None):
            with self.assertRaises(wi.MintRefusal, msg=str(mode)):
                wi.mint_document(seed, "/agent/a",
                                 _selectors(deployment_mode=mode),
                                 "tool:x", 600, _NOW, _policy())

    def test_signature_covers_selectors(self):
        # Mutating any signed field invalidates the signature.
        seed, pub = _issuer()
        doc = wi.mint_document(seed, "/agent/a", _selectors(), "tool:x",
                               600, _NOW, _policy())
        body = {k: v for k, v in doc.items() if k != "signature"}
        sig = wi._b64d(doc["signature"])
        self.assertTrue(_ed.verify(pub, wi._canonical_bytes(body), sig))
        body["selectors"] = dict(body["selectors"], binary_hash="00" * 32)
        self.assertFalse(_ed.verify(pub, wi._canonical_bytes(body), sig))


class VerifyTests(unittest.TestCase):
    def _verifier(self, pub=None, **kw):
        _seed, default_pub = _issuer()
        kw.setdefault("issuer_pubkeys", {_DOMAIN: pub or default_pub})
        kw.setdefault("trust_domain", _DOMAIN)
        kw.setdefault("now", _NOW)
        return wi.DocumentVerifier(**kw)

    def _doc(self, seed_byte=3, **kw):
        seed, _pub = _issuer(seed_byte)
        args = dict(issuer_seed=seed, agent_path="/agent/a",
                    selectors=_selectors(), audience="tool:x",
                    ttl_seconds=600, now=_NOW, policy=_policy())
        args.update(kw)
        return wi.mint_document(**args)

    def test_verify_ok(self):
        v = self._verifier().verify(self._doc(), "tool:x", _selectors())
        self.assertTrue(v.verified)
        self.assertEqual(v.code, "identity-attested")
        self.assertEqual(v.expires_at, _NOW + 600)

    def test_expiry_boundary(self):
        # not_after == now is expired (validity is [not_before, not_after)).
        doc = self._doc()
        v = self._verifier(now=_NOW + 600).verify(doc, "tool:x",
                                                  _selectors())
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-expired")
        v2 = self._verifier(now=_NOW + 599).verify(doc, "tool:x",
                                                   _selectors())
        self.assertTrue(v2.verified)

    def test_not_yet_valid(self):
        doc = self._doc(now=_NOW + 100)
        v = self._verifier().verify(doc, "tool:x", _selectors())
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-not-yet-valid")

    def test_audience_exact_match(self):
        doc = self._doc(audience="tool:x")
        v = self._verifier().verify(doc, "tool:X", _selectors())
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-audience-mismatch")

    def test_empty_audience_argument_raises(self):
        # Caller API misuse (not hostile data) fails fast.
        with self.assertRaises(ValueError):
            self._verifier().verify(self._doc(), "", _selectors())

    def test_selector_mismatch(self):
        doc = self._doc()
        other = _selectors(invocation_chain="ee" * 32)
        v = self._verifier().verify(doc, "tool:x", other)
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-selector-mismatch")

    def test_malformed_presented_selectors(self):
        doc = self._doc()
        v = self._verifier().verify(doc, "tool:x", {"nope": 1})
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-selector-mismatch")

    def test_foreign_domain_needs_federation(self):
        seed, _pub = _issuer(7)
        doc = wi.mint_document(seed, "/agent/a", _selectors(), "tool:x",
                               600, _NOW, _policy("partner.example"))
        v = self._verifier().verify(doc, "tool:x", _selectors())
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-untrusted-domain")

    def test_federation_accepts_and_bounds_ttl(self):
        seed, pub = _issuer(7)
        policy = _policy("partner.example")
        fed = wi.FederationPolicy(records={
            "partner.example": wi.FederationRecord(issuer_pubkey=pub,
                                                   max_ttl_seconds=300)})
        doc_ok = wi.mint_document(seed, "/agent/a", _selectors(),
                                  "tool:x", 300, _NOW, policy)
        v = self._verifier(federation=fed).verify(doc_ok, "tool:x",
                                                  _selectors())
        self.assertTrue(v.verified, v.detail)
        doc_long = wi.mint_document(seed, "/agent/a", _selectors(),
                                    "tool:x", 600, _NOW, policy)
        v2 = self._verifier(federation=fed).verify(doc_long, "tool:x",
                                                   _selectors())
        self.assertFalse(v2.verified)
        self.assertEqual(v2.code, "identity-untrusted-domain")

    def test_federation_wrong_key_refuses(self):
        _seed, _pub = _issuer(7)
        _other_seed, other_pub = _issuer(8)
        policy = _policy("partner.example")
        fed = wi.FederationPolicy(records={
            "partner.example": wi.FederationRecord(
                issuer_pubkey=other_pub, max_ttl_seconds=3600)})
        doc = wi.mint_document(bytes([7]) * 32, "/agent/a", _selectors(),
                               "tool:x", 600, _NOW, policy)
        v = self._verifier(federation=fed).verify(doc, "tool:x",
                                                  _selectors())
        self.assertFalse(v.verified)
        self.assertEqual(v.code, "identity-forged")

    def test_verdict_to_dict(self):
        v = self._verifier().verify(self._doc(), "tool:x", _selectors())
        d = v.to_dict()
        self.assertEqual(d["code"], "identity-attested")
        self.assertTrue(d["verified"])


class MalformedTests(unittest.TestCase):
    def test_hostile_inputs_never_raise(self):
        _seed, pub = _issuer()
        verifier = wi.DocumentVerifier(issuer_pubkeys={_DOMAIN: pub},
                                       trust_domain=_DOMAIN, now=_NOW)
        hostile = [None, 0, "x", [], {}, {"schema": wi.SCHEMA},
                   {"schema": wi.SCHEMA,
                    "spiffe_id": "spiffe://%s/agent/a" % _DOMAIN,
                    "trust_domain": "other.example"}]
        for h in hostile:
            v = verifier.verify(h, "tool:x", _selectors())
            self.assertFalse(v.verified, "accepted %r" % (h,))
            self.assertEqual(v.code, "identity-forged")


if __name__ == "__main__":
    unittest.main()
