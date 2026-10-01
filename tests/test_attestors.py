"""Unit tests for gov/attestors.py and the EvidenceCA attestor seam
(wave-274 lane 3).

Seams: AttestedRegistry.register_entry / .match, StaticAttestor /
PlatformAttestor .collect(), EvidenceCA(attestor=...,
attested_registry=...) issuance. Spec vectors are independent
literals (fixed seeds / fixed keys), never recomputed through the
code under test.
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w274-attestor-ut")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import attestors as at  # noqa: E402
from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import kms as kms_mod  # noqa: E402

NOW = 1790860000
ARC = "1.3.6.1.4.1.99999"
POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


def _ceremony(entry, ceremony_seed):
    body = {k: v for k, v in entry.items() if k != "ceremony"}
    canonical = json.dumps(body, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return base64.b64encode(ed.sign(ceremony_seed, canonical)).decode(
        "ascii")


def _registry():
    cseed, cpub = _keypair(0xC0)
    kid = hashlib.sha256(cpub).hexdigest()[:16]
    return at.AttestedRegistry(ceremony_keys={kid: cpub}), cseed, kid


def _entry(**over):
    e = {"entry_id": "e1", "attestor_id": "static-test",
         "selector": {"machine_id": "m1"},
         "producer_sub": "alice", "scopes": ["evidence:write"]}
    e.update(over)
    return e


class RegistryTests(unittest.TestCase):
    def test_register_and_match(self):
        reg, cseed, kid = _registry()
        entry = _entry()
        got = reg.register_entry(
            entry, ceremony={"signer": kid,
                             "signature": _ceremony(entry, cseed)})
        self.assertEqual(got, "e1")
        matched = reg.match({"machine_id": "m1", "extra": "x"},
                            attestor_id="static-test")
        self.assertEqual(matched["entry_id"], "e1")

    def test_register_without_ceremony_refused(self):
        reg, _cseed, _kid = _registry()
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(_entry(), ceremony=None)
        self.assertEqual(ctx.exception.code, "attestor-ceremony-invalid")

    def test_register_unknown_signer_refused(self):
        reg, cseed, _kid = _registry()
        entry = _entry()
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(entry, ceremony={
                "signer": "nobody",
                "signature": _ceremony(entry, cseed)})
        self.assertEqual(ctx.exception.code, "attestor-ceremony-invalid")

    def test_register_forged_ceremony_refused(self):
        reg, _cseed, kid = _registry()
        entry = _entry()
        other_seed, _ = _keypair(0xD0)
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(entry, ceremony={
                "signer": kid,
                "signature": _ceremony(entry, other_seed)})
        self.assertEqual(ctx.exception.code, "attestor-ceremony-invalid")

    def test_register_tampered_entry_refused(self):
        reg, cseed, kid = _registry()
        entry = _entry()
        sig = _ceremony(entry, cseed)
        tampered = dict(entry, producer_sub="mallory")
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(tampered, ceremony={
                "signer": kid, "signature": sig})
        self.assertEqual(ctx.exception.code, "attestor-ceremony-invalid")

    def test_register_duplicate_refused(self):
        reg, cseed, kid = _registry()
        entry = _entry()
        reg.register_entry(entry, ceremony={
            "signer": kid, "signature": _ceremony(entry, cseed)})
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(entry, ceremony={
                "signer": kid, "signature": _ceremony(entry, cseed)})
        self.assertEqual(ctx.exception.code, "attestor-entry-malformed")

    def test_register_malformed_entry_refused(self):
        reg, cseed, kid = _registry()
        bad = _entry()
        del bad["selector"]
        with self.assertRaises(at.AttestorError) as ctx:
            reg.register_entry(bad, ceremony={
                "signer": kid,
                "signature": _ceremony(bad, cseed)})
        self.assertEqual(ctx.exception.code, "attestor-entry-malformed")

    def test_match_returns_defensive_copy(self):
        reg, cseed, kid = _registry()
        entry = _entry()
        reg.register_entry(
            entry, ceremony={"signer": kid,
                             "signature": _ceremony(entry, cseed)})
        matched = reg.match({"machine_id": "m1"},
                            attestor_id="static-test")
        matched["selector"]["machine_id"] = "corrupted"
        matched["scopes"].append("evil")
        again = reg.match({"machine_id": "m1"},
                          attestor_id="static-test")
        self.assertEqual(again["selector"], {"machine_id": "m1"})
        self.assertEqual(again["scopes"], ["evidence:write"])

    def test_match_no_entry(self):
        reg, _cseed, _kid = _registry()
        with self.assertRaises(at.AttestorError) as ctx:
            reg.match({"machine_id": "m1"}, attestor_id="static-test")
        self.assertEqual(ctx.exception.code, "attestor-entry-unmatched")

    def test_match_ambiguous(self):
        reg, cseed, kid = _registry()
        for eid in ("e1", "e2"):
            entry = _entry(entry_id=eid)
            reg.register_entry(entry, ceremony={
                "signer": kid, "signature": _ceremony(entry, cseed)})
        with self.assertRaises(at.AttestorError) as ctx:
            reg.match({"machine_id": "m1"}, attestor_id="static-test")
        self.assertEqual(ctx.exception.code, "attestor-entry-ambiguous")

    def test_match_wrong_attestor_id(self):
        reg, cseed, kid = _registry()
        entry = _entry()
        reg.register_entry(entry, ceremony={
            "signer": kid, "signature": _ceremony(entry, cseed)})
        with self.assertRaises(at.AttestorError) as ctx:
            reg.match({"machine_id": "m1"}, attestor_id="platform")
        self.assertEqual(ctx.exception.code, "attestor-entry-unmatched")

    def test_match_malformed_facts(self):
        reg, _cseed, _kid = _registry()
        with self.assertRaises(at.AttestorError) as ctx:
            reg.match("not-a-dict", attestor_id="static-test")
        self.assertEqual(ctx.exception.code, "attestor-facts-malformed")


class AttestorTests(unittest.TestCase):
    def test_static_attestor_roundtrip(self):
        a = at.StaticAttestor({"k": "v", "n": 3, "b": True})
        got = a.collect()
        self.assertEqual(got["attestor_id"], "static-test")
        self.assertEqual(got["facts"], {"k": "v", "n": 3, "b": True})

    def test_static_attestor_drops_non_scalars(self):
        a = at.StaticAttestor({"k": "v", "bad": {"nested": 1}})
        self.assertEqual(a.collect()["facts"], {"k": "v"})

    def test_platform_attestor_shape(self):
        got = at.PlatformAttestor().collect()
        self.assertEqual(got["attestor_id"], "platform")
        self.assertIsInstance(got["facts"], dict)
        self.assertTrue(got["facts"])
        for k, v in got["facts"].items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v, (str, int, bool))

    def test_platform_attestor_deterministic(self):
        a = at.PlatformAttestor()
        self.assertEqual(a.collect(), a.collect())


class CAAttestorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="attestor-ca-ut-")

    def _ca(self, **over):
        fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {"a" * 32: {"decider": "alice",
                               "state": "pending"}}
        kw = dict(kms_provider=fake, ca_key_id="ca-key-1",
                  ca_public_key=fake.test_signing_public_key("ca-key-1"),
                  issuers=["https://issuer.example.com"],
                  approval_lookup=approvals.get,
                  audit_log_path=os.path.join(self.tmp, "audit.jsonl"),
                  anchor_reachable=lambda: True,
                  oid_arc=ARC, now=lambda: NOW)
        kw.update(over)
        return ec.EvidenceCA(**kw)

    def _req(self, sub="alice"):
        seed, pub = _keypair(0x01)
        chal = (POP_DOMAIN + ("a" * 32).encode("utf-8")
                + hashlib.sha256(pub).digest())
        return {"identity_assertion":
                {"iss": "https://issuer.example.com", "sub": sub,
                 "exp": NOW + 3600},
                "ephemeral_pub": pub,
                "pop_sig": ed.sign(seed, chal),
                "approval_id": "a" * 32,
                "intent_digest": "d" * 64}

    def _wired(self, entry, facts):
        reg, cseed, kid = _registry()
        reg.register_entry(entry, ceremony={
            "signer": kid, "signature": _ceremony(entry, cseed)})
        return self._ca(attestor=at.StaticAttestor(facts),
                        attested_registry=reg)

    def test_happy_path_embeds_claims(self):
        entry = _entry()
        ca = self._wired(entry, {"machine_id": "m1"})
        cert, stored = ca.issue(**self._req())
        self.assertEqual(stored["attested_entry_id"], "e1")
        self.assertEqual(stored["attested_facts"], {"machine_id": "m1"})
        self.assertEqual(cert["extensions"][ARC + ".1.41"], "e1")

    def test_spoofed_facts_refused(self):
        entry = _entry()
        ca = self._wired(entry, {"machine_id": "attacker"})
        with self.assertRaises(ec.EvidenceCertError) as ctx:
            ca.issue(**self._req())
        self.assertEqual(ctx.exception.code, "attestor-entry-unmatched")

    def test_producer_mismatch_refused(self):
        entry = _entry(producer_sub="mallory")
        ca = self._wired(entry, {"machine_id": "m1"})
        with self.assertRaises(ec.EvidenceCertError) as ctx:
            ca.issue(**self._req(sub="alice"))
        self.assertEqual(ctx.exception.code, "attestor-entry-unmatched")

    def test_legacy_path_byte_identical(self):
        ca = self._ca()
        cert, _stored = ca.issue(**self._req())
        self.assertNotIn(ARC + ".1.41", cert["extensions"])

    def test_half_configured_refused_at_construction(self):
        with self.assertRaises(ValueError):
            self._ca(attestor=at.StaticAttestor({"k": "v"}))
        reg, _cseed, _kid = _registry()
        with self.assertRaises(ValueError):
            self._ca(attested_registry=reg)

    def test_expected_codes_complete(self):
        self.assertEqual(set(at.EXPECTED_CODES),
                         {"attestor-entry-malformed",
                          "attestor-facts-malformed",
                          "attestor-ceremony-invalid",
                          "attestor-entry-unmatched",
                          "attestor-entry-ambiguous"})


if __name__ == "__main__":
    unittest.main()
