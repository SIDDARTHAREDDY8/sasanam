#!/usr/bin/env python3
"""Focused unit tests for the wave-209 admit_deploy seam wiring.

Public-seam tests: the ``namespace_registry`` kwarg on
``SkillLoader`` / ``load_skill_content``, the refusal wrapping
(NamespaceError -> ArtifactRefused ``namespace_admission_refused``),
legacy-callers-unchanged, constructor validation, and provenance
logging. Deterministic (fixed seeds, fixed clock); stdlib-only plus
gov modules.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import load_gate as lg  # noqa: E402
from gov import sign_deploy_namespaces as sdn  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402

_SEED_SIGN = bytes.fromhex("61" * 32)
_SEED_PIN = bytes.fromhex("62" * 32)
_SEED_AUTH = bytes.fromhex("63" * 32)
_TS = "2026-09-23T00:00:00+00:00"


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class WiringHarness(unittest.TestCase):
    def setUp(self):
        pin_signer = Ed25519Signer(_SEED_PIN)
        auth = Ed25519Signer(_SEED_AUTH)
        trust = DelegationTrust(
            human_keys={pin_signer.key_id: pin_signer.public_key},
            authority_keys={auth.key_id: auth.public_key},
            user_issuer_keys={pin_signer.key_id: pin_signer.public_key},
        )
        self.pin_signer = pin_signer
        self.pinset = lg.ArtifactPinset(trust)
        self.signers = [Ed25519Signer(_SEED_SIGN)]
        self.registry = sdn.NamespaceRegistry(
            verifiers=[Ed25519Verifier(s.public_key)
                       for s in self.signers],
            threshold=1)
        self.store = {}
        self.log = []

    def pin(self, name, content):
        digest = _digest(content)
        na = lg._resolve_pin_not_after(_TS, None)
        body = lg._canonical_pin_body("dev", "skill:" + name, digest,
                                      _TS, version=1, not_after=na)
        self.pinset.pin("skill:" + name, digest, self.pin_signer.key_id,
                        self.pin_signer.sign(body).hex(), ts=_TS,
                        tier="dev", version=1, not_after=na)
        return digest

    def ceremony(self, name, content, operators=("op-a", "op-b")):
        self.registry.stage(name, content)
        self.registry.sign(name, self.signers)
        self.registry.promote(name, operator_ids=list(operators))
        self.store[name] = content
        return self.pin(name, content)

    def wired(self):
        return lg.SkillLoader(self.pinset, self.store, log=self.log,
                              namespace_registry=self.registry)


class TestWiring(WiringHarness):
    def test_unsigned_refused(self):
        content = b"unsigned"
        self.pin("u", content)
        self.store["u"] = content
        self.registry.stage("u", content)
        with self.assertRaises(lg.ArtifactRefused) as cm:
            self.wired().load_skill("u")
        self.assertIn("namespace_admission_refused", str(cm.exception))
        reasons = [e.get("reason") for e in self.log
                   if e.get("event") == "artifact_load_refused"]
        self.assertIn("namespace_admission_refused", reasons)

    def test_signed_unpromoted_refused(self):
        content = b"halfway"
        self.pin("h", content)
        self.store["h"] = content
        self.registry.stage("h", content)
        self.registry.sign("h", self.signers)
        with self.assertRaises(lg.ArtifactRefused) as cm:
            self.wired().load_skill("h")
        self.assertIn("namespace_admission_refused", str(cm.exception))

    def test_full_ceremony_loads_and_logs_provenance(self):
        content = b"full"
        digest = self.ceremony("f", content)
        verified = self.wired().load_skill("f")
        self.assertEqual(verified.data, content)
        self.assertEqual(verified.digest, digest)
        admitted = [e for e in self.log
                    if e.get("event") == "namespace_admitted"]
        self.assertEqual(len(admitted), 1)
        self.assertEqual(admitted[0]["digest"], digest)
        self.assertTrue(admitted[0]["signed_by"])
        self.assertEqual(admitted[0]["promoted_by"], ["op-a", "op-b"])

    def test_refusal_code_is_specific(self):
        content = b"unsigned2"
        self.pin("u2", content)
        self.store["u2"] = content
        self.registry.stage("u2", content)
        try:
            self.wired().load_skill("u2")
        except lg.ArtifactRefused as exc:
            # The underlying namespace code is named, not swallowed.
            self.assertIn("unknown-bundle", str(exc))
        else:
            self.fail("expected ArtifactRefused")

    def test_legacy_unwired_loader_unchanged(self):
        content = b"legacy"
        self.pin("leg", content)
        self.store["leg"] = content
        self.registry.stage("leg", content)  # unsigned, never admitted
        verified = lg.SkillLoader(self.pinset, self.store,
                                  log=self.log).load_skill("leg")
        self.assertEqual(verified.data, content)
        self.assertFalse([e for e in self.log
                          if e.get("event") == "namespace_admitted"])

    def test_load_skill_content_passthrough(self):
        content = b"passthrough"
        digest = self.ceremony("p", content)
        marker = lg.load_skill_content(self.pinset, self.store, "p",
                                       log=self.log,
                                       namespace_registry=self.registry)
        from gov.sterile import Unvetted
        self.assertIsInstance(marker, Unvetted)
        self.assertEqual(marker.acknowledge("test-consumer"), content)
        sink = []
        marker2 = lg.load_skill_content(self.pinset, self.store, "p",
                                        namespace_registry=self.registry)
        marker2.acknowledge("test-consumer", sink=sink)
        self.assertEqual(sink[0]["ack_context"]["digest"], digest)

    def test_load_skill_content_refuses_unsigned(self):
        content = b"unsigned3"
        self.pin("u3", content)
        self.store["u3"] = content
        self.registry.stage("u3", content)
        with self.assertRaises(lg.ArtifactRefused):
            lg.load_skill_content(self.pinset, self.store, "u3",
                                  namespace_registry=self.registry)

    def test_constructor_rejects_non_registry(self):
        with self.assertRaises(TypeError):
            lg.SkillLoader(self.pinset, self.store,
                           namespace_registry=object())
        with self.assertRaises(TypeError):
            lg.SkillLoader(self.pinset, self.store,
                           namespace_registry="not-a-registry")

    def test_constructor_accepts_none(self):
        loader = lg.SkillLoader(self.pinset, self.store,
                                namespace_registry=None)
        self.assertIsNotNone(loader)

    def test_wired_loader_exposes_registry(self):
        loader = self.wired()
        self.assertIs(loader._namespace_registry, self.registry)

    def test_goharbor_regression_enforcement_never_bricks_signing(self):
        # Enforcement "on" (wired loader exists) BEFORE the fresh
        # bundle goes through stage -> sign -> promote.
        loader = self.wired()
        fresh = b"fresh-under-enforcement"
        self.registry.stage("g", fresh)
        self.registry.sign("g", self.signers)
        self.registry.promote("g", operator_ids=["op-a", "op-b"])
        self.pin("g", fresh)
        self.store["g"] = fresh
        verified = loader.load_skill("g")
        self.assertEqual(verified.data, fresh)


if __name__ == "__main__":
    unittest.main()
