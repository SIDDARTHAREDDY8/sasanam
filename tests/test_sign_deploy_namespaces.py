#!/usr/bin/env python3
"""Unit tests for gov.sign_deploy_namespaces (wave-207 Lane C).

Pin the namespace model: staging (signing workspace, unsigned allowed
but loudly labeled) vs enforced (deploy source, signed + digest-pinned
only), the two-operator promotion ceremony, digest-pinned admission,
fresh re-verification at every admission, and the hash-chained audit.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import sign_deploy_namespaces as sdn  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_SEED1 = bytes.fromhex("51" * 32)
_SEED2 = bytes.fromhex("52" * 32)
_SEED3 = bytes.fromhex("53" * 32)


def _reg(threshold=1):
    signers = [Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    return sdn.NamespaceRegistry(verifiers=verifiers, threshold=threshold), \
        signers, verifiers


class TestRegistryConstruction(unittest.TestCase):
    def test_requires_verifiers(self):
        with self.assertRaises(sdn.NamespaceError) as ctx:
            sdn.NamespaceRegistry(verifiers=[])
        self.assertEqual(ctx.exception.code, "bad-format")

    def test_threshold_bounds(self):
        _, signers, verifiers = _reg()
        for bad in (0, 3, True, "2"):
            with self.assertRaises(sdn.NamespaceError):
                sdn.NamespaceRegistry(verifiers=verifiers, threshold=bad)

    def test_verifier_shape(self):
        with self.assertRaises(sdn.NamespaceError):
            sdn.NamespaceRegistry(verifiers=[object()])


class TestStaging(unittest.TestCase):
    def test_stage_unsigned_loudly_labeled(self):
        reg, _, _ = _reg()
        rec = reg.stage("skill/x", b"bytes")
        self.assertEqual(rec["status"], "unsigned")
        self.assertIn("UNSIGNED", rec["label"])
        self.assertIn("enforced", rec["label"].lower())
        self.assertIsNone(rec["envelope"])

    def test_stage_bad_inputs(self):
        reg, _, _ = _reg()
        for bad_name in ("", None, True, 42):
            with self.assertRaises(sdn.NamespaceError):
                reg.stage(bad_name, b"bytes")
        with self.assertRaises(sdn.NamespaceError):
            reg.stage("skill/x", "not-bytes")

    def test_staging_label_unknown(self):
        reg, _, _ = _reg()
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.staging_label("skill/nope")
        self.assertEqual(ctx.exception.code, "unknown-bundle")


class TestPromotion(unittest.TestCase):
    def test_unsigned_cannot_promote(self):
        reg, _, _ = _reg()
        reg.stage("skill/x", b"bytes")
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote("skill/x", operator_ids=["a", "b"])
        self.assertEqual(ctx.exception.code, "unsigned-refused")

    def test_unknown_cannot_promote(self):
        reg, _, _ = _reg()
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote("skill/nope", operator_ids=["a", "b"])
        self.assertEqual(ctx.exception.code, "unknown-bundle")

    def test_ceremony_refusals(self):
        reg, signers, _ = _reg()
        reg.stage("skill/x", b"bytes")
        reg.sign("skill/x", [signers[0]])
        for bad_ops in (["a"], ["a", "a"], [True, "b"], ["", "b"],
                        ["a", None], "ab", None, [1, "b"]):
            with self.assertRaises(sdn.NamespaceError) as ctx:
                reg.promote("skill/x", operator_ids=bad_ops)
            self.assertEqual(ctx.exception.code, "ceremony-refused",
                             "operators=%r" % (bad_ops,))

    def test_threshold_unmet_at_promote(self):
        reg, signers, _ = _reg(threshold=2)
        reg.stage("skill/x", b"bytes")
        reg.sign("skill/x", [signers[0]])
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote("skill/x", operator_ids=["a", "b"])
        self.assertEqual(ctx.exception.code, "threshold-unmet")

    def test_promote_records_provenance(self):
        reg, signers, _ = _reg(threshold=2)
        reg.stage("skill/x", b"bytes")
        reg.sign("skill/x", signers)
        out = reg.promote("skill/x", operator_ids=["op-a", "op-b"])
        self.assertEqual(len(out["signed_by"]), 2)
        self.assertEqual(out["promoted_by"], ["op-a", "op-b"])
        self.assertEqual(out["status"], "promoted")


class TestAdmission(unittest.TestCase):
    def _promoted(self):
        reg, signers, _ = _reg()
        rec = reg.stage("skill/x", b"deploy-bytes")
        reg.sign("skill/x", [signers[0]])
        reg.promote("skill/x", operator_ids=["op-a", "op-b"])
        return reg, rec

    def test_admit_by_digest_pin(self):
        reg, rec = self._promoted()
        out = reg.admit_deploy(rec["digest"], namespace=sdn.ENFORCED)
        self.assertEqual(out["content"], b"deploy-bytes")
        self.assertEqual(len(out["signed_by"]), 1)

    def test_name_only_refused(self):
        reg, _ = self._promoted()
        for ref in ("skill/x", "a" * 40, "latest", ""):
            with self.assertRaises(sdn.NamespaceError) as ctx:
                reg.admit_deploy(ref, namespace=sdn.ENFORCED)
            self.assertEqual(ctx.exception.code, "reference-not-digest",
                             "ref=%r" % (ref,))

    def test_staging_not_a_deploy_source(self):
        reg, rec = self._promoted()
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.admit_deploy(rec["digest"], namespace=sdn.STAGING)
        self.assertEqual(ctx.exception.code, "bad-namespace")

    def test_unknown_namespace(self):
        reg, rec = self._promoted()
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.admit_deploy(rec["digest"], namespace="prod")
        self.assertEqual(ctx.exception.code, "bad-namespace")

    def test_tampered_bytes_refused(self):
        reg, rec = self._promoted()
        reg._enforced[rec["digest"]]["content"] = b"evil-bytes"
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.admit_deploy(rec["digest"], namespace=sdn.ENFORCED)
        self.assertIn(ctx.exception.code, ("digest-mismatch", "bad-signature"))

    def test_forged_envelope_refused(self):
        reg, rec = self._promoted()
        evil = Ed25519Signer(_SEED3)
        forged = reg._enforced[rec["digest"]]["envelope"]
        forged["signatures"] = [{"keyid": evil.key_id,
                                 "sig": "00" * 64}]
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.admit_deploy(rec["digest"], namespace=sdn.ENFORCED)
        self.assertIn(ctx.exception.code,
                      ("bad-signature", "threshold-unmet"))


class TestAudit(unittest.TestCase):
    def test_audit_chained(self):
        reg, signers, _ = _reg()
        reg.stage("skill/a", b"1")
        reg.sign("skill/a", [signers[0]])
        reg.promote("skill/a", operator_ids=["op-a", "op-b"])
        prev = "GENESIS"
        for entry in reg.audit:
            self.assertEqual(entry["prev"], prev)
            recomputed = sdn._audit_hash(
                {k: v for k, v in entry.items() if k != "entry_hash"})
            self.assertEqual(entry["entry_hash"], recomputed)
            prev = entry["entry_hash"]
        ops = [e["op"] for e in reg.audit]
        self.assertEqual(ops, ["registry-created", "staged", "signed",
                               "promoted"])


if __name__ == "__main__":
    unittest.main()
