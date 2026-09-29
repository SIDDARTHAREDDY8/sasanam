#!/usr/bin/env python3
"""Unit tests for gov.promotion_artifact_gate + the promotion-gate
wiring in gov.sign_deploy_namespaces (wave-213 lane B).

Pins: load-time terminal-DISALLOW lint (fail closed), fail-closed on
absent (materials, products) maps, tighten-only promotion (deny can
only be added, never removed), denial reasons in the audit log, and
byte-identical legacy promote() without a configured ruleset.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov import promotion_artifact_gate as pag  # noqa: E402
from gov import sign_deploy_namespaces as sdn  # noqa: E402
from gov.artifact_rules import ArtifactRuleError  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_H1 = "00" * 32
_H2 = "11" * 32
_H3 = "22" * 32
_H4 = "33" * 32

_RULES = [
    ("MATCH", "src/main.py", _H1),
    ("MATCH", "src/util.py", _H2),
    ("CREATE", "dist/app.bin"),
    ("DISALLOW",),
]
_MATERIALS = {"src/main.py": _H1, "src/util.py": _H2}
_PRODUCTS = {"dist/app.bin": _H3}

_SEED1 = bytes.fromhex("71" * 32)
_SEED2 = bytes.fromhex("72" * 32)


def _keys():
    signers = [Ed25519Signer(_SEED1), Ed25519Signer(_SEED2)]
    verifiers = [Ed25519Verifier(s.public_key) for s in signers]
    return signers, verifiers


def _registry(ruleset=None):
    _, verifiers = _keys()
    if ruleset is None:
        return sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    return sdn.NamespaceRegistry(verifiers=verifiers, threshold=1,
                                 artifact_ruleset=ruleset)


class TestLoadPromotionRules(unittest.TestCase):
    def test_valid_set_normalizes(self):
        rules = pag.load_promotion_rules(_RULES)
        self.assertIsInstance(rules, tuple)
        self.assertEqual(rules[-1], ("DISALLOW",))

    def test_missing_terminal_disallow_refused(self):
        with self.assertRaises(ArtifactRuleError) as ctx:
            pag.load_promotion_rules([("MATCH", "src/main.py", _H1)])
        self.assertIn("DISALLOW", str(ctx.exception))

    def test_disallow_mid_set_refused(self):
        bad = [("DISALLOW",), ("MATCH", "src/main.py", _H1),
               ("DISALLOW",)]
        with self.assertRaises(ArtifactRuleError):
            pag.load_promotion_rules(bad)

    def test_empty_set_refused(self):
        with self.assertRaises(ArtifactRuleError):
            pag.load_promotion_rules([])

    def test_unknown_kind_refused(self):
        with self.assertRaises(ArtifactRuleError):
            pag.load_promotion_rules([("ALLOW", "x"), ("DISALLOW",)])

    def test_error_is_value_error(self):
        # Sibling-module convention: loud ValueError, never silent False.
        with self.assertRaises(ValueError):
            pag.load_promotion_rules([("CREATE", "x")])


class TestCheckPromotionArtifacts(unittest.TestCase):
    def test_valid_maps_return_report(self):
        report = pag.check_promotion_artifacts("b/x", _MATERIALS,
                                               _PRODUCTS, _RULES)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["rule_set_digest"]), 64)
        self.assertIn("promotion:b/x", report["context"])

    def test_absent_maps_fail_closed(self):
        for materials, products in ((None, _PRODUCTS),
                                    (_MATERIALS, None),
                                    (None, None)):
            with self.assertRaises(ArtifactRuleError) as ctx:
                pag.check_promotion_artifacts("b/x", materials, products,
                                              _RULES)
            self.assertIn("fail closed", str(ctx.exception))

    def test_swapped_material_raises(self):
        swapped = dict(_MATERIALS, **{"src/main.py": _H4})
        with self.assertRaises(ArtifactRuleError):
            pag.check_promotion_artifacts("b/x", swapped, _PRODUCTS, _RULES)

    def test_extra_product_raises(self):
        poisoned = dict(_PRODUCTS, **{"dist/evil.bin": _H4})
        with self.assertRaises(ArtifactRuleError) as ctx:
            pag.check_promotion_artifacts("b/x", _MATERIALS, poisoned,
                                          _RULES)
        self.assertIn("DISALLOW", str(ctx.exception))


class TestPromotionGateIntegration(unittest.TestCase):
    def _promotable(self, reg, name="bundle/x", content=b"bytes"):
        signers, _ = _keys()
        reg.stage(name, content)
        reg.sign(name, signers)
        return name

    def test_bad_ruleset_refused_at_construction(self):
        with self.assertRaises(sdn.NamespaceError) as ctx:
            _registry([("MATCH", "src/main.py", _H1)])
        self.assertEqual(ctx.exception.code, "bad-ruleset")

    def test_valid_maps_promote(self):
        reg = _registry(_RULES)
        name = self._promotable(reg)
        out = reg.promote(name, operator_ids=["op-a", "op-b"],
                          materials=_MATERIALS, products=_PRODUCTS)
        self.assertEqual(out["status"], "promoted")
        promoted = [e for e in reg.audit if e["op"] == "promoted"]
        self.assertEqual(len(promoted), 1)
        self.assertIn("artifact_rules=", promoted[0]["detail"])

    def test_gate_violation_denies_and_audits(self):
        reg = _registry(_RULES)
        name = self._promotable(reg)
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote(name, operator_ids=["op-a", "op-b"],
                        materials=_MATERIALS,
                        products=dict(_PRODUCTS, **{"dist/x.bin": _H4}))
        self.assertEqual(ctx.exception.code, "artifact-gate-refused")
        denied = [e for e in reg.audit if e["op"] == "promotion-denied"]
        self.assertEqual(len(denied), 1)
        self.assertIn("artifact-gate", denied[0]["detail"])
        self.assertEqual(denied[0]["name"], name)

    def test_denied_bundle_not_in_enforced(self):
        reg = _registry(_RULES)
        name = self._promotable(reg)
        with self.assertRaises(sdn.NamespaceError):
            reg.promote(name, operator_ids=["op-a", "op-b"],
                        materials=_MATERIALS,
                        products=dict(_PRODUCTS, **{"dist/x.bin": _H4}))
        digest = "sha256:" + __import__("hashlib").sha256(b"bytes").hexdigest()
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.admit_deploy(digest)
        self.assertEqual(ctx.exception.code, "unknown-bundle")

    def test_legacy_path_unchanged_without_ruleset(self):
        reg = _registry()
        name = self._promotable(reg)
        out = reg.promote(name, operator_ids=["op-a", "op-b"])
        self.assertEqual(out["status"], "promoted")
        promoted = [e for e in reg.audit if e["op"] == "promoted"]
        self.assertNotIn("artifact_rules", promoted[0]["detail"])
        self.assertTrue(promoted[0]["detail"].startswith("signed_by="))

    def test_legacy_denies_unchanged_with_ruleset(self):
        reg = _registry(_RULES)
        signers, _ = _keys()
        reg.stage("b/u", b"x")
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote("b/u", operator_ids=["op-a", "op-b"],
                        materials=_MATERIALS, products=_PRODUCTS)
        self.assertEqual(ctx.exception.code, "unsigned-refused")
        name = self._promotable(reg, name="b/c", content=b"y")
        with self.assertRaises(sdn.NamespaceError) as ctx:
            reg.promote(name, operator_ids=["only-one"],
                        materials=_MATERIALS, products=_PRODUCTS)
        self.assertEqual(ctx.exception.code, "ceremony-refused")


if __name__ == "__main__":
    unittest.main()
