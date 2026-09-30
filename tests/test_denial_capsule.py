#!/usr/bin/env python3
"""Unit tests for gov.denial_capsule (wave-236 lane B).

Tests live at the public seams: seal_denial, verify_capsule,
disclose_fields, verify_disclosure, emit_denial,
and the additive deny-receipt attach path.
"""

import copy
import hashlib
import json
import os
import re
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import denial_capsule as dcap
from gov import deny_receipts as dr

_SECRET = b"denial-capsule-unit-test-key-00000002"
_KEYID = "denial-capsule-unit-key"


class _Signer:
    alg = "hmac-sha256-mac"
    key_id = _KEYID

    def __init__(self, secret=_SECRET):
        self.secret = bytes(secret)


def _seal(**over):
    kw = dict(refusal_code="deny-receipt-refused",
              authority="governance-authority",
              action_digest="ab" * 32,
              signer=_Signer(), decoy_count=0)
    kw.update(over)
    return dcap.seal_denial(**kw)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


class SealDenialTests(unittest.TestCase):
    def test_01_sealed_capsule_shape(self):
        capsule, material = _seal()
        self.assertEqual(capsule["v"], 1)
        self.assertEqual(capsule["kind"], "denial-capsule")
        self.assertEqual(set(capsule["commitments"]),
                         {"refusal_code", "authority",
                          "action_digest", "timestamp"})
        self.assertEqual(capsule["decoys"], [])
        self.assertEqual(capsule["alg"], "hmac-sha256-mac")
        self.assertEqual(capsule["key_id"], _KEYID)
        self.assertFalse(capsule["non_repudiation"])
        self.assertTrue(capsule["signature"])

    def test_02_sealed_body_is_values_free(self):
        capsule, material = _seal()
        body = {k: v for k, v in capsule.items()
                if k != "signature"}
        text = _canonical(body).decode("utf-8")
        self.assertNotIn("governance-authority", text)
        self.assertNotIn("deny-receipt-refused", text)

    def test_03_commitment_recomputes(self):
        capsule, material = _seal()
        for name, value in material["fields"].items():
            salt = bytes.fromhex(material["salts"][name])
            expect = hashlib.sha256(
                salt + _canonical(value)).hexdigest()
            self.assertEqual(capsule["commitments"][name], expect)

    def test_04_unmapped_refusal_refuses_at_seal(self):
        with self.assertRaises(dcap.DenialCapsuleMalformed) as cm:
            _seal(refusal_code="no-such-code")
        self.assertEqual(cm.exception.code, "denial-capsule-malformed")

    def test_05_nonhex_action_digest_refuses(self):
        with self.assertRaises(dcap.DenialCapsuleMalformed):
            _seal(action_digest="zz")

    def test_06_custom_salts_honored(self):
        salt = os.urandom(16)
        capsule, material = _seal(salts={"refusal_code": salt,
                                        "authority": salt,
                                        "action_digest": salt,
                                        "timestamp": salt})
        self.assertEqual(material["salts"]["refusal_code"], salt.hex())
        expect = hashlib.sha256(
            salt + _canonical("deny-receipt-refused")).hexdigest()
        self.assertEqual(capsule["commitments"]["refusal_code"], expect)

    def test_07_extra_fields_committed(self):
        capsule, material = _seal(extra_fields={"note": "hello"})
        self.assertIn("note", capsule["commitments"])
        self.assertIn("note", material["salts"])

    def test_08_extra_field_collision_refuses(self):
        with self.assertRaises(dcap.DenialCapsuleMalformed):
            _seal(extra_fields={"authority": "other"})

    def test_09_decoys_added_and_shaped(self):
        capsule, material = _seal(decoy_count=3)
        self.assertEqual(len(capsule["decoys"]), 3)
        for d in capsule["decoys"]:
            self.assertTrue(re.match(r"^[0-9a-f]{64}$", d))
        self.assertFalse(
            set(capsule["decoys"]) & set(capsule["commitments"].values()))

    def test_10_timestamp_default_and_pinned(self):
        _, material = _seal()
        self.assertIsInstance(material["fields"]["timestamp"], int)
        capsule, material = _seal(timestamp=1700000000)
        self.assertEqual(material["fields"]["timestamp"], 1700000000)

    def test_11_unregistered_alg_refuses(self):
        class Bad:
            alg = "no-such-alg"
            key_id = "k"
            secret = b"s" * 16
        with self.assertRaises(dcap.DenialCapsuleMalformed):
            _seal(signer=Bad())


class VerifyCapsuleTests(unittest.TestCase):
    def test_01_verify_ok(self):
        capsule, _ = _seal()
        claim = dcap.verify_capsule(capsule, key=_SECRET,
                            expect_alg="hmac-sha256-mac")
        self.assertTrue(claim["ok"])
        self.assertEqual(claim["key_id"], _KEYID)

    def test_02_tampered_commitment_refuses(self):
        capsule, _ = _seal()
        bad = copy.deepcopy(capsule)
        bad["commitments"]["authority"] = "00" * 32
        with self.assertRaises(dcap.DenialCapsuleInvalid) as cm:
            dcap.verify_capsule(bad, key=_SECRET,
                            expect_alg="hmac-sha256-mac")
        self.assertEqual(cm.exception.code,
                         "denial-capsule-signature-invalid")

    def test_03_wrong_key_refuses(self):
        capsule, _ = _seal()
        with self.assertRaises(dcap.DenialCapsuleInvalid):
            dcap.verify_capsule(capsule, key=b"wrong" + _SECRET[5:],
                            expect_alg="hmac-sha256-mac")

    def test_04_expect_alg_pins(self):
        capsule, _ = _seal()
        dcap.verify_capsule(capsule, key=_SECRET,
                            expect_alg="hmac-sha256-mac")
        with self.assertRaises(dcap.DenialCapsuleInvalid):
            dcap.verify_capsule(capsule, key=_SECRET,
                                expect_alg="ed25519-rfc8032")

    def test_05_malformed_shape_refuses(self):
        with self.assertRaises(dcap.DenialCapsuleMalformed):
            dcap.verify_capsule({"v": 1}, key=_SECRET,
                            expect_alg="hmac-sha256-mac")


class DisclosureTests(unittest.TestCase):
    def test_01_selective_disclosure(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["refusal_code", "authority"])
        self.assertEqual(set(disc["disclosed"]),
                         {"refusal_code", "authority"})
        self.assertEqual(disc["disclosed"]["refusal_code"],
                         "deny-receipt-refused")
        self.assertNotIn("action_digest", disc["disclosed"])
        self.assertNotIn("timestamp", disc["disclosed"])
        self.assertNotIn("action_digest", disc["salts"])

    def test_02_verify_disclosure_ok(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["refusal_code"])
        res = dcap.verify_disclosure(capsule, disc, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")
        self.assertTrue(res["ok"])
        self.assertEqual(res["disclosed"], ["refusal_code"])

    def test_03_tampered_value_refuses(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["authority"])
        bad = copy.deepcopy(disc)
        bad["disclosed"]["authority"] = "forged-authority"
        with self.assertRaises(dcap.DenialCapsuleDisclosure) as cm:
            dcap.verify_disclosure(capsule, bad, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")
        self.assertEqual(cm.exception.code,
                         "denial-disclosure-mismatch")

    def test_04_wrong_salt_refuses(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["authority"])
        bad = copy.deepcopy(disc)
        bad["salts"]["authority"] = "ff" * 32
        with self.assertRaises(dcap.DenialCapsuleDisclosure):
            dcap.verify_disclosure(capsule, bad, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")

    def test_05_uncommitted_field_refuses(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["authority"])
        bad = copy.deepcopy(disc)
        bad["disclosed"]["note"] = "x"
        bad["salts"]["note"] = "ff" * 32
        with self.assertRaises(dcap.DenialCapsuleDisclosure):
            dcap.verify_disclosure(capsule, bad, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")

    def test_06_capsule_digest_binding(self):
        capsule, material = _seal()
        disc = dcap.disclose_fields(capsule, material,
                                    ["authority"])
        other, _ = _seal()
        bad = copy.deepcopy(disc)
        bad["capsule_digest"] = dcap.disclose_fields(
            other, material, ["authority"])["capsule_digest"]
        with self.assertRaises(dcap.DenialCapsuleDisclosure):
            dcap.verify_disclosure(capsule, bad, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")

    def test_07_empty_field_list_refuses(self):
        capsule, material = _seal()
        with self.assertRaises(dcap.DenialCapsuleMalformed):
            dcap.disclose_fields(capsule, material, [])


class EmitDenialTests(unittest.TestCase):
    def test_01_unsealed_refuses(self):
        with self.assertRaises(dcap.DenialCapsuleUnsealed) as cm:
            dcap.emit_denial({"action": "pay"})
        self.assertEqual(cm.exception.code, "denial-unsealed")

    def test_02_sealed_emits_record(self):
        capsule, _ = _seal()
        rec = dcap.emit_denial({"action": "pay"}, capsule=capsule)
        self.assertEqual(rec["kind"], "denial")
        self.assertEqual(rec["capsule"], capsule)
        self.assertEqual(rec["action"], {"action": "pay"})


    def test_06_forged_capsule_disclosure_refused(self):
        # A self-consistent capsule sealed by another key is NOT
        # trusted: the seal is verified before commitments.
        capsule, material = _seal(
            signer=_Signer(secret=b"attacker-secret-0000000000000012"))
        disc = dcap.disclose_fields(capsule, material, ["authority"])
        with self.assertRaises(dcap.DenialCapsuleInvalid) as cm:
            dcap.verify_disclosure(capsule, disc, key=_SECRET,
                                   expect_alg="hmac-sha256-mac")
        self.assertEqual(cm.exception.code,
                         "denial-capsule-signature-invalid")


class EvidenceAndReceiptTests(unittest.TestCase):
    def test_02_receipt_attach_and_verify(self):
        capsule, _ = _seal()
        signer = dr.Signer("hmac-sha256-mac", _SECRET, _KEYID)
        decision = {
            "verdict": "DENY",
            "rule_path": "policy.allowlist",
            "token_digest": "cd" * 32,
            "policy_bundle_digest": "ef" * 32,
            "intent_digest": "01" * 32,
            "jurisdiction_profile": "default",
        }
        receipt = dr.emit(copy.deepcopy(decision), signer=signer,
                          denial_capsule=capsule)
        self.assertEqual(receipt["denial_capsule"], capsule)
        claim = dr.verify(receipt, key=_SECRET,
                          expect_alg="hmac-sha256-mac")
        self.assertTrue(claim["ok"])

    def test_03_receipt_legacy_bytes_identical(self):
        signer = dr.Signer("hmac-sha256-mac", _SECRET, _KEYID)
        decision = {
            "verdict": "DENY",
            "rule_path": "policy.allowlist",
            "token_digest": "cd" * 32,
            "policy_bundle_digest": "ef" * 32,
            "intent_digest": "01" * 32,
            "jurisdiction_profile": "default",
        }
        receipt = dr.emit(copy.deepcopy(decision), signer=signer)
        self.assertNotIn("denial_capsule", receipt)
        self.assertEqual(
            set(receipt),
            {"v", "kind", "verdict", "class", "rule_path",
             "token_digest", "policy_bundle_digest", "intent_digest",
             "jurisdiction_profile", "alg", "key_id",
             "non_repudiation", "signature"})
        dr.verify(receipt, key=_SECRET,
                  expect_alg="hmac-sha256-mac")

    def test_04_receipt_capsule_tamper_breaks_receipt(self):
        capsule, _ = _seal()
        signer = dr.Signer("hmac-sha256-mac", _SECRET, _KEYID)
        decision = {
            "verdict": "DENY",
            "rule_path": "policy.allowlist",
            "token_digest": "cd" * 32,
            "policy_bundle_digest": "ef" * 32,
            "intent_digest": "01" * 32,
            "jurisdiction_profile": "default",
        }
        receipt = dr.emit(copy.deepcopy(decision), signer=signer,
                          denial_capsule=capsule)
        bad = copy.deepcopy(receipt)
        bad["denial_capsule"]["commitments"]["authority"] = "00" * 32
        with self.assertRaises(Exception):
            dr.verify(bad, key=_SECRET,
                      expect_alg="hmac-sha256-mac")

    def test_05_receipt_malformed_capsule_refuses(self):
        signer = dr.Signer("hmac-sha256-mac", _SECRET, _KEYID)
        decision = {
            "verdict": "DENY",
            "rule_path": "policy.allowlist",
            "token_digest": "cd" * 32,
            "policy_bundle_digest": "ef" * 32,
            "intent_digest": "01" * 32,
            "jurisdiction_profile": "default",
        }
        with self.assertRaises(dcap.DenialCapsuleMalformed) as cm:
            dr.emit(copy.deepcopy(decision), signer=signer,
                    denial_capsule={"v": 1})
        # The native denial-capsule refusal propagates unwrapped so
        # the taxonomy code survives the seam.
        self.assertEqual(cm.exception.code,
                         "denial-capsule-malformed")


if __name__ == "__main__":
    unittest.main()
