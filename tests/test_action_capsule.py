#!/usr/bin/env python3
"""Unit tests for gov/action_capsule.py (public seams, spec literals)."""

import hashlib
import json
import unittest

from gov import action_capsule as ac


def _jcs(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


class SealTest(unittest.TestCase):
    def test_admit_seals_with_bound_digests(self):
        attempt = {"action": "read", "digest": "sha256:" + "11" * 32}
        effect = {"status": "admitted", "evidence": "sha256:" + "22" * 32}
        cap = ac.seal_capsule({"attempt": attempt, "effect": effect})
        self.assertEqual(cap["v"], 1)
        self.assertEqual(
            cap["verdict_digest"], hashlib.sha256(
                _jcs(attempt).encode()).hexdigest())
        self.assertEqual(
            cap["effect_digest"], hashlib.sha256(
                _jcs(effect).encode()).hexdigest())
        body = json.loads(cap["jcs_json"])
        self.assertEqual(
            cap["capsule_digest"], hashlib.sha256(
                cap["jcs_json"].encode()).hexdigest())
        self.assertEqual(body["attempt"], attempt)
        self.assertEqual(body["effect"], effect)

    def test_refusal_seals_as_evidence(self):
        cap = ac.capsule_from_refusal("permit-revoked",
                                      "sha256:" + "33" * 32)
        body = ac.verify_capsule(cap)
        self.assertEqual(body["effect"]["status"], "refused")
        self.assertEqual(body["effect"]["code"], "permit-revoked")
        self.assertEqual(body["attempt"]["subject_digest"],
                         "sha256:" + "33" * 32)

    def test_conflated_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1}, "effect": {"a": 1}})
        self.assertEqual(ctx.exception.code,
                         "capsule-attempt-effect-diverged")

    def test_effect_without_evidence_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1},
                             "effect": {"status": "admitted"}})
        self.assertEqual(ctx.exception.code,
                         "capsule-attempt-effect-diverged")

    def test_refused_effect_needs_code(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1},
                             "effect": {"status": "refused",
                                        "evidence": "e"}})
        self.assertEqual(ctx.exception.code,
                         "capsule-attempt-effect-diverged")

    def test_authority_smuggle_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1},
                             "effect": {"status": "admitted",
                                        "evidence": "e"},
                             "permit": {"all": True}})
        self.assertEqual(ctx.exception.code, "capsule-not-authorization")

    def test_verify_tamper_detected(self):
        cap = ac.seal_capsule(
            {"attempt": {"a": 1},
             "effect": {"status": "admitted", "evidence": "e"}})
        tampered = dict(cap)
        tampered["jcs_json"] = cap["jcs_json"].replace('"a":1', '"a":2')
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.verify_capsule(tampered)
        self.assertEqual(ctx.exception.code, "capsule-digest-mismatch")

    def test_verify_malformed(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.verify_capsule({"v": 1})
        self.assertEqual(ctx.exception.code, "capsule-malformed")

    def test_unknown_field_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1},
                             "effect": {"status": "admitted",
                                        "evidence": "e"},
                             "extra": "x"})
        self.assertEqual(ctx.exception.code, "capsule-unknown-field")

    def test_verify_roundtrip(self):
        cap = ac.seal_capsule(
            {"attempt": {"a": 1},
             "effect": {"status": "admitted", "evidence": "e"}})
        body = ac.verify_capsule(cap)
        self.assertEqual(body["effect"]["status"], "admitted")


class StrictJsonTest(unittest.TestCase):
    def test_duplicate_keys_refused(self):
        raw = (b'{"attempt": {"action": "x"}, "attempt": {"action": "y"}, '
               b'"effect": {"status": "refused", "code": "c", '
               b'"evidence": "e"}}')
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule_json(raw)
        self.assertEqual(ctx.exception.code, "capsule-noncanonical")

    def test_unsorted_refused(self):
        raw = (b'{"effect": {"code": "c", "evidence": "e", '
               b'"status": "refused"}, "attempt": {"action": "x"}}')
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule_json(raw)
        self.assertEqual(ctx.exception.code, "capsule-noncanonical")

    def test_nonutf8_refused(self):
        raw = b'{"attempt": {"action": "\xff"}, "effect": {}}'
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule_json(raw)
        self.assertEqual(ctx.exception.code, "capsule-noncanonical")

    def test_float_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule({"attempt": {"a": 1.5},
                             "effect": {"status": "admitted",
                                        "evidence": "e"}})
        self.assertEqual(ctx.exception.code, "capsule-noncanonical")

    def test_canonical_roundtrip(self):
        raw = (b'{"attempt":{"action":"x"},"effect":{"code":"c",'
               b'"evidence":"e","status":"refused"}}')
        cap = ac.seal_capsule_json(raw)
        self.assertEqual(ac.verify_capsule(cap)["effect"]["code"], "c")

    def test_non_bytes_refused(self):
        with self.assertRaises(ac.CapsuleError) as ctx:
            ac.seal_capsule_json('{"attempt": {}}')
        self.assertEqual(ctx.exception.code, "capsule-malformed")


if __name__ == "__main__":
    unittest.main()
