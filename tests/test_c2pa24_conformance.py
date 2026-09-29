"""Unit tests for gov/c2pa24_conformance.py (wave-215 lane B).

All keys and fixtures are synthetic test-local material.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import c2pa24_conformance as c24
from gov import ed25519 as _ed

_SEED = bytes(range(1, 33))
_PUB = _ed.publickey(_SEED)
_FOREIGN = bytes(range(33, 65))


def _assertions(*labels):
    asrt = {}
    for label in labels:
        if label == "c2pa.actions":
            asrt[label] = {"actions": [
                {"action": "c2pa.created", "softwareAgent": "u/1.0"}]}
        elif label == "c2pa.actions.v2":
            asrt[label] = {"version": 2, "actions": [
                {"action": "c2pa.created", "softwareAgent": "u/1.0"}]}
        elif label == "c2pa.ingredient":
            asrt[label] = {"ingredients": [
                {"ingredient_digest": "aa" * 32, "relationship": "parentOf",
                 "role": "prompt"}]}
        elif label == "c2pa.ingredient.v3":
            asrt[label] = {"version": 3, "ingredients": [
                {"ingredient_digest": "aa" * 32, "relationship": "parentOf",
                 "role": "prompt"}]}
        elif label == "c2pa.ai-disclosure":
            asrt[label] = {"aiDisclosure": {"label": "ai-generated"}}
        elif label == "c2pa.hash.data":
            asrt[label] = {"digest": "bb" * 32}
        else:
            asrt[label] = {}
    return asrt


def _pin(label, digest):
    return c24.sign_deprecation_pin(_SEED, label=label,
                                   assertions_digest=digest,
                                   reason="unit test")


class TestVocabulary(unittest.TestCase):
    def test_v2_accepted(self):
        out = c24.verify_24_vocabulary(_assertions("c2pa.actions.v2"))
        self.assertEqual(out["deprecated_admitted"], [])

    def test_v3_accepted(self):
        c24.verify_24_vocabulary(_assertions("c2pa.ingredient.v3"))

    def test_ai_disclosure_accepted(self):
        c24.verify_24_vocabulary(_assertions("c2pa.ai-disclosure"))

    def test_hash_data_accepted(self):
        c24.verify_24_vocabulary(_assertions("c2pa.hash.data"))

    def test_deprecated_actions_refused(self):
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(_assertions("c2pa.actions"))
        self.assertEqual(ctx.exception.code, "deprecated-assertion-version")

    def test_deprecated_ingredient_refused(self):
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(_assertions("c2pa.ingredient"))
        self.assertEqual(ctx.exception.code, "deprecated-assertion-version")

    def test_unknown_label_refused(self):
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary({"c2pa.madeup": {}})
        self.assertEqual(ctx.exception.code, "unknown-assertion-label")

    def test_v2_wrong_version_refused(self):
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(
                {"c2pa.actions.v2": {"version": 1, "actions": []}})
        self.assertEqual(ctx.exception.code, "bad-assertion-shape")

    def test_v2_unknown_action_refused(self):
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(
                {"c2pa.actions.v2": {
                    "version": 2,
                    "actions": [{"action": "c2pa.teleported"}]}})
        self.assertEqual(ctx.exception.code, "unknown-action-label")

    def test_v3_bad_digest_refused(self):
        bad = _assertions("c2pa.ingredient.v3")
        bad["c2pa.ingredient.v3"]["ingredients"][0]["ingredient_digest"] = "zz"
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(bad)
        self.assertEqual(ctx.exception.code, "bad-assertion-shape")

    def test_pin_admits_deprecated(self):
        asrt = _assertions("c2pa.actions")
        digest = c24.assertions_digest(asrt)
        out = c24.verify_24_vocabulary(
            asrt, deprecated_pins=[_pin("c2pa.actions", digest)],
            deprecated_pin_issuer_pub=_PUB)
        self.assertEqual(out["deprecated_admitted"], ["c2pa.actions"])

    def test_pin_digest_bound(self):
        asrt = _assertions("c2pa.actions")
        digest = c24.assertions_digest(asrt)
        other = _assertions("c2pa.actions", "c2pa.actions.v2")
        other_digest = c24.assertions_digest(other)
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(
                other, deprecated_pins=[_pin("c2pa.actions", digest)],
                deprecated_pin_issuer_pub=_PUB)
        self.assertEqual(ctx.exception.code, "bad-pin")

    def test_pin_wrong_key_refused(self):
        asrt = _assertions("c2pa.actions")
        digest = c24.assertions_digest(asrt)
        bad = c24.sign_deprecation_pin(
            _FOREIGN, label="c2pa.actions", assertions_digest=digest,
            reason="unit test")
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(
                asrt, deprecated_pins=[bad],
                deprecated_pin_issuer_pub=_PUB)
        self.assertEqual(ctx.exception.code, "bad-pin")

    def test_pin_without_issuer_key_refused(self):
        asrt = _assertions("c2pa.actions")
        digest = c24.assertions_digest(asrt)
        with self.assertRaises(c24.C2PA24Error) as ctx:
            c24.verify_24_vocabulary(
                asrt, deprecated_pins=[_pin("c2pa.actions", digest)])
        self.assertEqual(ctx.exception.code, "bad-pin")

    def test_assertions_digest_deterministic(self):
        a = _assertions("c2pa.actions.v2")
        b = _assertions("c2pa.actions.v2")
        self.assertEqual(c24.assertions_digest(a),
                         c24.assertions_digest(b))


class TestTrustStore(unittest.TestCase):
    def _record(self, layer, key_id, trust, seed=_SEED):
        return c24.sign_trust_record(seed, layer=layer, key_id=key_id,
                                     trust=trust)

    def test_custom_beats_itl_beats_default(self):
        store = c24.TrustStore()
        store.add_record(self._record("default", "k", "allow"),
                         issuer_pub=_PUB)
        store.add_record(self._record("itl", "k", "deny"),
                         issuer_pub=_PUB)
        store.add_record(self._record("custom", "k", "allow"),
                         issuer_pub=_PUB)
        self.assertEqual(store.check("k"), "allow")

    def test_itl_beats_default(self):
        store = c24.TrustStore()
        store.add_record(self._record("default", "k", "allow"),
                         issuer_pub=_PUB)
        store.add_record(self._record("itl", "k", "deny"),
                         issuer_pub=_PUB)
        with self.assertRaises(c24.C2PA24Error) as ctx:
            store.check("k")
        self.assertEqual(ctx.exception.code, "signer-denied")

    def test_unknown_signer_refused(self):
        store = c24.TrustStore()
        with self.assertRaises(c24.C2PA24Error) as ctx:
            store.check("ghost")
        self.assertEqual(ctx.exception.code, "untrusted-signer")

    def test_unsigned_record_refused(self):
        store = c24.TrustStore()
        with self.assertRaises(c24.C2PA24Error) as ctx:
            store.add_record({"layer": "default", "key_id": "k",
                              "trust": "allow", "signer": {"kid": "x"}},
                             issuer_pub=_PUB)
        self.assertEqual(ctx.exception.code, "bad-trust-signature")

    def test_wrong_authority_refused(self):
        store = c24.TrustStore()
        with self.assertRaises(c24.C2PA24Error) as ctx:
            store.add_record(self._record("default", "k", "allow",
                                          seed=_FOREIGN),
                             issuer_pub=_PUB)
        self.assertEqual(ctx.exception.code, "bad-trust-signature")

    def test_duplicate_keyid_same_layer_refused(self):
        store = c24.TrustStore()
        store.add_record(self._record("default", "k", "allow"),
                         issuer_pub=_PUB)
        with self.assertRaises(c24.C2PA24Error) as ctx:
            store.add_record(self._record("default", "k", "deny"),
                             issuer_pub=_PUB)
        self.assertEqual(ctx.exception.code, "duplicate-trust-record")


if __name__ == "__main__":
    unittest.main()
