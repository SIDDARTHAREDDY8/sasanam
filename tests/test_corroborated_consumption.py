#!/usr/bin/env python3
"""Unit tests for gov/corroborated_consumption.py (wave-238 lane D).

Independent-corroboration consumption: the consumer corroborates each
evidence item against its own out-of-band trust policy; key inequality
between sources is necessary; the gated runtime's own key is
self-attestation, never corroboration.
"""

import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import corroborated_consumption as cc
from gov import ed25519 as ed


def _hex(b):
    return b.hex()


class _Fixture:
    def __init__(self):
        self.seeds = [
            bytes(range(32)),
            bytes(255 - i for i in range(32)),
            bytes((7 * i + 3) % 256 for i in range(32)),
            bytes((11 * i + 5) % 256 for i in range(32)),
        ]
        self.pubs = [ed.publickey(s) for s in self.seeds]
        self.kids = [cc.key_id_of(p) for p in self.pubs]

    def item(self, idx, dimension="policy_applied", state="allowed",
             source_id=None, tamper_state=None):
        kid = self.kids[idx]
        item = {
            "dimension": dimension,
            "state": state,
            "source": {
                "source_id": source_id or ("source-%d" % idx),
                "key_id": kid,
                "signature": None,
            },
        }
        item["source"]["signature"] = _hex(
            ed.sign(self.seeds[idx], cc.canonical_item_bytes(item)))
        if tamper_state is not None:
            item["state"] = tamper_state
        return item

    def policy(self, trusted=(0, 1), runtime=2, require=("policy_applied",)):
        return cc.TrustPolicy(
            trusted_keys={self.kids[i]: self.pubs[i] for i in trusted},
            runtime_key_id=self.kids[runtime],
            require_dimensions=frozenset(require),
        )


def _refused(test, fn, code):
    with test.assertRaises(cc.CorroboratedConsumptionError) as ctx:
        fn()
    test.assertEqual(ctx.exception.code, code,
                     "expected %r, got %r (%s)" % (
                         code, ctx.exception.code, ctx.exception.detail))


class KeyIdTests(unittest.TestCase):
    def test_key_id_is_64_hex_and_deterministic(self):
        fx = _Fixture()
        kid = cc.key_id_of(fx.pubs[0])
        self.assertEqual(len(kid), 64)
        int(kid, 16)
        self.assertEqual(kid, cc.key_id_of(fx.pubs[0]))
        self.assertNotEqual(kid, cc.key_id_of(fx.pubs[1]))

    def test_key_id_rejects_bad_material(self):
        with self.assertRaises(cc.CorroboratedConsumptionError) as ctx:
            cc.key_id_of(b"short")
        self.assertEqual(ctx.exception.code, cc.CORROBORATION_MALFORMED)


class CanonicalItemBytesTests(unittest.TestCase):
    def test_signature_covers_signed_fields_not_signature(self):
        fx = _Fixture()
        item = fx.item(0)
        body = cc.canonical_item_bytes(item)
        self.assertNotIn(b"signature", body)
        self.assertIn(b"policy_applied", body)
        self.assertTrue(ed.verify(fx.pubs[0], body,
                                  bytes.fromhex(
                                      item["source"]["signature"])))


class ConsumeTests(unittest.TestCase):
    def test_two_independent_keys_consumed(self):
        fx = _Fixture()
        env = {"envelope_id": "e", "evidence": [fx.item(0), fx.item(1)]}
        receipt = cc.consume(env, fx.policy())
        self.assertEqual(receipt["envelope_id"], "e")
        self.assertEqual(set(receipt["corroborated"]["policy_applied"]),
                         set(fx.kids[:2]))

    def test_single_source_uncorroborated(self):
        fx = _Fixture()
        env = {"envelope_id": "e", "evidence": [fx.item(0)]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_UNCORROBORATED)

    def test_same_key_two_source_labels_key_inequality(self):
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0, source_id="a"),
                            fx.item(0, source_id="b")]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_KEY_INEQUALITY)

    def test_same_source_restating_is_one_witness(self):
        # Same source_id + same key restating counts once, not as
        # independent corroboration.
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0, source_id="a"),
                            fx.item(0, source_id="a")]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_UNCORROBORATED)

    def test_runtime_key_is_self_attestation(self):
        fx = _Fixture()
        env = {"envelope_id": "e", "evidence": [fx.item(2)]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_UNATTESTED)

    def test_self_attestation_fails_before_signature_check(self):
        # Runtime key not even in the policy: still unattested, never
        # silently downgraded to untrusted-source.
        fx = _Fixture()
        pol = cc.TrustPolicy(
            trusted_keys={fx.kids[0]: fx.pubs[0]},
            runtime_key_id=fx.kids[2],
            require_dimensions=frozenset(("policy_applied",)))
        env = {"envelope_id": "e", "evidence": [fx.item(2)]}
        _refused(self, lambda: cc.consume(env, pol),
                 cc.CORROBORATION_UNATTESTED)

    def test_unknown_key_untrusted_source(self):
        fx = _Fixture()
        env = {"envelope_id": "e", "evidence": [fx.item(3)]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_UNTRUSTED_SOURCE)

    def test_tampered_item_signature_invalid(self):
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0, tamper_state="denied")]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_SIGNATURE_INVALID)

    def test_malformed_envelope_variants(self):
        fx = _Fixture()
        pol = fx.policy()
        _refused(self, lambda: cc.consume("nope", pol),
                 cc.CORROBORATION_MALFORMED)
        _refused(self, lambda: cc.consume({"envelope_id": "e"}, pol),
                 cc.CORROBORATION_MALFORMED)
        _refused(self, lambda: cc.consume({"envelope_id": "e",
                                           "evidence": "nope"}, pol),
                 cc.CORROBORATION_MALFORMED)
        _refused(self, lambda: cc.consume({"envelope_id": "e",
                                           "evidence": [{"no": "fields"}]},
                                          pol),
                 cc.CORROBORATION_MALFORMED)
        bad_hex = fx.item(0)
        bad_hex["source"]["key_id"] = "zz" * 32
        _refused(self, lambda: cc.consume({"envelope_id": "e",
                                           "evidence": [bad_hex]}, pol),
                 cc.CORROBORATION_MALFORMED)

    def test_required_dimension_missing_is_uncorroborated(self):
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0, dimension="policy_applied"),
                            fx.item(1, dimension="policy_applied")]}
        pol = fx.policy(require=("policy_applied", "outcome"))
        _refused(self, lambda: cc.consume(env, pol),
                 cc.CORROBORATION_UNCORROBORATED)

    def test_nonrequired_dimension_still_signature_checked(self):
        # Extra dimensions do not gate consumption, but a tampered extra
        # item still refuses fail-closed.
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0), fx.item(1),
                            fx.item(0, dimension="note",
                                    tamper_state="forged")]}
        _refused(self, lambda: cc.consume(env, fx.policy()),
                 cc.CORROBORATION_SIGNATURE_INVALID)

    def test_policy_shape_failures_are_malformed(self):
        fx = _Fixture()
        with self.assertRaises(cc.CorroboratedConsumptionError) as ctx:
            cc.TrustPolicy({}, fx.kids[2], frozenset(("policy_applied",)))
        self.assertEqual(ctx.exception.code, cc.CORROBORATION_MALFORMED)
        with self.assertRaises(cc.CorroboratedConsumptionError) as ctx:
            cc.TrustPolicy({fx.kids[0]: fx.pubs[0]}, fx.kids[2],
                           frozenset())
        self.assertEqual(ctx.exception.code, cc.CORROBORATION_MALFORMED)

    def test_disagreement_still_consumes_keys_not_truth(self):
        # Corroboration here is source-independence, not truth: two
        # independent sources disagreeing on state still corroborate
        # (each item is honestly signed). Truth arbitration is not this
        # module's job -- documented honest boundary.
        fx = _Fixture()
        env = {"envelope_id": "e",
               "evidence": [fx.item(0, state="allowed"),
                            fx.item(1, state="denied")]}
        receipt = cc.consume(env, fx.policy())
        self.assertEqual(len(receipt["corroborated"]["policy_applied"]), 2)


if __name__ == "__main__":
    unittest.main()
