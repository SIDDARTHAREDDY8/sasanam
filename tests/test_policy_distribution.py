"""Unit tests for gov/policy_distribution.py (wave-260 lane 1)."""

import json
import os
import unittest

from gov import decision_codes
from gov import ed25519
from gov import policy_distribution as pd


class PublisherTests(unittest.TestCase):
    def test_sign_apply_round_trip(self):
        pub = pd.Publisher(os.urandom(32))
        sub = pd.Subscriber(topic="policies", pubkey=pub.pubkey)
        res = sub.apply(pub.sign_bundle("policies", 1, {"deny": ["x"]}))
        self.assertEqual(res["outcome"], "applied")
        self.assertEqual(res["version"], 1)
        self.assertEqual(sub.payload, {"deny": ["x"]})
        self.assertFalse(res["duplicate"])
        self.assertFalse(res["gap"])

    def test_pubkey_is_ed25519_publickey(self):
        seed = os.urandom(32)
        self.assertEqual(pd.Publisher(seed).pubkey, ed25519.publickey(seed))

    def test_verify_contract_is_bool(self):
        # Wave-243 lesson: assert `is True` / `is False`, never truthiness.
        pub = pd.Publisher(os.urandom(32))
        sub = pd.Subscriber(topic="policies", pubkey=pub.pubkey)
        bundle = pub.sign_bundle("policies", 1, {"a": 1})
        env = json.loads(bundle.decode())
        good = pd.signed_bytes("policies", 1, {"a": 1})
        self.assertIs(
            ed25519.verify(pub.pubkey, good, bytes.fromhex(env["sig"])),
            True)
        self.assertIs(
            ed25519.verify(pub.pubkey, good, b"\x00" * 64), False)
        res = sub.apply(bundle)
        self.assertEqual(res["outcome"], "applied")

    def test_publisher_refuses_non_increasing_version(self):
        pub = pd.Publisher(os.urandom(32))
        pub.sign_bundle("t", 3, {})
        with self.assertRaises(pd.PublisherError):
            pub.sign_bundle("t", 3, {})
        with self.assertRaises(pd.PublisherError):
            pub.sign_bundle("t", 1, {})

    def test_publisher_rejects_bad_inputs(self):
        pub = pd.Publisher(os.urandom(32))
        with self.assertRaises(pd.PublisherError):
            pd.Publisher(b"short")
        for bad_topic in ("", "has space", "../x", 123, None):
            with self.assertRaises(pd.PublisherError):
                pub.sign_bundle(bad_topic, 1, {})
        for bad_version in (-1, True, "2", 2.0):
            with self.assertRaises(pd.PublisherError):
                pub.sign_bundle("t", bad_version, {})
        with self.assertRaises(pd.PublisherError):
            pub.sign_bundle("t", 1, object())  # not JSON-serializable

    def test_domain_separator_binds_signature(self):
        # The domain separator means the signature cannot be replayed as
        # a bare ed25519 signature over the canonical payload bytes.
        pub = pd.Publisher(os.urandom(32))
        bundle = pub.sign_bundle("policies", 1, {"a": 1})
        sig = bytes.fromhex(json.loads(bundle.decode())["sig"])
        self.assertIs(
            ed25519.verify(pub.pubkey,
                           pd.canonical_payload("policies", 1, {"a": 1}),
                           sig),
            False)


class SubscriberRefusalTests(unittest.TestCase):
    def _pair(self, topic="policies"):
        seed = os.urandom(32)
        return pd.Publisher(seed), pd.Subscriber(topic=topic,
                                                 pubkey=pd.Publisher(seed).pubkey)

    def _refused(self, sub, bundle, code):
        res = sub.apply(bundle)
        self.assertEqual(res["outcome"], "refused")
        self.assertEqual(res["code"]["code"], code)
        self.assertEqual(res["code"]["domain"], "poldist")
        self.assertFalse(res["code"]["authority"])
        return res

    def test_unsigned_bundle_refused(self):
        _, sub = self._pair()
        raw = json.dumps({"v": 1, "topic": "policies", "version": 1,
                          "payload": {}}).encode()
        self._refused(sub, raw, "poldist-signature-missing")

    def test_cross_topic_refused_before_sig_oracle(self):
        pub, _ = self._pair()
        sub = pd.Subscriber(topic="grants", pubkey=pub.pubkey)
        bundle = pub.sign_bundle("policies", 1, {"a": 1})
        self._refused(sub, bundle, "poldist-topic-cross")

    def test_rollback_refused(self):
        pub, sub = self._pair()
        b1 = pub.sign_bundle("policies", 1, {"a": 1})
        sub.apply(pub.sign_bundle("policies", 2, {"a": 2}))
        self._refused(sub, b1, "poldist-version-rollback")
        self.assertEqual(sub.version, 2)  # head unchanged

    def test_apply_never_raises_on_hostile_input(self):
        _, sub = self._pair()
        for hostile in (b"\xff\xfe", "not bytes", None, 42, b'[]',
                        b'{"v": 2, "topic": "policies"}'):
            res = sub.apply(hostile)
            self.assertEqual(res["outcome"], "refused")

    def test_apply_refuses_recursion_hostile_bundle_machine_coded(self):
        # F235: an UNSIGNED bundle nested far beyond the interpreter's
        # recursion budget must be refused with a machine code, never
        # raise RecursionError out of apply() (the "never raises on
        # hostile input" contract). Hand-crafted bytes, no json on the
        # attack side.
        _, sub = self._pair()
        depth = 30000
        raw = ('{"v":1,"topic":"policies","version":1,"payload":{"nest":'
               + "[" * depth + '"x"' + "]" * depth
               + '},"sig":"' + "0" * 128 + '"}').encode("utf-8")
        res = sub.apply(raw)  # must not raise
        self.assertEqual(res["outcome"], "refused")
        self.assertEqual(res["code"]["code"], "poldist-bundle-malformed")
        self.assertEqual(res["code"]["domain"], "poldist")

    def test_signed_deep_but_valid_bundle_still_applies(self):
        # The F235 fix must not bound legitimate depth: a validly
        # signed bundle nested deep (but within the interpreter's
        # recursion budget) still verifies and applies.
        pub, sub = self._pair()
        payload = "x"
        for _ in range(800):
            payload = [payload]
        res = sub.apply(pub.sign_bundle("policies", 1,
                                        {"nest": payload}))
        self.assertEqual(res["outcome"], "applied")
        self.assertEqual(res["version"], 1)

    def test_loaded_head_is_deep_copied(self):
        pub, sub = self._pair()
        payload = {"rules": ["a"]}
        sub.apply(pub.sign_bundle("policies", 1, payload))
        payload["rules"].append("MUTATED")
        self.assertEqual(sub.payload, {"rules": ["a"]})

    def test_subscriber_rejects_bad_construction(self):
        with self.assertRaises(ValueError):
            pd.Subscriber(topic="", pubkey=os.urandom(32))
        with self.assertRaises(ValueError):
            pd.Subscriber(topic="policies", pubkey=b"short")


class TaxonomyPinTests(unittest.TestCase):
    def test_pin(self):
        # Wave-260 lane 1: pin -> 1085 (+5 poldist-* codes).
        self.assertEqual(len(decision_codes.TAXONOMY), 1888)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*)
        for code in ("poldist-bundle-malformed", "poldist-signature-missing",
                     "poldist-signature-mismatch", "poldist-topic-cross",
                     "poldist-version-rollback"):
            self.assertIn(code, decision_codes.TAXONOMY)
            self.assertEqual(decision_codes.TAXONOMY[code]["domain"],
                             "poldist")

    def test_codes_emit(self):
        mc = decision_codes.emit("poldist-signature-mismatch",
                                 evidence_digests=("ab" * 32,),
                                 detail="probe")
        self.assertEqual(mc["code"], "poldist-signature-mismatch")
        self.assertFalse(mc["authority"])


if __name__ == "__main__":
    unittest.main()
