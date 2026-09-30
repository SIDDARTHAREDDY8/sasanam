"""Unit tests for the W242-8 AEE parity probe helpers.

Covers the pure functions in evals/w242_aee_refusal_vector.py (RFC 8785
canonicalization, DSSE PAE, RFC 6962 Merkle root) and the failure-set
re-derivation in evals/w242_aee_parity_probes.py. The corpus-dependent
probes themselves run against the reference checker binary and corpus;
these tests pin the byte-level machinery they rely on.
"""

import base64
import hashlib
import json
import os
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "evals"))

import w242_aee_refusal_vector as rv
import w242_aee_parity_probes as probes

CORPUS_VECTORS = os.environ.get(
    "W242_AEE_CORPUS", "/tmp/aee-conformance"
) + "/vectors"


class TestCanonicalBytes(unittest.TestCase):
    def test_sorts_keys_and_removes_whitespace(self):
        self.assertEqual(
            rv.canonical_bytes({"b": 1, "a": [True, None]}),
            b'{"a":[true,null],"b":1}',
        )

    def test_byte_exact_on_corpus_record_payloads(self):
        # The reference checker rejects payload bytes that are not in RFC
        # 8785 canonical form; our serializer must reproduce the corpus's
        # own bytes exactly or every authored vector dies at stage one.
        if not os.path.isdir(CORPUS_VECTORS):
            self.skipTest("corpus not present")
        stmt = json.load(
            open(
                os.path.join(
                    CORPUS_VECTORS, "statements", "vcf20eae7df4f1f1b.json"
                )
            )
        )
        for rec in stmt["predicate"]["observationRecords"]:
            original = base64.b64decode(rec["payload"])
            parsed = json.loads(original.decode())
            self.assertEqual(
                rv.canonical_bytes(parsed),
                original,
                f"canonical form mismatch for {rec['payloadType']}",
            )

    def test_rejects_unsupported_types(self):
        with self.assertRaises(ValueError):
            rv.canonical_bytes(1.5)

    def test_bool_is_not_int(self):
        # True must serialize as "true", not "1".
        self.assertEqual(rv.canonical_bytes(True), b"true")


class TestPaeAndMerkle(unittest.TestCase):
    def test_pae_shape(self):
        out = rv.pae("application/vnd.x+json", b'{"a":1}')
        self.assertTrue(out.startswith(b"DSSEv1 "))
        self.assertIn(b"application/vnd.x+json", out)
        self.assertTrue(out.endswith(b'{"a":1}'))

    def test_leaf_hash_is_rfc6962(self):
        preimage = b"hello"
        self.assertEqual(
            rv.leaf_hash(preimage), hashlib.sha256(b"\x00" + preimage).digest()
        )

    def test_merkle_root_single_leaf(self):
        leaf = b"\x01" * 32
        self.assertEqual(rv.merkle_root([leaf]), leaf)

    def test_merkle_root_two_leaves(self):
        l1, l2 = b"\x01" * 32, b"\x02" * 32
        self.assertEqual(
            rv.merkle_root([l1, l2]), hashlib.sha256(b"\x01" + l1 + l2).digest()
        )

    def test_merkle_root_three_leaves_splits_2_1(self):
        # RFC 6962 largest-power-of-two-below split: ((l1,l2),l3).
        l1, l2, l3 = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
        left = hashlib.sha256(b"\x01" + l1 + l2).digest()
        expected = hashlib.sha256(b"\x01" + left + l3).digest()
        self.assertEqual(rv.merkle_root([l1, l2, l3]), expected)

    def test_test_seed_recipe(self):
        self.assertEqual(
            rv.test_seed("substrate-observation-test"),
            hashlib.sha256(
                b"in-toto-aee-test-key/substrate-observation-test/v1"
            ).digest(),
        )


class TestExpectedCleanFailures(unittest.TestCase):
    def _payload(self, **kw):
        base = {
            "aeeStillArmed": True,
            "aeeDropCount": 0,
            "aeePostureDigest": "a" * 64,
        }
        base.update(kw)
        return base

    def test_clean_record_no_failures(self):
        self.assertEqual(
            probes.expected_clean_failures(self._payload(), "a" * 64, []), []
        )

    def test_still_armed_false_named(self):
        failures = probes.expected_clean_failures(
            self._payload(aeeStillArmed=False), "a" * 64, []
        )
        self.assertEqual(failures, ["aeeStillArmed is false"])

    def test_drops_without_bound_named(self):
        failures = probes.expected_clean_failures(
            self._payload(aeeDropCount=1), "a" * 64, []
        )
        self.assertEqual(
            failures,
            ["aeeDropCount is non-zero and exceeds its aeeDropBound, or declares no bound"],
        )

    def test_drops_within_bound_not_a_failure(self):
        self.assertEqual(
            probes.expected_clean_failures(
                self._payload(aeeDropCount=2, aeeDropBound=5), "a" * 64, []
            ),
            [],
        )

    def test_posture_mismatch_named(self):
        failures = probes.expected_clean_failures(
            self._payload(aeePostureDigest="b" * 64), "a" * 64, []
        )
        self.assertEqual(
            failures,
            ["aeePostureDigest differs from the pinned networkPosture digest"],
        )

    def test_every_failing_conjunct_reported_not_just_first(self):
        # The head rule's whole point: no short-circuit hiding failures.
        failures = probes.expected_clean_failures(
            self._payload(aeeStillArmed=False, aeePostureDigest="b" * 64),
            "a" * 64,
            [],
        )
        self.assertEqual(len(failures), 2)
        self.assertIn("aeeStillArmed is false", failures)
        self.assertIn(
            "aeePostureDigest differs from the pinned networkPosture digest",
            failures,
        )

    def test_arming_conjunct_empty_operand_set_not_named(self):
        # all() over an empty set is vacuous: the comparison decides nothing
        # and must not be named.
        failures = probes.expected_clean_failures(
            self._payload(aeePostureDigest="b" * 64), "a" * 64, []
        )
        self.assertNotIn(
            "arming record",
            " ".join(failures),
        )

    def test_arming_conjunct_divergent_named_with_row_set(self):
        failures = probes.expected_clean_failures(
            self._payload(aeePostureDigest="b" * 64), "b" * 64, ["c" * 64]
        )
        self.assertEqual(
            failures,
            [
                "aeePostureDigest differs from the aeePostureDigest of the "
                "1 arming record the rows resolve"
            ],
        )

    def test_arming_conjunct_agreeing_not_named(self):
        failures = probes.expected_clean_failures(
            self._payload(aeePostureDigest="b" * 64), "a" * 64, ["b" * 64]
        )
        self.assertEqual(
            failures,
            ["aeePostureDigest differs from the pinned networkPosture digest"],
        )


if __name__ == "__main__":
    unittest.main()
