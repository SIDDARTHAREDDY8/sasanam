#!/usr/bin/env python3
"""Unit tests for action-capsule batch verification (wave-225 lane A).

Recompute-don't-assert: the verifier recomputes counts and derives
close state from the sealed items and links; issuer claims are
checked, never trusted. Independent spec-vector literals throughout
(no re-deriving expectations through the implementation).
"""

import unittest

from gov.action_capsule import (
    CapsuleError,
    chain_capsules,
    capsule_from_refusal,
    seal_capsule,
    verify_capsule,
    verify_capsule_batch,
)


def _admit():
    return seal_capsule({
        "attempt": {"action": "write_file",
                    "params_digest": "sha256:" + "a1" * 32},
        "effect": {"status": "admitted",
                   "evidence": "sha256:" + "b2" * 32,
                   "observed": "file written at 2026-09-30T04:00:00Z"},
    })


def _refusal():
    return capsule_from_refusal("permit-revoked", "sha256:" + "d4" * 32)


class BatchShapeTest(unittest.TestCase):
    def test_honest_batch_returns_commitment(self):
        a, r = _admit(), _refusal()
        out = verify_capsule_batch({"capsules": [a, r]})
        self.assertEqual(
            out["counts"],
            {"verdicts": 2, "refusal_capsules": 1, "links": 0})
        self.assertEqual(out["close_state"], "open")
        self.assertEqual(len(out["chain_digest"]), 64)
        self.assertEqual(out["capsule_digests"],
                         [a["capsule_digest"], r["capsule_digest"]])
        self.assertEqual(out["v"], 1)

    def test_batch_must_be_dict(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch([_admit()])
        self.assertEqual(cm.exception.code, "capsule-malformed")

    def test_capsules_must_be_list(self):
        with self.assertRaises(CapsuleError) as cm:
            chain_capsules("not-a-list")
        self.assertEqual(cm.exception.code, "capsule-malformed")

    def test_empty_batch_verifies(self):
        out = verify_capsule_batch({"capsules": []})
        self.assertEqual(
            out["counts"],
            {"verdicts": 0, "refusal_capsules": 0, "links": 0})
        self.assertEqual(out["close_state"], "open")


class RecomputeCountsTest(unittest.TestCase):
    def test_matching_claims_verify(self):
        out = verify_capsule_batch(
            {"capsules": [_admit(), _refusal()],
             "claimed_counts": {"verdicts": 2,
                                "refusal_capsules": 1,
                                "links": 0}})
        self.assertEqual(out["counts"]["verdicts"], 2)

    def test_inflated_verdict_count_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()],
                 "claimed_counts": {"verdicts": 2}})
        self.assertEqual(cm.exception.code, "capsule-count-mismatch")

    def test_hidden_refusal_count_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit(), _refusal()],
                 "claimed_counts": {"refusal_capsules": 0}})
        self.assertEqual(cm.exception.code, "capsule-count-mismatch")

    def test_partial_claims_checked(self):
        # Only the claimed keys are checked; unclaimed keys are not
        # trusted away either — they are recomputed and returned.
        out = verify_capsule_batch(
            {"capsules": [_admit(), _refusal()],
             "claimed_counts": {"verdicts": 2}})
        self.assertEqual(out["counts"]["refusal_capsules"], 1)

    def test_unknown_count_key_fails_closed(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()],
                 "claimed_counts": {"verdicts": 1, "bribes": 0}})
        self.assertEqual(cm.exception.code, "capsule-unknown-field")

    def test_negative_count_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()],
                 "claimed_counts": {"verdicts": -1}})
        self.assertEqual(cm.exception.code, "capsule-malformed")

    def test_bool_count_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()],
                 "claimed_counts": {"verdicts": True}})
        self.assertEqual(cm.exception.code, "capsule-malformed")


class CloseStateTest(unittest.TestCase):
    def test_open_derived_with_no_links(self):
        out = chain_capsules([_admit()])
        self.assertEqual(out["close_state"], "open")

    def test_acknowledges_derives_closed_acknowledged(self):
        a = _admit()
        out = chain_capsules(
            [a], [{"kind": "acknowledges",
                   "target_capsule_digest": a["capsule_digest"]}])
        self.assertEqual(out["close_state"], "closed-acknowledged")

    def test_rebuts_derives_closed_rebutted(self):
        a = _admit()
        out = chain_capsules(
            [a], [{"kind": "rebuts",
                   "target_capsule_digest": a["capsule_digest"]}])
        self.assertEqual(out["close_state"], "closed-rebutted")

    def test_matching_close_claim_verifies(self):
        a = _admit()
        out = verify_capsule_batch(
            {"capsules": [a],
             "links": [{"kind": "acknowledges",
                        "target_capsule_digest": a["capsule_digest"]}],
             "claimed_close_state": "closed-acknowledged"})
        self.assertEqual(out["close_state"], "closed-acknowledged")

    def test_mismatched_close_claim_refused(self):
        a = _admit()
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [a],
                 "links": [{"kind": "acknowledges",
                            "target_capsule_digest":
                                a["capsule_digest"]}],
                 "claimed_close_state": "open"})
        self.assertEqual(cm.exception.code,
                         "capsule-closestate-mismatch")

    def test_unknown_close_state_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()],
                 "claimed_close_state": "closed-by-decree"})
        self.assertEqual(cm.exception.code, "capsule-malformed")


class LinkTamperTest(unittest.TestCase):
    def test_unknown_link_kind_refused(self):
        a = _admit()
        with self.assertRaises(CapsuleError) as cm:
            chain_capsules(
                [a], [{"kind": "disputes",
                       "target_capsule_digest":
                           a["capsule_digest"]}])
        self.assertEqual(cm.exception.code, "capsule-malformed")

    def test_link_to_missing_capsule_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            chain_capsules(
                [_admit()], [{"kind": "acknowledges",
                              "target_capsule_digest": "00" * 32}])
        self.assertEqual(cm.exception.code, "capsule-digest-mismatch")

    def test_link_missing_target_refused(self):
        with self.assertRaises(CapsuleError) as cm:
            chain_capsules([_admit()], [{"kind": "acknowledges"}])
        self.assertEqual(cm.exception.code, "capsule-malformed")

    def test_link_extra_field_fails_closed(self):
        a = _admit()
        with self.assertRaises(CapsuleError) as cm:
            chain_capsules(
                [a], [{"kind": "acknowledges",
                       "target_capsule_digest":
                           a["capsule_digest"],
                       "forged": True}])
        self.assertEqual(cm.exception.code, "capsule-unknown-field")

    def test_tampered_capsule_in_batch_refused(self):
        a = _admit()
        tampered = dict(a)
        tampered["jcs_json"] = a["jcs_json"].replace(
            "write_file", "write_fileX")
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch({"capsules": [tampered]})
        self.assertEqual(cm.exception.code, "capsule-digest-mismatch")

    def test_link_is_replayed_after_capsule_tamper(self):
        # Digest-first ordering: a tampered capsule refuses on the
        # capsule digest, not on a count claim, because verification
        # runs before claim comparison.
        a = _admit()
        tampered = dict(a)
        tampered["capsule_digest"] = "ff" * 32
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [tampered],
                 "claimed_counts": {"verdicts": 1}})
        self.assertEqual(cm.exception.code, "capsule-digest-mismatch")


class BatchHygieneTest(unittest.TestCase):
    def test_unknown_batch_field_fails_closed(self):
        with self.assertRaises(CapsuleError) as cm:
            verify_capsule_batch(
                {"capsules": [_admit()], "bogus": 1})
        self.assertEqual(cm.exception.code, "capsule-unknown-field")

    def test_chain_digest_is_deterministic(self):
        a, r = _admit(), _refusal()
        first = chain_capsules([a, r])["chain_digest"]
        second = chain_capsules([a, r])["chain_digest"]
        self.assertEqual(first, second)

    def test_chain_digest_binds_order(self):
        a, r = _admit(), _refusal()
        self.assertNotEqual(
            chain_capsules([a, r])["chain_digest"],
            chain_capsules([r, a])["chain_digest"])


if __name__ == "__main__":
    unittest.main()
