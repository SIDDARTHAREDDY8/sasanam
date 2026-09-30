"""Unit tests for gov/seeded_denials.py (wave-231 lane B).

Pin tests assert the refusal-code strings and record field shape
against known literals (independent source of truth: the refusal
vocabulary), not by recomputing the module's own logic.
"""

import hashlib
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import seeded_denials as sd  # noqa: E402


def _d(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _seed(**over):
    kw = {
        "decision_digest": _d("decision-1"),
        "deny_reason_code": "hybrid-suite-not-accepted",
        "rule_path": "policy/default/hybrid-gate",
        "log_head_digest": _d("log-head"),
        "receipt_digest": _d("receipt-1"),
    }
    kw.update(over)
    return sd.seed_denial(**kw)


class ShapeTest(unittest.TestCase):
    def test_record_has_exact_fields(self):
        rec = _seed()
        self.assertEqual(
            set(rec),
            {"v", "kind", "decision_digest", "deny_reason_code",
             "rule_path", "anchor", "denied_txn_head",
             "receipt_digest", "receipt_less_reason", "digest"})
        self.assertEqual(rec["v"], 1)
        self.assertEqual(rec["kind"], "seeded-denial")
        self.assertEqual(rec["anchor"], _d("log-head"))
        self.assertIsNone(rec["denied_txn_head"])
        self.assertIsNone(rec["receipt_less_reason"])

    def test_receipt_less_record_shape(self):
        rec = _seed(receipt_digest=None,
                    receipt_unavailable_cause="no-intent-evidence")
        self.assertEqual(rec["kind"], "receipt-less-denial")
        self.assertIsNone(rec["receipt_digest"])
        self.assertEqual(rec["receipt_less_reason"],
                         "denial-receipt-unavailable-no-intent-evidence")

    def test_digest_stable_and_recomputable(self):
        rec = _seed()
        self.assertEqual(rec["digest"], sd.record_digest(rec))
        # Independent recomputation: domain-separated SHA-256 over
        # canonical JSON of the body.
        import json
        body = {k: v for k, v in rec.items() if k != "digest"}
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        expect = hashlib.sha256(
            b"gov-seeded-denial/v1" + b"\x00" + blob).hexdigest()
        self.assertEqual(rec["digest"], expect)


class RefusalCodePinTest(unittest.TestCase):
    def test_error_code_strings(self):
        cases = [
            (sd.DenialAnchoredInTransaction,
             "denial-anchored-in-denied-transaction"),
            (sd.DenialEvidenceLost, "denial-evidence-lost"),
            (sd.DenialMalformed, "seeded-denial-malformed"),
            (sd.DenialDigestMismatch, "seeded-denial-digest-mismatch"),
            (sd.DenialNotAuthority, "seeded-denial-not-authorization"),
            (sd.SeededDenialError, "seeded-denial-refused"),
        ]
        for cls, code in cases:
            self.assertEqual(cls.code, code)


class AnchorTest(unittest.TestCase):
    def test_outside_anchor_verifies(self):
        rec = _seed()
        out = sd.verify_denial(rec, denied_txn_digests={_d("t1"), _d("t2")})
        self.assertTrue(out["ok"])
        self.assertEqual(out["anchor"], _d("log-head"))

    def test_inside_anchor_refused(self):
        head = _d("log-head")
        rec = _seed(log_head_digest=head)
        with self.assertRaises(sd.DenialAnchoredInTransaction) as ctx:
            sd.verify_denial(rec, denied_txn_digests={head, _d("t2")})
        self.assertEqual(ctx.exception.code,
                         "denial-anchored-in-denied-transaction")

    def test_non_hex_anchor_refused_at_seed(self):
        with self.assertRaises(sd.DenialMalformed) as ctx:
            _seed(log_head_digest="not-a-digest")
        self.assertEqual(ctx.exception.code, "seeded-denial-malformed")


class ReceiptLessTest(unittest.TestCase):
    def test_receipt_and_cause_together_refused(self):
        with self.assertRaises(sd.DenialMalformed) as ctx:
            _seed(receipt_digest=_d("r"),
                  receipt_unavailable_cause="no-intent-evidence")
        self.assertEqual(ctx.exception.code, "seeded-denial-malformed")

    def test_no_receipt_no_cause_refused(self):
        with self.assertRaises(sd.DenialMalformed) as ctx:
            _seed(receipt_digest=None)
        self.assertEqual(ctx.exception.code, "seeded-denial-malformed")

    def test_none_is_never_evidence(self):
        with self.assertRaises(sd.DenialMalformed) as ctx:
            sd.verify_denial(None, denied_txn_digests=set())
        self.assertEqual(ctx.exception.code, "seeded-denial-malformed")


class RollbackTest(unittest.TestCase):
    def _log(self):
        return [
            {"seq": 1, "hash": _d("e1")},
            {"seq": 2, "hash": _d("e2")},
        ]

    def test_commit_found_survives(self):
        rec = _seed(log_head_digest=_d("e2"))
        entry = sd.denial_commit_entry(rec)
        entry = dict(entry, seq=3, prev_hash=_d("e2"))
        out = sd.denial_survives_rollback(
            rec, post_rollback_entries=self._log() + [entry])
        self.assertTrue(out["ok"])
        self.assertEqual(out["seq"], 3)

    def test_commit_lost_refused(self):
        rec = _seed(log_head_digest=_d("e2"))
        with self.assertRaises(sd.DenialEvidenceLost) as ctx:
            sd.denial_survives_rollback(
                rec, post_rollback_entries=self._log())
        self.assertEqual(ctx.exception.code, "denial-evidence-lost")


class TamperTest(unittest.TestCase):
    def test_field_flip_refused(self):
        rec = _seed()
        bad = dict(rec)
        bad["decision_digest"] = _d("other-decision")
        with self.assertRaises(sd.DenialDigestMismatch) as ctx:
            sd.verify_denial(bad, denied_txn_digests=set())
        self.assertEqual(ctx.exception.code,
                         "seeded-denial-digest-mismatch")

    def test_unknown_field_refused(self):
        rec = _seed()
        bad = dict(rec)
        bad["extra"] = "field"
        with self.assertRaises(sd.DenialMalformed) as ctx:
            sd.verify_denial(bad, denied_txn_digests=set())
        self.assertEqual(ctx.exception.code, "seeded-denial-malformed")

    def test_denial_not_authority(self):
        rec = _seed()
        with self.assertRaises(sd.DenialNotAuthority) as ctx:
            sd.denial_as_authority(rec)
        self.assertEqual(ctx.exception.code,
                         "seeded-denial-not-authorization")


if __name__ == "__main__":
    unittest.main()
