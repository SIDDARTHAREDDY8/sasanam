#!/usr/bin/env python3
"""Unit tests for gov/consumption_ledger.py (wave-234 lane C).

At-most-once consumption keyed to frozen-instance digests, with
entity-bound idempotency keys, write-ahead journal commits, and an
additive single-use adapter. Deterministic; no network; stdlib only.
"""

import hashlib
import json
import os
import tempfile
import unittest

from gov import consumption_ledger as cl
from gov import single_use as su


def _digest(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True).encode("utf-8")).hexdigest()


class BuildKeyTest(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(
            cl.build_idempotency_key("approval", "tool", "git", "r1"),
            cl.build_idempotency_key("approval", "tool", "git", "r1"))

    def test_entity_bound(self):
        # Same raw tail, different entity: no collision (EMILIA lesson).
        self.assertNotEqual(
            cl.build_idempotency_key("approval", "tool", "git", "r1"),
            cl.build_idempotency_key("approval", "tool", "ssh", "r1"))

    def test_order_sensitive(self):
        self.assertNotEqual(
            cl.build_idempotency_key("a", "bc"),
            cl.build_idempotency_key("ab", "c"))

    def test_length_prefix_disambiguates(self):
        # Without length-prefixing ("ab"+"c") would equal ("a"+"bc").
        self.assertNotEqual(
            cl.build_idempotency_key("x", "ab", "c"),
            cl.build_idempotency_key("x", "a", "bc"))

    def test_rejects_short_and_bad_parts(self):
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.build_idempotency_key("only-one")
        self.assertEqual(ctx.exception.code, "consumption-key-malformed")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.build_idempotency_key("a", "")
        self.assertEqual(ctx.exception.code, "consumption-key-malformed")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.build_idempotency_key("a", 42)
        self.assertEqual(ctx.exception.code, "consumption-key-malformed")


class ConsumeTest(unittest.TestCase):
    def setUp(self):
        self.ledger = cl.ConsumptionLedger()
        self.parts = ("approval", "tool", "git", "r1")

    def test_first_consume_returns_receipt(self):
        d = _digest({"approval_id": "a1"})
        receipt = self.ledger.consume(d, self.parts)
        self.assertEqual(receipt["outcome"], "consumed")
        self.assertEqual(receipt["instance_digest"], d)
        self.assertEqual(len(receipt["receipt_digest"]), 64)
        self.assertTrue(self.ledger.is_consumed(d))

    def test_replay_named_outcome_carries_original_receipt(self):
        d = _digest({"approval_id": "a2"})
        first = self.ledger.consume(d, self.parts)
        with self.assertRaises(cl.ConsumptionError) as ctx:
            self.ledger.consume(d, self.parts)
        self.assertEqual(ctx.exception.code, "previously-consumed")
        self.assertEqual(ctx.exception.receipt, first)

    def test_replay_with_different_key_parts_still_previously_consumed(self):
        # The instance is consumed; key parts are irrelevant on replay.
        d = _digest({"approval_id": "a3"})
        self.ledger.consume(d, self.parts)
        with self.assertRaises(cl.ConsumptionError) as ctx:
            self.ledger.consume(d, ("approval", "tool", "git", "other"))
        self.assertEqual(ctx.exception.code, "previously-consumed")

    def test_idempotency_reuse_refused(self):
        d1 = _digest({"approval_id": "a4"})
        d2 = _digest({"approval_id": "a5"})
        self.ledger.consume(d1, self.parts)
        with self.assertRaises(cl.ConsumptionError) as ctx:
            self.ledger.consume(d2, self.parts)
        self.assertEqual(ctx.exception.code,
                         "consumption-idempotency-reused")
        self.assertTrue(self.ledger.is_consumed(d1))
        self.assertFalse(self.ledger.is_consumed(d2))

    def test_malformed_digest(self):
        for bad in ("nope", "AB" * 32, "sha256:" + "ab" * 32, "", None, 42):
            with self.assertRaises(cl.ConsumptionError) as ctx:
                self.ledger.consume(bad, self.parts)
            self.assertEqual(ctx.exception.code,
                             "consumption-instance-malformed")

    def test_malformed_key_parts(self):
        d = "ab" * 32
        with self.assertRaises(cl.ConsumptionError) as ctx:
            self.ledger.consume(d, "not-a-tuple")
        self.assertEqual(ctx.exception.code, "consumption-key-malformed")

    def test_base_class_carries_no_product_code(self):
        # The w228 vocabulary scanner must see only real codes.
        self.assertIsNone(cl.ConsumptionError.code)


class ReceiptTest(unittest.TestCase):
    def test_verify_round_trip(self):
        ledger = cl.ConsumptionLedger()
        d = _digest({"approval_id": "r1"})
        receipt = ledger.consume(d, ("approval", "tool", "git", "r2"))
        self.assertTrue(cl.ConsumptionLedger.verify_receipt(receipt))
        self.assertEqual(ledger.consumption_receipt(d), receipt)

    def test_tampered_refused(self):
        ledger = cl.ConsumptionLedger()
        d = _digest({"approval_id": "r2"})
        receipt = ledger.consume(d, ("approval", "tool", "git", "r3"))
        bad = dict(receipt)
        bad["consumed_at"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger.verify_receipt(bad)
        self.assertEqual(ctx.exception.code, "consumption-receipt-tampered")

    def test_malformed_refused(self):
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger.verify_receipt({"version": 1})
        self.assertEqual(ctx.exception.code, "consumption-receipt-malformed")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger.verify_receipt("nope")
        self.assertEqual(ctx.exception.code, "consumption-receipt-malformed")


class JournalTest(unittest.TestCase):
    def test_restart_reads_consumed(self):
        tmp = tempfile.mkdtemp(prefix="cl-test-")
        journal = os.path.join(tmp, "j.jsonl")
        d = _digest({"approval_id": "j1"})
        parts = ("approval", "tool", "git", "jr1")
        first = cl.ConsumptionLedger(journal_path=journal)
        r1 = first.consume(d, parts)
        second = cl.ConsumptionLedger(journal_path=journal)
        self.assertTrue(second.is_consumed(d))
        self.assertEqual(second.consumption_receipt(d)["receipt_digest"],
                         r1["receipt_digest"])
        with self.assertRaises(cl.ConsumptionError) as ctx:
            second.consume(d, parts)
        self.assertEqual(ctx.exception.code, "previously-consumed")

    def test_corrupt_journal_fails_closed(self):
        tmp = tempfile.mkdtemp(prefix="cl-test-")
        journal = os.path.join(tmp, "j.jsonl")
        with open(journal, "w", encoding="utf-8") as fh:
            fh.write("not json\n")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger(journal_path=journal)
        self.assertEqual(ctx.exception.code, "consumption-journal-unusable")

    def test_tampered_journal_line_fails_closed(self):
        tmp = tempfile.mkdtemp(prefix="cl-test-")
        journal = os.path.join(tmp, "j.jsonl")
        d = _digest({"approval_id": "j2"})
        ledger = cl.ConsumptionLedger(journal_path=journal)
        receipt = ledger.consume(d, ("approval", "tool", "git", "jr2"))
        bad = dict(receipt)
        bad["instance_digest"] = "ff" * 32
        with open(journal, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(bad) + "\n")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger(journal_path=journal)
        self.assertEqual(ctx.exception.code, "consumption-journal-unusable")

    def test_journal_directory_fails_closed(self):
        tmp = tempfile.mkdtemp(prefix="cl-test-")
        with self.assertRaises(cl.ConsumptionError) as ctx:
            cl.ConsumptionLedger(journal_path=tmp)
        self.assertEqual(ctx.exception.code, "consumption-journal-unusable")


class AdapterTest(unittest.TestCase):
    def test_adapter_wires_without_changing_registry(self):
        tmp = tempfile.mkdtemp(prefix="cl-test-")
        journal = os.path.join(tmp, "j.jsonl")
        reg = su.SingleUseRegistry()
        ledger = cl.ConsumptionLedger(journal_path=journal)
        adapter = cl.SingleUseConsumptionAdapter(reg, ledger)
        att = hashlib.sha256(b"att-a").hexdigest()
        record = reg.issue(att, "issuer-a", "nonce-a")
        receipt, evidence = adapter.consume_attestation(record)
        self.assertEqual(evidence["kind"], "single-use-attestation")
        self.assertEqual(evidence["jti"], record["jti"])
        self.assertEqual(receipt["outcome"], "consumed")
        # Registry semantics unchanged: second consume is a replay.
        with self.assertRaises(su.SingleUseError) as ctx:
            reg.consume(record)
        self.assertEqual(ctx.exception.code, "single-use-replay-refused")
        # But the adapter refuses at the ledger first (persistent).
        with self.assertRaises(cl.ConsumptionError) as ctx:
            adapter.consume_attestation(record)
        self.assertEqual(ctx.exception.code, "previously-consumed")


if __name__ == "__main__":
    unittest.main()
