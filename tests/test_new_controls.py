"""Red-team tests for the Phase-3 hardening controls.

Covers the new controls that have no dedicated test elsewhere:
  R6: reserved log metadata cannot be forged by callers
  R6: verification fails under the wrong GOV_LOG_KEY
  R6: tail truncation is detected via signed checkpoints
  R6: log-emission failure blocks side effects (fail-closed logging)
  R4: read-before-send correlation queues with the read_before_send flag

These tests PASS on the hardened code; they guard the controls against
regression.
"""

import json
import os
import sys
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)
from gov.log import ActionLog, _active_key, verify_chain, read_entries


class TestReservedLogMetadata(unittest.TestCase):
    """R6: a caller must not be able to forge chain bookkeeping by smuggling
    reserved keys inside the event dict."""

    def test_reserved_fields_cannot_be_forged(self):
        ctx = make_run()
        log = ctx["log"]
        entry = log.append({
            "event": "tool_call",
            "seq": 999,
            "ts": "1900-01-01T00:00:00",
            "prev_hash": "FORGED",
            "hash": "FORGED",
            "format_version": 99,
            "key_epoch": "evil-epoch",
        })
        # F48 (R11): the executor logs policy_loaded + policy_pin_absent
        # at construction, wave-85 logs the ungoverned_bypass
        # declaration at seq 1, wave-158 (row 12) logs the
        # deployment_manifest_absent declaration, wave-175 logs the
        # invocation_receipts_disabled declaration (loud when no receipt
        # key is configured), and wave-176 logs the
        # decision_packet_disabled declaration (loud when no packet key
        # is configured) -- so the first test-appended entry is
        # seq 7.
        self.assertEqual(entry["seq"], 7)
        # F48 (R11): two construction entries precede (four with the
        # wave-85 and wave-158 declarations), so prev_hash chains from
        # previous entry — the forged "FORGED" value is overridden,
        # not GENESIS.
        prior = read_entries(log.path)[-2]
        self.assertEqual(entry["prev_hash"], prior["hash"])
        self.assertEqual(entry["format_version"], 1)
        _, epoch = _active_key()
        self.assertEqual(entry["key_epoch"], epoch)
        self.assertNotEqual(entry["hash"], "FORGED")
        ok, broken, count = verify_chain(log.path)
        self.assertTrue(ok, "chain must verify after forged-metadata attempt "
                            "(broken=%r)" % (broken,))


class TestWrongKeyDetection(unittest.TestCase):
    """R6: verification under a different GOV_LOG_KEY must fail."""

    def test_wrong_key_fails_verification(self):
        old_key = os.environ.get("GOV_LOG_KEY")
        old_epoch = os.environ.get("GOV_LOG_KEY_EPOCH")
        try:
            os.environ["GOV_LOG_KEY"] = "correct-key-for-this-test"
            os.environ["GOV_LOG_KEY_EPOCH"] = "test-epoch-1"
            ctx = make_run()
            ctx["executor"].call(
                ctx["mint_identity"]("k1", "support", "org"),
                "read_file", path="notes.txt")
            # One call = authorization entry + completion entry
            # (write-ahead); F48 (R11) adds policy_loaded +
            # policy_pin_absent at executor construction, wave-85
            # adds the ungoverned_bypass declaration at seq 1,
            # wave-158 (row 12) adds the deployment_manifest_absent
            # declaration, wave-175 adds the
            # invocation_receipts_disabled declaration (loud, no receipt
            # key configured), and wave-176 adds the
            # decision_packet_disabled declaration (loud, no packet key
            # configured) -- the manifest seam is default-on LOUD,
            # never silent.
            self.assertEqual(len(read_entries(ctx["run_dir"] / "actions.jsonl")), 8)

            os.environ["GOV_LOG_KEY"] = "attacker-guessed-key"
            ok, broken, count = verify_chain(ctx["run_dir"] / "actions.jsonl")
            self.assertFalse(ok, "verification under the wrong key must fail")
            self.assertEqual(broken, 1)
        finally:
            if old_key is None:
                os.environ.pop("GOV_LOG_KEY", None)
            else:
                os.environ["GOV_LOG_KEY"] = old_key
            if old_epoch is None:
                os.environ.pop("GOV_LOG_KEY_EPOCH", None)
            else:
                os.environ["GOV_LOG_KEY_EPOCH"] = old_epoch


class TestTailTruncation(unittest.TestCase):
    """R6: deleting the newest log line must be caught by the checkpoint."""

    def test_tail_truncation_detected(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["identities"]["support"]
        for _ in range(3):
            ex.call(ident, "read_file", path="notes.txt")
        log_path = ctx["run_dir"] / "actions.jsonl"
        lines = log_path.read_text(encoding="utf-8").splitlines()
        # One call = authorization entry + completion entry (write-ahead);
        # F48 (R11) adds policy_loaded + policy_pin_absent at construction;
        # wave-85 adds the ungoverned_bypass declaration at seq 1;
        # wave-158 (row 12) adds the deployment_manifest_absent
        # declaration; wave-175 adds the invocation_receipts_disabled
        # declaration (loud, no receipt key configured); wave-176 adds the
        # decision_packet_disabled declaration (loud, no packet key
        # configured).
        self.assertEqual(len(lines), 12)
        # Attacker truncates the tail (newest call's two entries).
        log_path.write_text("\n".join(lines[:10]) + "\n", encoding="utf-8")
        ok, broken, count = verify_chain(log_path)
        self.assertFalse(ok, "tail truncation must be detected")
        self.assertEqual(count, 10)


class TestFailClosedLogging(unittest.TestCase):
    """R6: if the log entry cannot be emitted, the side effect must not
    happen. The executor must raise rather than silently skipping the log."""

    def test_log_failure_blocks_side_effect(self):
        ctx = make_run()
        ex = ctx["executor"]
        coder = ctx["identities"]["coder"]

        def boom(event):
            raise IOError("simulated log outage")

        ex.log.append = boom
        target = ctx["run_dir"] / "sandbox" / "should_not_exist.txt"
        with self.assertRaises(IOError):
            ex.call(coder, "write_file", path="should_not_exist.txt",
                    content="x" * 40)
        self.assertFalse(target.exists(),
                         "side effect happened despite log failure: "
                         "logging is not fail-closed")


class TestReadBeforeSendCorrelation(unittest.TestCase):
    """R4: an outbound post carrying content previously read from a file is
    queued under the read-before-send rule with its flag, even to an
    allowlisted host."""

    def test_read_then_post_to_allowlisted_host_queued_with_flag(self):
        ctx = make_run()
        ex = ctx["executor"]
        researcher = ctx["identities"]["researcher"]

        secret = "customer record payload " + "X" * 64
        p = ctx["run_dir"] / "sandbox" / "records.txt"
        p.write_text(secret, encoding="utf-8")
        r1 = ex.call(researcher, "read_file", path="records.txt")
        self.assertEqual(r1["status"], "executed")

        r2 = ex.call(
            researcher,
            "http_post",
            url="https://hooks.synthetic.local/collect",
            payload={"records": secret},
        )
        self.assertEqual(
            r2["status"], "queued",
            "post carrying read content to an allowlisted host must be "
            "queued for review, not silently allowed (got %s)" % r2["status"])
        self.assertEqual(r2["policy_id"], "approval-read-before-send")
        entry = ctx["read_log"]()[-1]
        self.assertEqual(entry["flag"], "read_before_send")
        self.assertIn("provenance", entry)


class TestApprovalLifecycleEndToEnd(unittest.TestCase):
    """Regression test for a real end-to-end bug found during the Phase-3
    build: decide() logged the decision but never persisted it (the mutated
    record was dropped on rewrite), so approved actions silently never
    executed."""

    def test_approve_persists_and_executes(self):
        ctx = make_run()
        ex, q = ctx["executor"], ctx["approvals"]
        agent = ctx["mint_identity"]("pub-1", "publisher", "org")
        r = ex.call(
            agent, "send_email",
            to="reviewer@synthetic.local",
            subject="synthetic review request",
            body="Synthetic body.",
            agent_justification="please send",
        )
        self.assertEqual(r["status"], "queued")
        aid = r["approval_id"]

        rec, entry = q.decide(aid, True, "reviewed; synthetic recipient")
        self.assertEqual(rec["status"], "approved")
        # The decision must survive a fresh read of the queue file.
        reloaded = {x["id"]: x for x in q.all()}
        self.assertEqual(reloaded[aid]["status"], "approved",
                         "decide() must persist the decision to the queue file")
        self.assertEqual(reloaded[aid]["decided_by"], "human-operator")

        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["tool"], "send_email")
        final = {x["id"]: x for x in q.all()}[aid]
        self.assertTrue(final.get("executed"))
        decisions = [e["decision"] for e in ctx["read_log"]()]
        self.assertIn("approved_executed", decisions)
        # Second execution pass must be a no-op (no double execution).
        self.assertEqual(ex.execute_approved(), [])


if __name__ == "__main__":
    unittest.main()
