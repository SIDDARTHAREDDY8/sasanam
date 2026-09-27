"""Cross-run intent ledger unit tests (wave-134, row-7 third half).

Covers the public seams of gov/intent_ledger.py (record_intent /
latest_countermands / messages_since / messages_with_context /
verify_chain / save / load) and the executor wiring
(record_intent_turn, intent_ledger kwarg, execution-boundary
cross-run countermand check).

Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
GOV_DEPLOYMENT_MODE=staging. No env scrubbing here (tearDown never
touches key env vars).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import make_run  # noqa: E402
from gov import revoke as revoke_mod  # noqa: E402
from gov.policy import PolicyDecision  # noqa: E402
from gov.intent_ledger import (  # noqa: E402
    IntentLedger, IntentPersistenceError, INTENT_LEDGER_VERSION)


def _tmp():
    d = tempfile.mkdtemp(prefix="intent-ledger-test-")
    return d


class RecordSeamTest(unittest.TestCase):
    def test_record_returns_chained_record(self):
        led = IntentLedger()
        r = led.record_intent("op", "do the thing")
        self.assertEqual(r["principal"], "op")
        self.assertEqual(r["message"], "do the thing")
        self.assertFalse(r["is_countermand"])
        self.assertTrue(r["record_digest"])
        self.assertEqual(r["prev_record_digest"], "")
        r2 = led.record_intent("op", "do the other thing")
        self.assertEqual(r2["prev_record_digest"], r["record_digest"])

    def test_record_rejects_empty_principal_or_message(self):
        led = IntentLedger()
        with self.assertRaises(ValueError):
            led.record_intent("", "hello")
        with self.assertRaises(ValueError):
            led.record_intent("op", "   ")
        with self.assertRaises(ValueError):
            led.record_intent("op", "hello", verdict="not-a-dict")

    def test_record_rejects_unparseable_ts(self):
        led = IntentLedger()
        with self.assertRaises(ValueError):
            led.record_intent("op", "hello", ts="not-a-time")

    def test_detector_marks_countermand(self):
        led = IntentLedger()
        led.record_intent("op", "send the report to team@example.com")
        r = led.record_intent(
            "op", "actually do not send anything to team@example.com")
        self.assertTrue(r["is_countermand"])
        self.assertTrue(r["detector_countermand"])
        self.assertFalse(r["verdict_countermand"])

    def test_verdict_marks_countermand_without_detector_overlap(self):
        led = IntentLedger()
        r = led.record_intent("op", "noted",
                              verdict={"flagged": True,
                                       "flag": "stale_intent"})
        self.assertTrue(r["is_countermand"])
        self.assertFalse(r["detector_countermand"])
        self.assertTrue(r["verdict_countermand"])

    def test_countermand_needs_prior_instruction(self):
        # A lone "don't do X" with no prior instruction from this
        # principal is not a countermand of anything.
        led = IntentLedger()
        r = led.record_intent("op", "do not send anything")
        self.assertFalse(r["is_countermand"])

    def test_audit_events(self):
        seen = []
        led = IntentLedger(audit=seen.append)
        led.record_intent("op", "send the report to team@example.com")
        led.record_intent("op",
                          "actually do not send to team@example.com")
        self.assertEqual(seen[0]["event"], "intent_turn_recorded")
        self.assertEqual(seen[1]["event"], "intent_countermand_recorded")
        self.assertEqual(seen[1]["flag"], "intent_countermand")


class QuerySeamTest(unittest.TestCase):
    def _ledger(self):
        led = IntentLedger()
        led.record_intent("op", "first instruction",
                          ts="2026-09-27T10:00:00+00:00")
        led.record_intent("op", "do not do the first instruction",
                          ts="2026-09-27T11:00:00+00:00")
        led.record_intent("other", "do not do the first instruction",
                          ts="2026-09-27T11:30:00+00:00")
        led.record_intent("op", "status update",
                          ts="2026-09-27T12:00:00+00:00")
        return led

    def test_latest_countermands_temporal_and_principal(self):
        led = self._ledger()
        cms = led.latest_countermands("op", "2026-09-27T10:30:00+00:00")
        self.assertEqual(len(cms), 1)
        self.assertTrue(cms[0]["is_countermand"])
        # The other principal's record never bleeds over.
        self.assertEqual(
            led.latest_countermands("other", "2026-09-27T10:30:00+00:00"),
            [])
        # A later anchor excludes everything.
        self.assertEqual(
            led.latest_countermands("op", "2026-09-27T12:30:00+00:00"),
            [])

    def test_latest_countermands_fail_safe_on_bad_anchor(self):
        led = self._ledger()
        self.assertEqual(led.latest_countermands("op", "garbage"), [])
        self.assertEqual(led.latest_countermands("op", None), [])

    def test_messages_since(self):
        led = self._ledger()
        msgs = led.messages_since("op", "2026-09-27T10:30:00+00:00")
        self.assertEqual(msgs, ["do not do the first instruction",
                                "status update"])

    def test_messages_with_context(self):
        led = self._ledger()
        ctx = led.messages_with_context("op", "2026-09-27T10:30:00+00:00",
                                        prior=1)
        self.assertEqual(ctx, ["first instruction",
                               "do not do the first instruction",
                               "status update"])
        # No prior turn available: context starts at the first known.
        ctx2 = led.messages_with_context("op", "2026-09-27T09:00:00+00:00",
                                         prior=1)
        self.assertEqual(ctx2[0], "first instruction")
        # Principal isolation.
        self.assertEqual(
            led.messages_with_context("other", "2026-09-27T10:30:00+00:00",
                                      prior=1),
            ["do not do the first instruction"])

    def test_messages_with_context_prior_none_keeps_all_before(self):
        # F181: prior=None means ALL messages at-or-before `since`
        # travel with the later turns (the granting instruction can
        # never be evicted by intervening chatter).
        led = self._ledger()
        ctx = led.messages_with_context("op", "2026-09-27T10:30:00+00:00",
                                        prior=None)
        self.assertEqual(ctx, ["first instruction",
                               "do not do the first instruction",
                               "status update"])
        # Default (prior=1) keeps only the last pre-since turn.
        ctx1 = led.messages_with_context("op", "2026-09-27T10:30:00+00:00")
        self.assertEqual(ctx1[0], "first instruction")
        ctx1b = led.messages_with_context("op",
                                          "2026-09-27T11:30:00+00:00")
        self.assertEqual(ctx1b, ["do not do the first instruction",
                                 "status update"])
        # prior=None with no turns at-or-before since: just the later.
        ctx2 = led.messages_with_context("op", "2026-09-27T09:00:00+00:00",
                                         prior=None)
        self.assertEqual(ctx2[0], "first instruction")


class PersistenceTest(unittest.TestCase):
    def test_save_load_round_trip_continues_chain(self):
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        led = IntentLedger()
        led.record_intent("op", "send the report to team@example.com")
        led.save(p)
        led2 = IntentLedger.load(p)
        ok, _ = led2.verify_chain()
        self.assertTrue(ok)
        led2.record_intent("op", "actually do not send to team@example.com")
        ok, _ = led2.verify_chain()
        self.assertTrue(ok)
        # The re-saved file still verifies (chain tip carried over).
        led2.save(p)
        led3 = IntentLedger.load(p)
        ok, _ = led3.verify_chain()
        self.assertTrue(ok)
        self.assertEqual(len(led3._turns), 2)

    def test_empty_ledger_round_trip(self):
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        led = IntentLedger()
        led.save(p)
        led2 = IntentLedger.load(p)
        ok, _ = led2.verify_chain()
        self.assertTrue(ok)
        self.assertEqual(led2._turns, [])

    def test_tampered_payload_fails_closed(self):
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        led = IntentLedger()
        led.record_intent("op", "send the report")
        led.save(p)
        raw = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(
            raw.replace("send the report", "send the REPORT", 1))
        with self.assertRaises(IntentPersistenceError):
            IntentLedger.load(p)

    def test_truncated_file_fails_closed(self):
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write('{"record_type":"intent_ledger_header"}\n')
        with self.assertRaises(IntentPersistenceError):
            IntentLedger.load(p)

    def test_missing_file_fails_closed(self):
        with self.assertRaises(IntentPersistenceError):
            IntentLedger.load("/nonexistent-dir-x/ledger.jsonl")

    def test_chain_tip_mismatch_fails_closed(self):
        # Forge a file whose file_digest is CONSISTENT (recomputed)
        # but whose header chain_tip no longer matches the stored
        # chain: the load must still fail closed on the tip check.
        import hashlib
        import json
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        led = IntentLedger()
        led.record_intent("op", "one")
        led.save(p)
        lines = [ln for ln in open(p, encoding="utf-8").read().splitlines()
                 if ln.strip()]
        header = json.loads(lines[0])
        records = [json.loads(ln) for ln in lines[1:-1]]
        header["chain_tip"] = "0" * 64
        canon = lambda o: json.dumps(  # noqa: E731
            o, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, default=str)
        body = "\n".join([canon(header)]
                         + [canon(r) for r in records]) + "\n"
        footer = {"record_type": "intent_ledger_footer",
                  "file_digest": hashlib.sha256(
                      body.encode("utf-8")).hexdigest()}
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(body + canon(footer) + "\n")
        with self.assertRaises(IntentPersistenceError):
            IntentLedger.load(p)


class ExecutorWiringTest(unittest.TestCase):
    def _approved(self, ctx, turns):
        q, ex = ctx["approvals"], ctx["executor"]
        ident = ctx["mint_identity"]("a1", "coder", "org")
        ex.set_intent_context(list(turns))
        verdict = ex._intent_slice_verdict(
            "delete_file", {"path": str(ex.sandbox / "x.txt")},
            "cleaning temp files per your instruction", ident)
        aid = q.queue(
            {"tool": "delete_file",
             "args": {"path": str(ex.sandbox / "x.txt")},
             "identity": ident.as_dict(),
             "agent_justification":
                 "cleaning temp files per your instruction",
             "redactions": []},
            PolicyDecision("require_approval", "intent-ledger tests",
                           policy_id="test", flag="t"),
            "agent_direct", "preview",
            policy_hash=ex.policy.policy_hash, caller_identity=ident,
            intent_slice_verdict=verdict)
        q.decide(aid, True, "human says ok", decided_by="human-operator")
        return aid

    def test_record_intent_turn_noop_without_ledger(self):
        ctx = make_run()
        ex = ctx["executor"]
        self.assertIsNone(ex.intent_ledger)
        self.assertIsNone(ex.record_intent_turn("op", "hello"))

    def test_cross_run_countermand_refuses_at_boundary(self):
        from gov.log import read_entries
        d = _tmp()
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(ctx, ["Delete the temp files."])
        decided_at = q.get(aid)["decided_at"]
        # Run 1 persists its granting turn; run 2 persists the
        # countermand. The ledger crosses the run boundary on disk.
        led = IntentLedger()
        led.record_intent("org", "Delete the temp files.")
        led.save(lp)
        led2 = IntentLedger.load(lp)
        led2.record_intent("org", "Do not delete the temp files.")
        led2.save(lp)
        # Run 3: fresh load, no run-scoped intent context.
        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        self.assertEqual(done, [])
        rec = q.get(aid)
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], revoke_mod.INTENT_SYSTEM)
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in evts
                   if e.get("event") == "approval_execution_refused"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_intent_changed")
        self.assertEqual(refused[0]["policy_id"], "intent-revocation-xr")

    def test_cross_run_chatter_does_not_evict_grant(self):
        """F181: [grant instruction, chatter] at/before decided_at, a
        verbatim countermand strictly after. The cross-run sweep feeds
        the judge the FULL pre-grant history (prior=None), so the
        granting instruction survives the intervening chatter and the
        grant is auto-revoked at the execution boundary
        (intent-revocation-xr). With the old prior=1 window the judge
        saw only [chatter, countermand], found nothing to anchor, and
        the grant executed."""
        from datetime import datetime, timedelta
        from gov.log import read_entries
        d = _tmp()
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        grant = "Delete the temp files in the scratch dir."
        aid = self._approved(ctx, [grant])
        decided_at = q.get(aid)["decided_at"]

        def shift(iso, seconds):
            dt = datetime.fromisoformat(str(iso))
            return (dt + timedelta(seconds=seconds)).isoformat()

        self._ledger_with_turns(lp, [
            (grant, shift(decided_at, -300)),
            ("Thanks, that's all for now.", shift(decided_at, -100)),
            ("Stop -- don't delete anything in the scratch dir.",
             shift(decided_at, +300)),
        ])
        # Run 3: fresh load, no run-scoped intent context.
        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        rec = q.get(aid)
        self.assertEqual(done, [])
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], revoke_mod.INTENT_SYSTEM)
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in evts
                   if e.get("event") == "approval_execution_refused"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_intent_changed")
        self.assertEqual(refused[0]["policy_id"], "intent-revocation-xr")

    def test_no_ledger_no_behavior_change(self):
        ctx = make_run()
        aid = self._approved(ctx, ["Delete the temp files."])
        done = ctx["executor"].execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(ctx["approvals"].get(aid)["executed"])

    def _ledger_with_turns(self, path, turns):
        """turns: list of (message, ts). Returns the saved path."""
        led = IntentLedger()
        for message, ts in turns:
            led.record_intent("org", message, ts=ts)
        led.save(path)
        return path

    def test_override_without_new_turns_stands(self):
        """Human approved DESPITE a queue-time stale flag; the ledger
        holds no post-grant turns -> the override stands, executes
        (the wave-131 contract survives cross-run)."""
        import tempfile
        d = tempfile.mkdtemp(prefix="intent-ledger-test-")
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(
            ctx, ["Delete the temp files in the scratch dir.",
                  "Stop -- don't delete anything in the scratch dir."])
        self.assertTrue((q.get(aid).get("intent_slice") or {}).get(
            "flagged"))
        self._ledger_with_turns(lp, [
            ("Delete the temp files in the scratch dir.",
             "2026-01-01T00:00:00+00:00"),
            ("Stop -- don't delete anything in the scratch dir.",
             "2026-01-01T01:00:00+00:00"),
        ])
        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        self.assertEqual(len(done), 1)
        self.assertTrue(q.get(aid)["executed"])

    def test_override_with_new_countermand_revoked(self):
        """Human approved DESPITE a queue-time stale flag; a NEW
        post-grant countermand arrives -> the new information wins:
        auto-revoked with approval_intent_changed."""
        import tempfile
        from datetime import datetime, timedelta
        d = tempfile.mkdtemp(prefix="intent-ledger-test-")
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        aid = self._approved(
            ctx, ["Delete the temp files in the scratch dir.",
                  "Stop -- don't delete anything in the scratch dir."])
        self.assertTrue((q.get(aid).get("intent_slice") or {}).get(
            "flagged"))
        decided = q.get(aid)["decided_at"]
        post = (datetime.fromisoformat(decided)
                + timedelta(seconds=300)).isoformat()
        self._ledger_with_turns(lp, [
            ("Delete the temp files in the scratch dir.",
             "2026-01-01T00:00:00+00:00"),
            ("Stop -- don't delete anything in the scratch dir.",
             "2026-01-01T01:00:00+00:00"),
            ("Stop -- I mean it, don't delete anything in the scratch dir.",
             post),
        ])
        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        self.assertEqual(done, [])
        rec = q.get(aid)
        self.assertEqual(rec["status"], "revoked")
        self.assertEqual(rec["revoked_by"], revoke_mod.INTENT_SYSTEM)


if __name__ == "__main__":
    unittest.main()
