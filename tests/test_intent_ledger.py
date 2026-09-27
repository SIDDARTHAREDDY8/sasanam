"""Cross-run intent ledger unit tests (wave-134, row-7 third half).

Covers the public seams of gov/intent_ledger.py (record_intent /
latest_countermands / messages_since / messages_with_context /
verify_chain / save / load) and the executor wiring
(record_intent_turn, intent_ledger kwarg, execution-boundary
cross-run countermand check).

Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
GOV_DEPLOYMENT_MODE=staging. The wave-138 DerivedThresholdSeamTest
scrubs/provisions key env vars and always restores them in a finally
(keyfixture scrub/provision are exception-safe).
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
    IntentLedger, IntentPersistenceError, INTENT_LEDGER_VERSION,
    derive_countermand_threshold, similarity_countermand)
from gov.keys import NoKeyConfiguredError  # noqa: E402
from gov.target_match import target_similarity  # noqa: E402
from keyfixture import provision_test_key, scrub_key_env  # noqa: E402


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


class SimilaritySignalSeamTest(unittest.TestCase):
    """Wave-136, row-7: the negation-gated similarity countermand
    signal at the record_intent seam."""

    def test_refrain_paraphrase_fires_without_redirect_signal(self):
        # "refrain" is in _NEGATION_RE but NOT the redirect list, so
        # the legacy detector stays silent and this isolates the new
        # similarity signal.
        led = IntentLedger()
        led.record_intent("op", "Send the Q3 report to the vendor.")
        r = led.record_intent(
            "op", "Please refrain from sending that Q3 report anywhere.")
        self.assertTrue(r["similarity_countermand"])
        self.assertFalse(r["detector_countermand"])
        self.assertTrue(r["is_countermand"])
        self.assertEqual(r["similarity_anchor"],
                         "Send the Q3 report to the vendor.")
        self.assertGreaterEqual(r["similarity_score"], 0.5)

    def test_similarity_without_negation_never_fires(self):
        # High similarity (0.76) but no negation cue: the gate holds,
        # a paraphrased confirmation is not a countermand.
        led = IntentLedger()
        led.record_intent("op", "Send the Q3 report to the vendor.")
        r = led.record_intent(
            "op", "Yes please do send the Q3 report to the vendor.")
        self.assertFalse(r["similarity_countermand"])
        self.assertFalse(r["is_countermand"])
        self.assertIsNone(r["similarity_anchor"])
        self.assertIsNone(r["similarity_anchor_ts"])

    def test_negation_without_prior_instruction_does_not_fire(self):
        led = IntentLedger()
        r = led.record_intent("op", "do not send anything")
        self.assertFalse(r["similarity_countermand"])
        self.assertFalse(r["is_countermand"])

    def test_best_anchor_wins(self):
        from gov.intent_ledger import similarity_countermand
        priors = ["Delete the temp files in the scratch dir.",
                  "Send the Q3 report to the vendor."]
        fired, idx, score = similarity_countermand(
            "Please refrain from sending that Q3 report anywhere.",
            priors)
        self.assertTrue(fired)
        self.assertEqual(idx, 1)
        self.assertGreaterEqual(score, 0.5)

    def test_threshold_must_be_open_unit_interval(self):
        from gov.intent_ledger import similarity_countermand
        for bad in (0, -0.5, 1.5, True, "0.5", None):
            with self.assertRaises(ValueError):
                similarity_countermand("don't do x", ["do x"],
                                       threshold=bad)

    def test_non_string_inputs_fail_safe(self):
        from gov.intent_ledger import similarity_countermand
        self.assertEqual(similarity_countermand(None, ["do x"]),
                         (False, None, 0.0))
        self.assertEqual(similarity_countermand("   ", ["do x"]),
                         (False, None, 0.0))
        self.assertEqual(similarity_countermand("don't do x", None),
                         (False, None, 0.0))
        self.assertEqual(similarity_countermand("don't do x", "do x"),
                         (False, None, 0.0))

    def test_non_string_priors_are_skipped_not_coerced(self):
        from gov.intent_ledger import similarity_countermand
        fired, idx, score = similarity_countermand(
            "do not send the Q3 report",
            [None, 42, "Send the Q3 report."])
        self.assertTrue(fired)
        # The anchor index refers to the caller's list as passed.
        self.assertEqual(idx, 2)
        self.assertGreaterEqual(score, 0.5)

    def test_similarity_fields_survive_save_load_and_verify(self):
        d = _tmp()
        p = os.path.join(d, "ledger.jsonl")
        led = IntentLedger()
        grant_ts = "2026-09-27T10:00:00+00:00"
        led.record_intent("op", "Send the Q3 report to the vendor.",
                          ts=grant_ts)
        r = led.record_intent(
            "op", "Please refrain from sending that Q3 report anywhere.",
            ts="2026-09-27T11:00:00+00:00")
        self.assertTrue(r["similarity_countermand"])
        led.save(p)
        led2 = IntentLedger.load(p)
        self.assertTrue(led2.verify_chain())
        recs = [t for t in led2._turns
                if t.get("similarity_countermand")]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["similarity_anchor"],
                         "Send the Q3 report to the vendor.")
        self.assertEqual(recs[0]["similarity_anchor_ts"], grant_ts)
        self.assertGreaterEqual(recs[0]["similarity_score"], 0.5)


class NegationInflectionSeamTest(unittest.TestCase):
    """Wave-143, row-7: similarity_countermand picks up the extended
    negation core (German kein-inflections, French ne...X paired
    pattern incl. elided n') with NO ledger change -- the seam reuses
    gov.intent_slice._NEGATION_RE. Verified end-to-end through
    record_intent, not assumed."""

    GRANT = "Send the Q3 report to the vendor."

    def test_german_inflections_fire_through_shared_core(self):
        for msg in ("Keinen Q3 report an den vendor senden.",
                    "Keinem vendor den Q3 report senden.",
                    "Keiner der vendors erhaelt den Q3 report.",
                    "Keines der Q3 reports an den vendor senden."):
            fired, idx, score = similarity_countermand(
                msg, [self.GRANT], threshold=0.5)
            self.assertTrue(fired, msg)
            self.assertEqual(idx, 0)
            self.assertGreaterEqual(score, 0.5)

    def test_french_elided_pairs_fire_through_shared_core(self):
        for msg in ("Je n'enverrai jamais ce Q3 report au vendor.",
                    "N'envoyez plus ce Q3 report au vendor.",
                    "N'envoyez rien au vendor concernant le Q3 report.",
                    "N'envoyez aucun Q3 report au vendor."):
            fired, idx, score = similarity_countermand(
                msg, [self.GRANT], threshold=0.5)
            self.assertTrue(fired, msg)
            self.assertGreaterEqual(score, 0.5)

    def test_record_intent_marks_inflected_countermand(self):
        led = IntentLedger()
        led.record_intent("op", self.GRANT)
        r = led.record_intent(
            "op", "Keinen Q3 report an den vendor senden.")
        self.assertTrue(r["similarity_countermand"])
        self.assertTrue(r["is_countermand"])
        self.assertEqual(r["similarity_anchor"], self.GRANT)
        self.assertGreaterEqual(r["similarity_score"], 0.5)

    def test_record_intent_marks_elided_french_countermand(self):
        led = IntentLedger()
        led.record_intent("op", self.GRANT)
        r = led.record_intent(
            "op", "N'envoyez jamais ce Q3 report au vendor.")
        self.assertTrue(r["similarity_countermand"])
        self.assertTrue(r["is_countermand"])

    def test_lookalikes_do_not_fire(self):
        # kein-substring words and unpaired French particles stay
        # silent even at/above gate similarity. (similarity_countermand
        # short-circuits to 0.0 when the cue misses, so the raw
        # similarity is measured directly to keep the probe
        # meaningful.) Wave-145: "keineswegs" left this list -- it
        # is a cue now ("keinerlei"/"keinesfalls" are cues too; their
        # scope imprecision is a documented ceiling, not a lookalike
        # probe).
        for msg in ("Il y a de plus en plus de Q3 reports pour le "
                    "vendor.",
                    "Merci pour le Q3 report; rien d'autre pour le "
                    "vendor.",
                    "Aucun retard: le Q3 report partira vers le "
                    "vendor."):
            self.assertGreaterEqual(target_similarity(msg, self.GRANT),
                                    0.5, msg)
            fired, _, _ = similarity_countermand(
                msg, [self.GRANT], threshold=0.5)
            self.assertFalse(fired, msg)

    def test_wave145_keineswegs_fires_at_ledger(self):
        # Wave-145: keineswegs graduates from pinned miss to cue and
        # revokes through the real ledger seam.
        led = IntentLedger()
        led.record_intent("op", self.GRANT)
        for msg in ("Keineswegs geht der Q3 report an den vendor.",
                    "Keineswegs senden Sie den Q3 report an den "
                    "vendor."):
            r = led.record_intent("op", msg)
            self.assertTrue(r["similarity_countermand"], msg)
            self.assertTrue(r["is_countermand"], msg)

    def test_wave147_keineswegs_scope_sentence_now_silent(self):
        # Graduated in wave-147 (row 7 scope window): keineswegs
        # scoping over the wrong predicate ("fertig", not the grant
        # verb) while the grant verb is re-affirmed in a separate
        # clause no longer fires the gate. The anti-rot discipline
        # is preserved in the other direction: if this sentence ever
        # fires again, this test FAILS. Explicit threshold (not
        # record_intent's derived per-message threshold): the raw
        # similarity is 0.545, inside the derived [0.4, 0.6) band, so
        # record_intent would be flaky here -- the pin is about the
        # cue+scope, not calibration.
        fired, _, score = similarity_countermand(
            "Der Q3 report ist keineswegs fertig; bitte senden Sie "
            "ihn an den vendor.",
            [self.GRANT], threshold=0.5)
        self.assertFalse(fired)
        self.assertGreaterEqual(score, 0.5)

    def test_wave144_cues_fire_at_ledger(self):
        # The wave-144 leftovers revoke through the countermand path:
        # German keinerlei/keinesfalls and the French reverse-order
        # pair (elided n' -- no standalone "ne").
        # Explicit threshold (not record_intent's derived per-message
        # threshold): the French sentences score 0.571, inside the
        # wave-138 derived [0.4, 0.6) band, so record_intent is flaky
        # here (measured 2/6 with no code change -- the suite
        # provisions a fresh random test key per run). The pin is
        # about the cue+score, not calibration. (wave-145 lesson)
        for msg in ("Keinerlei Q3 report geht an den vendor.",
                    "Keinesfalls geht der Q3 report an den vendor.",
                    "Rien n'est encore decide concernant le Q3 report "
                    "pour le vendor.",
                    "Jamais n'envoyez ce Q3 report au vendor."):
            fired, _, score = similarity_countermand(
                msg, [self.GRANT], threshold=0.5)
            self.assertTrue(fired, msg)
            self.assertGreaterEqual(score, 0.5, msg)

    def test_positive_confirmations_do_not_fire(self):
        for msg in ("Ja, bitte den Q3 report an den vendor senden.",
                    "Oui, envoyez ce Q3 report au vendor s'il vous "
                    "plait."):
            self.assertGreaterEqual(target_similarity(msg, self.GRANT),
                                    0.5, msg)
            fired, _, _ = similarity_countermand(
                msg, [self.GRANT], threshold=0.5)
            self.assertFalse(fired, msg)


class SimilarityAfterSeamTest(unittest.TestCase):
    """Wave-136, row-7: similarity_countermands_after grant
    attribution at the execution boundary."""

    def _ledger(self):
        led = IntentLedger()
        led.record_intent("op", "Send the Q3 report to the vendor.",
                          ts="2026-09-27T10:00:00+00:00")
        led.record_intent("op", "Please refrain from sending that "
                          "Q3 report anywhere.",
                          ts="2026-09-27T11:00:00+00:00")
        return led

    def test_post_grant_similarity_countermand_returned(self):
        led = self._ledger()
        hits = led.similarity_countermands_after(
            "op", "2026-09-27T10:30:00+00:00")
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["similarity_countermand"])
        self.assertEqual(hits[0]["similarity_anchor_ts"],
                         "2026-09-27T10:00:00+00:00")

    def test_nothing_new_after_grant_returns_empty(self):
        led = self._ledger()
        self.assertEqual(
            led.similarity_countermands_after(
                "op", "2026-09-27T12:00:00+00:00"), [])

    def test_wrong_principal_returns_empty(self):
        led = self._ledger()
        self.assertEqual(
            led.similarity_countermands_after(
                "other", "2026-09-27T10:30:00+00:00"), [])

    def test_unparseable_since_returns_empty(self):
        led = self._ledger()
        self.assertEqual(
            led.similarity_countermands_after("op", "not-a-time"), [])

    def test_anchor_after_grant_is_not_misattributed(self):
        # The load-bearing guard: a negated paraphrase that anchors
        # to POST-grant chatter (not the grant) must not revoke the
        # grant. "do not review the Q3 report again" is most similar
        # to the chatter turn, so the anchor postdates decided_at and
        # the query stays empty.
        led = IntentLedger()
        led.record_intent("op", "Send the Q3 report to the vendor.",
                          ts="2026-09-27T10:00:00+00:00")
        led.record_intent("op", "I also reviewed the Q3 report this "
                          "morning.",
                          ts="2026-09-27T11:00:00+00:00")
        r = led.record_intent("op", "do not review the Q3 report again",
                              ts="2026-09-27T12:00:00+00:00")
        self.assertTrue(r["similarity_countermand"])
        self.assertEqual(r["similarity_anchor"],
                         "I also reviewed the Q3 report this morning.")
        # decided_at sits between grant and chatter: the countermand
        # anchors to chatter (post-grant), so no grant attribution.
        self.assertEqual(
            led.similarity_countermands_after(
                "op", "2026-09-27T10:30:00+00:00"), [])


class SimilarityExecutorWiringTest(unittest.TestCase):
    """Wave-136, row-7: execute_approved revokes a grant on a
    paraphrased (negation-gated similarity) countermand and the
    refusal audit event carries match_method/match_score."""

    def _approved_send(self, ctx, turns):
        q, ex = ctx["approvals"], ctx["executor"]
        # Role "researcher": the default policy's role allowlist
        # permits researcher -> send_email; the recipient is on the
        # egress domain allowlist so the sweep's fresh policy
        # evaluation passes and only the intent check can fire.
        ident = ctx["mint_identity"]("a1", "researcher", "org")
        args = {"to": "vendor@synthetic.local",
                "subject": "Q3 report", "body": "see attached"}
        ex.set_intent_context(list(turns))
        verdict = ex._intent_slice_verdict(
            "send_email", args,
            "sending the Q3 report per your instruction", ident)
        aid = q.queue(
            {"tool": "send_email", "args": args,
             "identity": ident.as_dict(),
             "agent_justification":
                 "sending the Q3 report per your instruction",
             "redactions": []},
            PolicyDecision("require_approval", "similarity tests",
                           policy_id="test", flag="t"),
            "agent_direct", "preview",
            policy_hash=ex.policy.policy_hash, caller_identity=ident,
            intent_slice_verdict=verdict)
        q.decide(aid, True, "human says ok", decided_by="human-operator")
        return aid

    def test_similarity_countermand_revokes_with_match_metadata(self):
        from gov.log import read_entries
        from gov.target_match import MATCH_METHOD
        d = _tmp()
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        grant = "Send the Q3 report to vendor@synthetic.local."
        aid = self._approved_send(ctx, [grant])
        decided_at = q.get(aid)["decided_at"]

        def shift(iso, seconds):
            from datetime import datetime, timedelta
            dt = datetime.fromisoformat(str(iso))
            return (dt + timedelta(seconds=seconds)).isoformat()

        led = IntentLedger()
        led.record_intent("org", grant, ts=shift(decided_at, -300))
        rec = led.record_intent(
            "org", "Please refrain from sending that Q3 report anywhere.",
            ts=shift(decided_at, 300))
        # Isolate the similarity signal: the legacy redirect detector
        # must stay silent on "refrain".
        self.assertTrue(rec["similarity_countermand"])
        self.assertFalse(rec["detector_countermand"])
        led.save(lp)

        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        self.assertEqual(done, [])
        self.assertEqual(q.get(aid)["status"], "revoked")
        self.assertEqual(q.get(aid)["revoked_by"],
                         revoke_mod.INTENT_SYSTEM)
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in evts
                   if e.get("event") == "approval_execution_refused"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_intent_changed")
        self.assertEqual(refused[0]["policy_id"],
                         "intent-revocation-xr-sim")
        self.assertEqual(refused[0]["match_method"], MATCH_METHOD)
        self.assertEqual(refused[0]["match_method"], "token-tversky")
        self.assertGreaterEqual(refused[0]["match_score"], 0.5)

    def test_legacy_path_revocation_carries_no_similarity_labels(self):
        # The exact countermand still revokes through the legacy
        # redirect path: no match_method/match_score on the refusal.
        from gov.log import read_entries
        d = _tmp()
        lp = os.path.join(d, "ledger.jsonl")
        ctx = make_run()
        q, ex = ctx["approvals"], ctx["executor"]
        grant = "Send the Q3 report to vendor@synthetic.local."
        aid = self._approved_send(ctx, [grant])
        decided_at = q.get(aid)["decided_at"]

        def shift(iso, seconds):
            from datetime import datetime, timedelta
            dt = datetime.fromisoformat(str(iso))
            return (dt + timedelta(seconds=seconds)).isoformat()

        led = IntentLedger()
        led.record_intent("org", grant, ts=shift(decided_at, -300))
        led.record_intent(
            "org", "Don't send the Q3 report to vendor@synthetic.local.",
            ts=shift(decided_at, 300))
        led.save(lp)

        ex.intent_ledger = IntentLedger.load(lp)
        ex.set_intent_context(None)
        done = ex.execute_approved()
        self.assertEqual(done, [])
        self.assertEqual(q.get(aid)["status"], "revoked")
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        refused = [e for e in evts
                   if e.get("event") == "approval_execution_refused"
                   and e.get("approval_id") == aid]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["flag"], "approval_intent_changed")
        self.assertNotIn("match_method", refused[0])
        self.assertNotIn("match_score", refused[0])


class DerivedThresholdSeamTest(unittest.TestCase):
    """Wave-138, row-7: the per-message HMAC-derived countermand
    threshold at the similarity_countermand seam."""

    _MSGS = [
        "Do not send the Q3 report to the vendor",
        "Please do not ever transmit that quarterly report anywhere",
        "Never forward the vendor report",
        "Do not email the Q3 numbers out",
        "Please refrain from sharing the quarterly figures",
    ]
    _PRIORS = ["Send the Q3 report to the vendor."]

    def test_derive_is_deterministic_per_key(self):
        for m in self._MSGS:
            self.assertEqual(derive_countermand_threshold(m),
                             derive_countermand_threshold(m))

    def test_derive_stays_in_band(self):
        for m in self._MSGS:
            t = derive_countermand_threshold(m)
            self.assertGreaterEqual(t, 0.4)
            self.assertLess(t, 0.6)

    def test_derive_varies_per_message(self):
        # The whole point: no single fixed threshold. Distinct
        # messages must not all derive the same boundary.
        seen = {derive_countermand_threshold(m) for m in self._MSGS}
        self.assertGreater(len(seen), 1)

    def test_derive_differs_across_keys(self):
        # Deterministic part of the cross-deployment story: the same
        # message derives a different threshold under a different
        # deployment key (continuous values; equality has
        # probability 0).
        m = self._MSGS[0]
        provision_test_key(epoch="w138-a")
        ta = derive_countermand_threshold(m)
        provision_test_key(epoch="w138-b")
        tb = derive_countermand_threshold(m)
        self.assertNotEqual(ta, tb)

    def test_derive_rejects_bad_input(self):
        for bad in (None, "", "   ", 42, b"bytes"):
            with self.assertRaises(ValueError):
                derive_countermand_threshold(bad)

    def test_default_uses_derived_threshold(self):
        # Wiring pin: the default decision path fires exactly when the
        # best similarity meets the message's derived threshold --
        # not a fixed 0.5.
        for m in self._MSGS:
            t = derive_countermand_threshold(m)
            score = max(target_similarity(m, p) for p in self._PRIORS)
            fired, _, got_score = similarity_countermand(m, self._PRIORS)
            self.assertEqual(fired, score >= t)
            self.assertAlmostEqual(got_score, score)

    def test_explicit_threshold_keeps_fixed_semantics(self):
        # Explicit floats keep fixed-threshold behavior (tests,
        # adversarial probes); the refrain pair scores 0.75.
        m = "Please refrain from sending that Q3 report anywhere."
        fired, _, _ = similarity_countermand(m, self._PRIORS,
                                             threshold=0.9)
        self.assertFalse(fired)
        fired, _, _ = similarity_countermand(m, self._PRIORS,
                                             threshold=0.4)
        self.assertTrue(fired)

    def test_no_key_fail_closed_at_seam(self):
        restore = scrub_key_env()
        try:
            with self.assertRaises(NoKeyConfiguredError):
                derive_countermand_threshold(self._MSGS[0])
            # The decision seam refuses to decide rather than
            # silently falling back to a fixed threshold.
            with self.assertRaises(NoKeyConfiguredError):
                similarity_countermand(self._MSGS[0], self._PRIORS)
        finally:
            restore()

    def test_fail_safe_paths_do_not_touch_key_seam(self):
        # Garbage inputs and the negation gate return before key
        # resolution: no key needed, no raise, even unprovisioned.
        restore = scrub_key_env()
        try:
            self.assertEqual(similarity_countermand(None, ["do x"]),
                             (False, None, 0.0))
            self.assertEqual(
                similarity_countermand(
                    "Yes please do send the Q3 report to the vendor.",
                    self._PRIORS),
                (False, None, 0.0))
        finally:
            restore()

    def test_record_stores_similarity_threshold(self):
        led = IntentLedger()
        led.record_intent("op", "Send the Q3 report to the vendor.")
        r = led.record_intent(
            "op", "Please refrain from sending that Q3 report anywhere.")
        t = r["similarity_threshold"]
        self.assertGreaterEqual(t, 0.4)
        self.assertLess(t, 0.6)
        self.assertEqual(
            t, derive_countermand_threshold(
                "Please refrain from sending that Q3 report anywhere."))

    def test_same_key_same_verdicts(self):
        first = [similarity_countermand(m, self._PRIORS)[0]
                 for m in self._MSGS]
        second = [similarity_countermand(m, self._PRIORS)[0]
                  for m in self._MSGS]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
