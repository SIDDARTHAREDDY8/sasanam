#!/usr/bin/env python3
"""Unit tests for gov/attack_ledger.py (wave-281 lane 8, PyRIT pattern)."""

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import attack_ledger as al  # noqa: E402


def _db():
    d = tempfile.mkdtemp(prefix="al-ut-",
                         dir=os.environ.get("TMPDIR", "/tmp"))
    return al.AttackLedger(os.path.join(d, "t.sqlite3"))


class ScorerTests(unittest.TestCase):
    def test_substring_hit_and_miss(self):
        s = al.SubstringScorer("x", ["needle"])
        v, n = s.score(b"has a needle here")
        self.assertTrue(v)
        self.assertIn("needle", n)
        v, _ = s.score(b"nothing")
        self.assertFalse(v)

    def test_equality_drift(self):
        body = b"pinned behavior"
        digest = hashlib.sha256(body).hexdigest()
        s = al.DriftScorer("eq", digest)
        v, _ = s.score(body)
        self.assertFalse(v)
        v, n = s.score(b"changed behavior")
        self.assertTrue(v)
        self.assertIn("drift", n)

    def test_scorer_is_abc(self):
        with self.assertRaises(TypeError):
            al.Scorer()  # abstract


class ConverterTests(unittest.TestCase):
    def test_compose_deterministic(self):
        a = al.apply_converters(b"abc", ["base64", "base64"])
        b = al.apply_converters(b"abc", ["base64", "base64"])
        self.assertEqual(a, b)

    def test_unknown_refused(self):
        with self.assertRaises(al.ConverterError):
            al.apply_converters(b"x", ["nope"])

    def test_rot13_non_ascii_refused(self):
        with self.assertRaises(al.ConverterError):
            al.apply_converters("héllo".encode("utf-8"), ["rot13"])


class LedgerTests(unittest.TestCase):
    def test_seed_and_piece_ids(self):
        led = _db()
        s = led.record_seed("lbl", b"\x00")
        self.assertEqual(s, hashlib.sha256(b"lbl" + b"\x00").hexdigest())
        p = led.record_piece("observation", b"data")
        self.assertEqual(p, hashlib.sha256(b"data").hexdigest())

    def test_orphan_score_refused(self):
        led = _db()
        with self.assertRaises(al.ScoreLinkError):
            led.record_score("ff" * 32, "s", True, "ghost")
        with self.assertRaises(al.ScoreLinkError):
            led.score_with(al.SubstringScorer("s", ["x"]), "ff" * 32)

    def test_scorer_exception_recorded_not_raised(self):
        class Boom(al.Scorer):
            scorer_id = "boom"

            def score(self, observation):
                raise RuntimeError("x")

        led = _db()
        piece = led.record_piece("observation", b"o")
        v, n = led.score_with(Boom(), piece)
        self.assertIs(v, False)
        self.assertIn("scorer-error", n)

    def test_scenario_validation(self):
        led = _db()
        with self.assertRaises(al.ScenarioRegistrationError):
            led.register_scenario("bad", {"seed_label": "b", "steps": [
                {"plugin": "nope", "strategy": "direct", "payload": "x"}]},
                labels=[])
        with self.assertRaises(al.ScenarioRegistrationError):
            led.register_scenario("bad2", {"nope": 1}, labels=[])
        led.register_scenario("ok", {"seed_label": "ok", "steps": []},
                              labels=["l1"])
        with self.assertRaises(al.ScenarioRegistrationError):
            led.register_scenario("ok", {"seed_label": "ok", "steps": []},
                                  labels=[])
        self.assertEqual([s["name"] for s in led.scenarios_by_label("l1")],
                         ["ok"])

    def test_bytes_payload_refused(self):
        led = _db()
        with self.assertRaises(al.ScenarioRegistrationError):
            led.register_scenario("b", {"seed_label": "b", "steps": [
                {"plugin": "jailbreak", "strategy": "direct",
                 "payload": b"bytes"}]}, labels=[])

    def test_unknown_campaign_error(self):
        led = _db()
        with self.assertRaises(al.CampaignNotFoundError):
            led.replay_campaign(999, lambda a: b"x", [])
        with self.assertRaises(al.CampaignNotFoundError):
            led.campaign_evidence_rows(999)

    def test_rerecord_no_duplicate_chain_events(self):
        led = _db()
        led.record_piece("observation", b"same")
        n1 = led.conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0]
        led.record_piece("observation", b"same")
        n2 = led.conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(n1, n2)
        self.assertTrue(led.verify_chain())

    def test_chain_detects_piece_tamper(self):
        led = _db()
        piece = led.record_piece("observation", b"v1")
        self.assertTrue(led.verify_chain())
        led.conn.execute("UPDATE pieces SET body = ? WHERE piece_id = ?",
                         (b"v2", piece))
        led.conn.commit()
        self.assertFalse(led.verify_chain())

    def test_chain_detects_score_tamper(self):
        led = _db()
        piece = led.record_piece("observation", b"v1")
        led.record_score(piece, "s", False, "clean")
        self.assertTrue(led.verify_chain())
        led.conn.execute("UPDATE scores SET verdict = 1")
        led.conn.commit()
        self.assertFalse(led.verify_chain())

    def test_replay_is_read_only(self):
        led = _db()
        led.register_scenario("s", {"seed_label": "s", "steps": [
            {"plugin": "jailbreak", "strategy": "direct", "payload": "p"}]},
            labels=[])
        scorers = [al.SubstringScorer("x", ["zzz"])]
        camp = led.run_campaign("s", lambda a: b"clean", scorers)
        n_events = led.conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0]
        diffs = led.replay_campaign(camp, lambda a: b"clean", scorers)
        self.assertEqual(diffs, [])
        n_events2 = led.conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(n_events, n_events2)

    def test_evidence_rows(self):
        led = _db()
        led.register_scenario("s", {"seed_label": "s", "steps": [
            {"plugin": "jailbreak", "strategy": "direct", "payload": "p"}]},
            labels=[])
        scorers = [al.SubstringScorer("x", ["p"])]
        camp = led.run_campaign("s", lambda a: b"has p", scorers)
        rows = led.campaign_evidence_rows(camp)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "BREAK")
        self.assertEqual(rows[0]["plugin_id"], "jailbreak")


if __name__ == "__main__":
    unittest.main()
