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
    rien/aucun paired pattern (incl. elided n'). Wave-144:
    keinerlei/keinesfalls graduate to standalone cues and the French
    pair fires in both orders (ne...X and X...ne). Word-boundary and
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
        # silent. ("keinerlei" shares its "keiner" prefix with the
        # existing cue "keiner"; the boundary guard is what keeps
        # "keinerlei" from cueing via "keiner" -- it cues only via
        # its own alternative, pinned below. Wave-145: "keineswegs"
        # graduated from this guard list to a full cue of its own --
        # see NegationKeineswegsTest.)
        self.assertIsNone(self._cue("Der kleine Bericht."))
        self.assertIsNone(self._cue("Nichts zu beanstanden."))
        self.assertIsNone(self._cue("Nichtsdestotrotz senden."))

    def test_german_keinerlei_keinesfalls_match(self):
        # Wave-144: unambiguous negation words graduate to cues.
        self.assertEqual(self._cue("keinerlei"), "keinerlei")
        self.assertEqual(self._cue("Keinerlei Q3 report geht an den vendor."),
                         "keinerlei")
        self.assertEqual(self._cue("keinesfalls"), "keinesfalls")
        self.assertEqual(
            self._cue("Keinesfalls geht der Q3 report an den vendor."),
            "keinesfalls")

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
        # Wave-144: the reverse order (X ... ne / X ... n') cues
        # with the same guards. The elided n' isolates the new
        # branch (no standalone "ne" token exists).
        self.assertIn("rien", self._cue("Rien n'est encore decide."))
        self.assertIn("jamais", self._cue("Jamais n'envoyez ce rapport."))
        self.assertIn("plus", self._cue("Plus n'ira au vendor."))
        self.assertIn("aucun", self._cue("Aucun rapport n'ira au vendor."))
        # Curly-apostrophe elision in reverse order too.
        self.assertIn("rien", self._cue("Rien n\u2019est encore decide."))

    def test_french_unpaired_particles_do_not_match(self):
        # Pairing discipline: the particle without "ne" stays silent.
        self.assertIsNone(self._cue("Il y a de plus en plus."))
        self.assertIsNone(self._cue("Merci, rien d'autre."))
        self.assertIsNone(self._cue("Aucun probleme ici."))

    def test_french_reverse_order_no_longer_misses(self):
        # Wave-143 pinned this as a directional miss (ne-before-X
        # only). Wave-144 fires both orders: the reverse pair cues.
        hit = self._cue("Rien n'est encore decide.")
        self.assertIsNotNone(hit)
        self.assertIn("rien", hit)

    def test_french_reverse_unpaired_particles_do_not_match(self):
        # Pairing discipline holds in reverse too: the particle
        # without a following ne/n' stays silent.
        self.assertIsNone(self._cue("Merci, rien d'autre."))
        self.assertIsNone(self._cue("Aucun retard ici."))
        self.assertIsNone(self._cue("Plus d'informations."))
        # An elided n' too far away (>8 intervening words) does not
        # pair (same distance guard as the forward order).
        self.assertIsNone(self._cue(
            "Rien dans ce tres long rapport tres detaille sur le "
            "troisieme trimestre vraiment tres complet n'ira."))

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


class NegationKeineswegsTest(unittest.TestCase):
    """Wave-145: "keineswegs" ("in no way / by no means") graduates
    from the wave-144 pinned miss to a standalone-word cue -- the
    last German leftover. Same word-boundary discipline, same
    style."""

    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0).lower() if hit else None

    def test_keineswegs_matches(self):
        self.assertEqual(self._cue("keineswegs"), "keineswegs")
        self.assertEqual(
            self._cue("Keineswegs geht der Q3 report an den vendor."),
            "keineswegs")
        self.assertEqual(
            self._cue("Keineswegs senden Sie den Q3 report an den "
                      "vendor."),
            "keineswegs")

    def test_keineswegs_fires_exactly_once_no_prefix_double_fire(self):
        # The "keines" prefix shared with "keinesfalls" cannot cue
        # inside "keineswegs": the word boundary fails mid-word, so
        # the full-word alternative wins exactly once. Same guard
        # for the keinerlei/keinesfalls family.
        for text, want in (
                ("Keineswegs geht der Q3 report.", "keineswegs"),
                ("Keinesfalls geht der Q3 report.", "keinesfalls"),
                ("Keinerlei Q3 report geht an den vendor.", "keinerlei"),
                ("Keines der reports.", "keines")):
            hits = [mm.group(0).lower()
                    for mm in m._NEGATION_RE.finditer(text)]
            self.assertEqual(hits, [want], text)

    def test_negated_verb_picks_up_keineswegs(self):
        # The verb-scope consumer shares the core: keineswegs before
        # the verb stem counts as negation (the wave-145 battery's
        # g_keineswegs_verb probe exercises the same seam).
        self.assertTrue(
            m._negated_verb("Keineswegs senden Sie den Q3 report an "
                            "den vendor.",
                            "send_email"))
        self.assertFalse(
            m._negated_verb("Keineswegs ist der Q3 report fertig; "
                            "bitte senden Sie ihn an den vendor.",
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


class NegationScopeWindowTest(unittest.TestCase):
    """Wave-147, row 7: negation_scopes_grant -- a negation cue only
    cancels an intent when it falls within a bounded token window of
    the intent's action verb in the same clause."""

    def test_cue_on_grant_verb_scopes(self):
        self.assertTrue(m.negation_scopes_grant(
            "Don't send the Q3 report.",
            "Send the Q3 report to the vendor."))

    def test_wrong_predicate_other_clause_does_not_scope(self):
        self.assertFalse(m.negation_scopes_grant(
            "Der Q3 report ist keineswegs fertig; bitte senden Sie "
            "ihn an den vendor.",
            "Senden Sie den Q3-Bericht an den Vendor."))

    def test_wrong_predicate_french_does_not_scope(self):
        self.assertFalse(m.negation_scopes_grant(
            "Le Q3 report n'est pas en retard; envoyez-le au vendor.",
            "Send the Q3 report to the vendor."))

    def test_no_grant_verb_in_message_stays_conservative(self):
        # "There is no Q3 report" -- the grant's object is denied;
        # no verb to attribute scope to, so the old behavior holds.
        self.assertTrue(m.negation_scopes_grant(
            "There is no Q3 report for the vendor.",
            "Send the Q3 report to the vendor."))

    def test_unknown_anchor_verb_stays_conservative(self):
        self.assertTrue(m.negation_scopes_grant(
            "Don't review the Q3 report.",
            "Review the Q3 report with the vendor."))

    def test_elided_french_verb_matches_send_class(self):
        self.assertTrue(m.negation_scopes_grant(
            "N'envoyez plus ce Q3 report au vendor.",
            "Send the Q3 report to the vendor."))

    def test_elliptical_cross_clause_countermand_is_boundary(self):
        # Known boundary, documented: the bare cue's clause carries
        # no verb, so the re-affirmed verb clause wins -> silent.
        self.assertFalse(m.negation_scopes_grant(
            "Send the report. Don't.",
            "Send the Q3 report to the vendor."))


class NegationVerbTier2Test(unittest.TestCase):
    """Wave-148, row 7: tier-2 verb classes (REDACT / SHARE / PUBLISH
    / FORWARD / UPLOAD) get the same +-8 token scope discipline as
    tier 1, in EN/DE/FR/ES/romanized-HI."""

    def test_tier2_genuine_countermand_revokes(self):
        self.assertTrue(m.negation_scopes_grant(
            "Don't publish the report.",
            "Publish the Q3 report to the portal."))

    def test_tier2_wrong_predicate_stays_silent(self):
        self.assertFalse(m.negation_scopes_grant(
            "The report is not final; please publish it to the portal.",
            "Publish the Q3 report to the portal."))

    def test_tier2_german_separable_upload(self):
        # "laden ... hoch": particle + stem in the same clause
        # names the UPLOAD class.
        self.assertTrue(m.negation_scopes_grant(
            "Laden Sie das Backup nicht hoch.",
            "Laden Sie das Backup in den Tresor hoch."))

    def test_tier2_german_separable_wrong_predicate_silent(self):
        self.assertFalse(m.negation_scopes_grant(
            "Das Backup ist nicht geprueft; laden Sie es bitte in "
            "den Tresor hoch.",
            "Laden Sie das Backup in den Tresor hoch."))

    def test_tier2_particle_alone_is_not_a_verb(self):
        # "hoch" without a laden-stem is "high", not upload: the
        # separable rule must not fire.
        self.assertEqual(
            m._anchor_verb_classes("Die Kosten sind nicht hoch."),
            set())

    def test_tier2_accented_french_forward(self):
        # Accent-folded tokenization: "transférez" -> "transferez".
        self.assertTrue(m.negation_scopes_grant(
            "Ne transférez pas la chaîne.",
            "Transférez la chaîne au service juridique."))

    def test_tier2_accented_german_publish(self):
        self.assertFalse(m.negation_scopes_grant(
            "Der Bericht ist nicht final; veröffentlichen Sie ihn "
            "bitte im Portal.",
            "Veröffentlichen Sie den Q3-Bericht im Portal."))

    def test_tier2_hindi_share(self):
        self.assertTrue(m.negation_scopes_grant(
            "Draft nahi baanto.",
            "Review team ke saath draft baanto."))
        self.assertFalse(m.negation_scopes_grant(
            "Draft ready nahi hai; review team ke saath draft baanto.",
            "Review team ke saath draft baanto."))

    def test_tier2_spanish_redact(self):
        self.assertTrue(m.negation_scopes_grant(
            "No censure los nombres.",
            "Censure los nombres de los testigos."))

    def test_tier2_unknown_verb_still_conservative(self):
        # Verbs outside BOTH tiers keep pre-wave-147 behavior.
        self.assertTrue(m.negation_scopes_grant(
            "Don't summarize the Q3 report.",
            "Summarize the Q3 report for the vendor."))


class DevanagariNegationTest(unittest.TestCase):
    """Wave-149, row 7: Devanagari negation cues (नहीं/न/मत) with
    explicit word-boundary discipline, Devanagari SEND/ARCHIVE/DELETE
    verb forms, and the _fold_accents length-preservation fix."""

    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0) if hit else None

    def test_cues_match_standalone(self):
        self.assertEqual(self._cue("रिपोर्ट नहीं भेजें"), "नहीं")
        self.assertEqual(self._cue("रिपोर्ट मत भेजें"), "मत")
        self.assertEqual(self._cue("रिपोर्ट न भेजें"), "न")

    def test_danda_terminator_does_not_block_cue(self):
        # U+0964 is excluded from the boundary guard on purpose.
        self.assertEqual(self._cue("रिपोर्ट नहीं।"), "नहीं")
        self.assertEqual(self._cue("मत भेजें।"), "मत")

    def test_embedded_cue_does_not_match(self):
        self.assertIsNone(self._cue("रिपोर्टनहींभेजें"))
        # "मतलब" ("meaning") contains "मत" -- the guard blocks it.
        self.assertIsNone(self._cue("इसका मतलब रिपोर्ट भेजें"))

    def test_fold_preserves_devanagari_length(self):
        # The cue regex runs on raw text while scope tokens run on
        # folded text: any length change misaligns cue spans. Virama
        # (U+094D) must survive the fold.
        for s in ("रिपोर्ट", "नहीं", "भेजें", "Q3 रिपोर्ट मत भेजें।"):
            self.assertEqual(m._fold_accents(s), s)

    def test_scope_mat_revokes(self):
        self.assertTrue(m.negation_scopes_grant(
            "Q3 रिपोर्ट मत भेजें",
            "Send the Q3 report to the vendor."))

    def test_scope_nahin_revokes(self):
        self.assertTrue(m.negation_scopes_grant(
            "Q3 रिपोर्ट नहीं भेजें",
            "Send the Q3 report to the vendor."))

    def test_scope_wrong_predicate_other_clause_silent(self):
        self.assertFalse(m.negation_scopes_grant(
            "Q3 रिपोर्ट तैयार नहीं है; कृपया इसे विक्रेता को भेजें",
            "Send the Q3 report to the vendor."))

    def test_scope_danda_clause_split_silent(self):
        self.assertFalse(m.negation_scopes_grant(
            "Q3 रिपोर्ट तैयार नहीं है। कृपया इसे विक्रेता को भेजें।",
            "Send the Q3 report to the vendor."))

    def test_scope_devanagari_delete_form(self):
        self.assertTrue(m.negation_scopes_grant(
            "Q3 रिपोर्ट को हटाना नहीं है",
            "Delete the Q3 report."))

    def test_scope_devanagari_archive_form(self):
        self.assertTrue(m.negation_scopes_grant(
            "Q3 रिपोर्ट संग्रहित नहीं करें",
            "Archive the Q3 report."))

    def test_tag_question_fires_documented_cost(self):
        # "है न?" ("...haven't you?") is a confirmation, but the
        # mandated standalone-न cue reads it as a countermand. This
        # is a MEASURED precision cost (wave-142 "ne" precedent),
        # pinned so any future tag-question guard updates this test
        # and the battery together.
        self.assertTrue(m.negation_scopes_grant(
            "Q3 रिपोर्ट vendor को भेज दी है न?",
            "Send the Q3 report to the vendor."))


class CyrillicNegationTest(unittest.TestCase):
    """Wave-151, row 7: Russian Cyrillic negation cues (не/нет/ни/
    нельзя + paired ни...ни) with plain-\\b boundary discipline,
    Cyrillic SEND/DELETE/SHARE verb forms (dual spellings for the
    fold's й->и / ё->е normalization), and the positional "нельзя
    ли" / "не так ли" precision guards."""

    def _cue(self, text):
        hit = m._NEGATION_RE.search(text)
        return hit.group(0) if hit else None

    def test_cues_match_standalone(self):
        self.assertEqual(self._cue("отчёт не отправляйте"), "не")
        self.assertEqual(self._cue("Нет. Q3 отчёт подождёт."), "Нет")
        self.assertEqual(self._cue("Q3 отчёт ни в коем случае."), "ни")
        self.assertEqual(self._cue("Q3 отчёт отправлять нельзя"),
                         "нельзя")

    def test_paired_ni_ni_matches(self):
        self.assertIsNotNone(
            m._NEGATION_RE.search("Ни отправлять, ни сохранять Q3 отчёт"))

    def test_embedded_cue_does_not_match(self):
        # "не"/"нет"/"ни" inside larger words: \b fires correctly
        # around Cyrillic (letters are \w).
        for w in ("менеджер", "некоторые", "интернет", "организация",
                  "униформа", "ниже"):
            self.assertIsNone(self._cue(w), w)

    def test_nelzya_li_guard(self):
        # The polite idiom "нельзя ли" ("could you please...") is not
        # a countermand; bare "нельзя" still cues.
        self.assertIsNone(self._cue("Нельзя ли отправить Q3 отчёт?"))
        self.assertEqual(self._cue("Q3 отчёт отправлять нельзя"),
                         "нельзя")

    def test_ne_tak_li_guard(self):
        # The tag question "не так ли" ("...didn't you?") is not a
        # countermand; "не так" without "ли" still cues.
        self.assertIsNone(
            self._cue("Вы отправили Q3 отчёт, не так ли?"))
        self.assertEqual(self._cue("Не так отправляйте Q3 отчёт"),
                         "Не")

    def test_fold_length_identical_cyrillic(self):
        # The cue regex runs on raw text while scope tokens run on
        # folded text: any length change misaligns cue spans. ё->е
        # and й->и normalization is length-preserving (not identity).
        for s in ("отправляйте", "нельзя", "удалён", "поделитесь",
                  "Q3 отчёт не отправляйте"):
            self.assertEqual(len(m._fold_accents(s)), len(s), s)
        self.assertEqual(m._fold_accents("отправляйте"), "отправляите")
        self.assertEqual(m._fold_accents("удалён"), "удален")

    def test_judge_native_cyrillic_countermand(self):
        self.assertTrue(m._negated_verb("Q3 отчёт не отправляйте",
                                       "send_email"))
        self.assertTrue(m._negated_verb("Q3 отчёт не удаляйте",
                                       "delete_file"))
        self.assertTrue(m._negated_verb("Нельзя удалять Q3 отчёт",
                                       "delete_file"))

    def test_judge_wrong_predicate_silent(self):
        self.assertFalse(m._negated_verb("Q3 отчёт не отправляйте",
                                        "delete_file"))

    def test_scope_split_silent(self):
        self.assertFalse(m.negation_scopes_grant(
            "Q3 отчёт не готов; отправьте его vendor.",
            "Send the Q3 report to the vendor."))

    def test_scope_delete_share_forms(self):
        self.assertTrue(m.negation_scopes_grant(
            "Q3 отчёт удалять нельзя",
            "Delete the Q3 report."))
        self.assertTrue(m.negation_scopes_grant(
            "Q3 отчётом делиться нельзя",
            "Share the Q3 report with the vendor."))


if __name__ == "__main__":
    unittest.main()
