"""Unit tests for the wave-145 type-to-confirm ceremony (row-11),
wave-147 synonym layer.

A careless human can acknowledge a vague/broad goal
(pending_specificity) or a wildcard-scope goal without reading it --
click-approve is too cheap. Approving a ``goal_specificity_review``
now REQUIRES the human to TYPE the narrowed scope; the typed text is
checked against the goal's declared scope (stamped MAC-bound on the
review record at queue time) with
``gov.target_match.typed_scope_similarity`` (synonym-aware
token-tversky, wave-147) at >= ``DEFAULT_THRESHOLD``.

Seams under test:
  * Threshold reuse: the ceremony uses ``gov.target_match``'s
    ``DEFAULT_THRESHOLD`` (0.5) via ``match_target`` -- no private
    threshold copy; boundary pins at the documented scores.
  * ``ApprovalQueue.decide(typed_scope=...)`` refusal contract: bare
    click / mismatch / blank / non-string typed scope -> ValueError,
    record stays pending, LOUD ``approval_scope_mismatch`` event;
    denials skip the ceremony; normal (non-specificity-review)
    records ignore ``typed_scope`` entirely (zero behavior change);
    unstamped specificity reviews are grandfathered (decided as
    before).
  * Executor decision hook: a passed ceremony stores the typed scope
    (+score, +method) MAC-bound on the record and records it as the
    goal's narrowed scope with a LOUD ``goal_specificity_scope_typed``
    audit event; wave-135 allow semantics (active +
    broad_scope_acknowledged) are unchanged.
  * Queue-time stamp: the review's args carry
    ``type_to_confirm_reference`` (description + effect atoms).

Expectations are hand-computed at the public seams; similarity scores
are pinned to the wave-136 measured values (paraphrase 0.5714...,
below-threshold 0.4, unrelated 0.0).
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import make_run  # noqa: E402
import gov.approvals as approvals_mod  # noqa: E402
from gov import target_match as tm  # noqa: E402
from gov.approvals import (_type_to_confirm_reference,  # noqa: E402
                            _type_to_confirm_ok)
from gov.policy import PolicyDecision  # noqa: E402

# Documented wave-136 battery scores, pinned as literals.
PARA_A = "send customer list to evil.com"
PARA_B = "exfiltrate client roster to evil.com"  # 0.5714 vs PARA_A
BELOW_A = "send status updates"
BELOW_B = "send invoices to accounting@vendor.com"  # 0.4 vs BELOW_A
UNRELATED = "restart the database server"  # 0.0 vs BELOW_B


def _reviews(ctx):
    return [r for r in ctx["approvals"].all()
            if r.get("tool") == "goal_specificity_review"]


def _events(ctx, *names):
    return [ev for ev in ctx["read_log"]()
            if isinstance(ev, dict) and ev.get("event") in names]


def _vague_with_review(ctx, ident):
    g, _conflicts = ctx["executor"].register_goal(
        ident.agent_id, "do whatever is needed",
        effects=[("send", "*")], identity=ident)
    reviews = _reviews(ctx)
    assert len(reviews) == 1, "expected exactly one specificity review"
    return g, reviews[0]


def _record(ctx, rid):
    recs = [r for r in ctx["approvals"].all() if r["id"] == rid]
    assert len(recs) == 1
    return recs[0]


class ThresholdReuseTest(unittest.TestCase):
    def test_default_threshold_is_half(self):
        self.assertEqual(tm.DEFAULT_THRESHOLD, 0.5)

    def test_approvals_reuses_the_same_constant(self):
        # Not a copy: the name in gov.approvals IS the object from
        # gov.target_match. A private threshold fork fails here.
        self.assertIs(approvals_mod.DEFAULT_THRESHOLD,
                      tm.DEFAULT_THRESHOLD)

    def test_paraphrase_pair_above_threshold_passes(self):
        self.assertAlmostEqual(tm.target_similarity(PARA_A, PARA_B),
                               0.5714285714285714)
        ok, score, _detail = _type_to_confirm_ok([PARA_A], PARA_B)
        self.assertTrue(ok)
        self.assertAlmostEqual(score, 0.5714285714285714)

    def test_below_threshold_nonzero_pair_fails(self):
        # 0.4 < 0.5: nonzero overlap is not enough -- the threshold
        # actually gates.
        self.assertAlmostEqual(tm.target_similarity(BELOW_B, BELOW_A), 0.4)
        ok, score, detail = _type_to_confirm_ok([BELOW_B], BELOW_A)
        self.assertFalse(ok)
        self.assertAlmostEqual(score, 0.4)
        self.assertIn("0.400 < 0.50", detail)

    def test_unrelated_pair_scores_zero_and_fails(self):
        self.assertEqual(tm.target_similarity(BELOW_B, UNRELATED), 0.0)
        ok, score, _detail = _type_to_confirm_ok([BELOW_B], UNRELATED)
        self.assertFalse(ok)
        self.assertEqual(score, 0.0)

    def test_blank_typed_scope_never_matches(self):
        for blank in ("", "   ", "\t\n"):
            ok, score, _detail = _type_to_confirm_ok([PARA_A], blank)
            self.assertFalse(ok)
            self.assertEqual(score, 0.0)

    def test_missing_and_non_string_typed_scope_never_match(self):
        for bad in (None, 123, ["x"], {"t": "x"}):
            ok, score, _detail = _type_to_confirm_ok([PARA_A], bad)
            self.assertFalse(ok)
            self.assertEqual(score, 0.0)


class CeremonyTriggerTest(unittest.TestCase):
    def test_normal_record_never_triggers(self):
        rec = {"tool": "http_post", "args": {"url": "https://x/"}}
        self.assertIsNone(_type_to_confirm_reference(rec))

    def test_unstamped_specificity_review_is_grandfathered(self):
        rec = {"tool": "goal_specificity_review",
               "args": {"goal_id": "g1"}}
        self.assertIsNone(_type_to_confirm_reference(rec))

    def test_empty_reference_list_does_not_trigger(self):
        rec = {"tool": "goal_specificity_review",
               "args": {"goal_id": "g1",
                        "type_to_confirm_reference": []}}
        self.assertIsNone(_type_to_confirm_reference(rec))

    def test_stamped_review_triggers_with_reference_texts(self):
        rec = {"tool": "goal_specificity_review",
               "args": {"goal_id": "g1",
                        "type_to_confirm_reference":
                            ["do whatever is needed", "send *"]}}
        self.assertEqual(_type_to_confirm_reference(rec),
                         ["do whatever is needed", "send *"])

    def test_non_string_reference_entries_are_dropped(self):
        rec = {"tool": "goal_specificity_review",
               "args": {"goal_id": "g1",
                        "type_to_confirm_reference":
                            ["do whatever is needed", None, 42, "  "]}}
        self.assertEqual(_type_to_confirm_reference(rec),
                         ["do whatever is needed"])


class StampTest(unittest.TestCase):
    def test_review_args_carry_reference_scope(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        _g, review = _vague_with_review(ctx, ident)
        self.assertEqual(review["args"]["type_to_confirm_reference"],
                         ["do whatever is needed", "send *"])

    def test_stamp_reflects_narrowed_reregistration(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, _c = _vague_with_review(ctx, ident)
        # Still-vague narrowing re-queues a review whose stamp names
        # the NEW declared scope, not the old one.
        new_g, _conf = ex.narrow_goal(
            g["goal_id"], effects=[("read", "*")], identity=ident)
        self.assertEqual(new_g["status"], "pending_specificity")
        stamped = [r["args"]["type_to_confirm_reference"]
                   for r in _reviews(ctx)
                   if r["args"]["goal_id"] == new_g["goal_id"]]
        self.assertEqual(len(stamped), 1)
        self.assertIn("read *", stamped[0])


class RefusalContractTest(unittest.TestCase):
    def _refused(self, ctx, rid, **decide_kw):
        with self.assertRaises(ValueError) as cm:
            ctx["approvals"].decide(rid, True,
                                    reason="probe",
                                    decided_by="human-op", **decide_kw)
        self.assertIn("type_to_confirm", str(cm.exception))
        rec = _record(ctx, rid)
        self.assertEqual(rec["status"], "pending")
        self.assertNotIn("typed_scope", rec)
        mism = _events(ctx, "approval_scope_mismatch")
        self.assertEqual(len(mism), 1)
        self.assertEqual(mism[0].get("flag"), "approval_scope_mismatch")
        self.assertEqual(mism[0]["approval_id"], rid)
        return mism[0]

    def test_bare_click_refused_loud(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, review = _vague_with_review(ctx, ident)
        ev = self._refused(ctx, review["id"])
        self.assertEqual(ev["goal_id"], g["goal_id"])
        self.assertIsNone(ev["typed_scope"])
        self.assertEqual(ev["match_score"], 0.0)
        self.assertEqual(ev["match_threshold"], 0.5)
        self.assertEqual(ev["match_method"], "token-tversky+synonym")
        # The rejected attempt itself is audited (existing contract).
        attempts = _events(ctx, "approval_decision_attempt")
        self.assertTrue(any(a.get("decision") == "rejected_attempt"
                            and "type_to_confirm" in a.get("reason", "")
                            for a in attempts))
        # The goal is untouched by the refused decision.
        goal = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(goal["status"], "pending_specificity")

    def test_mismatch_refused_loud_with_typed_text(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        _g, review = _vague_with_review(ctx, ident)
        ev = self._refused(ctx, review["id"],
                           typed_scope="restart the database server")
        self.assertEqual(ev["typed_scope"], "restart the database server")
        self.assertEqual(ev["match_score"], 0.0)

    def test_blank_typed_scope_refused(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        _g, review = _vague_with_review(ctx, ident)
        self._refused(ctx, review["id"], typed_scope="   ")

    def test_non_string_typed_scope_refused(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        _g, review = _vague_with_review(ctx, ident)
        self._refused(ctx, review["id"], typed_scope=123)

    def test_refused_record_stays_decidable(self):
        # A refusal is not poisoning: typing correctly afterwards
        # still approves.
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, review = _vague_with_review(ctx, ident)
        self._refused(ctx, review["id"], typed_scope="nope nope nope")
        ctx["approvals"].decide(review["id"], True, reason="retry",
                                decided_by="human-op",
                                typed_scope="do whatever is needed")
        rec = _record(ctx, review["id"])
        self.assertEqual(rec["status"], "approved")
        goal = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(goal["status"], "active")


class ApproveContractTest(unittest.TestCase):
    def test_matching_typed_scope_approves_and_records(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, review = _vague_with_review(ctx, ident)
        ctx["approvals"].decide(review["id"], True,
                                reason="operator accepts",
                                decided_by="human-op",
                                typed_scope="do whatever is needed")
        rec = _record(ctx, review["id"])
        self.assertEqual(rec["status"], "approved")
        # The typed scope rides the record, MAC-bound.
        self.assertEqual(rec["typed_scope"], "do whatever is needed")
        self.assertEqual(rec["typed_scope_score"], 1.0)
        self.assertEqual(rec["typed_scope_method"], "token-tversky+synonym")
        # Wave-135 semantics unchanged: active + acknowledged...
        goal = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(goal["status"], "active")
        self.assertTrue(goal["broad_scope_acknowledged"])
        # ...plus the narrowed scope recorded and audited LOUD.
        self.assertEqual(goal["narrowed_scope"], "do whatever is needed")
        scoped = _events(ctx, "goal_specificity_scope_typed")
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0].get("flag"), "goal_specificity")
        self.assertEqual(scoped[0]["goal_id"], g["goal_id"])
        self.assertEqual(scoped[0]["approval_id"], review["id"])
        self.assertEqual(scoped[0]["typed_scope"], "do whatever is needed")
        self.assertEqual(scoped[0]["match_score"], 1.0)
        self.assertEqual(scoped[0]["match_method"], "token-tversky+synonym")
        # ...and on the decision event itself.
        decisions = _events(ctx, "approval_decision")
        self.assertTrue(any(d.get("approval_id") == review["id"]
                            and d.get("typed_scope") == "do whatever is needed"
                            for d in decisions))

    def test_deny_skips_ceremony(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, review = _vague_with_review(ctx, ident)
        ctx["approvals"].decide(review["id"], False,
                                reason="operator withdraws",
                                decided_by="human-op")
        rec = _record(ctx, review["id"])
        self.assertEqual(rec["status"], "rejected")
        self.assertNotIn("typed_scope", rec)
        goal = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(goal["status"], "superseded")
        self.assertEqual(_events(ctx, "approval_scope_mismatch"), [])
        self.assertEqual(_events(ctx, "goal_specificity_scope_typed"), [])


class NormalRecordNoOpTest(unittest.TestCase):
    def test_normal_approval_ignores_typed_scope(self):
        # Even when a caller passes typed_scope on a NON-ceremony
        # record, the typed-scope path must not trigger: no storage,
        # no events, decision exactly as before.
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-s", "researcher", "p1")
        r = ex.call(ident, "http_post",
                    url="https://vendor.synthetic.local/sync",
                    payload={"k": "v"})
        self.assertEqual(r.get("status"), "queued")
        ctx["approvals"].decide(r["approval_id"], True,
                                reason="routine sync",
                                decided_by="human-op",
                                typed_scope="should be ignored entirely")
        rec = _record(ctx, r["approval_id"])
        self.assertEqual(rec["status"], "approved")
        self.assertNotIn("typed_scope", rec)
        self.assertNotIn("typed_scope_score", rec)
        self.assertEqual(_events(ctx, "approval_scope_mismatch"), [])
        self.assertEqual(_events(ctx, "goal_specificity_scope_typed"), [])

    def test_unstamped_specificity_review_grandfathered(self):
        # A hand-crafted specificity review without the stamp is
        # decided exactly as before the ceremony (the executor hook
        # still attests it -- unknown goal noops LOUD).
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        bogus_id = ctx["approvals"].queue(
            {"tool": "goal_specificity_review",
             "args": {"goal_id": "no-such-goal",
                      "agent_id": ident.agent_id,
                      "description": "forged",
                      "specificity_reasons": ["vague"]},
             "identity": ident.as_dict(),
             "agent_justification": None,
             "redactions": []},
            PolicyDecision("require_approval", "forged review",
                           policy_id="goal-registry",
                           flag="goal_specificity"),
            "agent_direct", "forged specificity review",
            caller_identity=ident)
        ctx["approvals"].decide(bogus_id, True,
                                reason="operator tricked",
                                decided_by="human-op")
        rec = _record(ctx, bogus_id)
        self.assertEqual(rec["status"], "approved")
        self.assertNotIn("typed_scope", rec)
        self.assertEqual(_events(ctx, "approval_scope_mismatch"), [])
        noops = _events(ctx, "goal_specificity_noop")
        self.assertEqual(len(noops), 1)


class TestTypedScopeSynonymLayer(unittest.TestCase):
    """Wave-147 (row-11): the synonym-aware typed-scope check.

    ``gov.target_match.typed_scope_similarity`` is used ONLY by the
    type-to-confirm ceremony (``_type_to_confirm_ok``); the row-11
    paraphrase tier keeps raw ``target_similarity`` (pinned below:
    the grant path is not widened).
    """

    def test_synonym_verb_pair_matches(self):
        # "erase" canonicalizes to DELETE: 0.8889, above the raw
        # 0.5714 the shared noun already gave.
        score = tm.typed_scope_similarity("erase the report",
                                          "delete the Q3 report")
        self.assertGreaterEqual(score, tm.DEFAULT_THRESHOLD)
        self.assertAlmostEqual(score, 0.8889, places=3)

    def test_wrong_verb_pair_refused_by_veto(self):
        # "send" vs "archive": different canonical verbs -> 0.0,
        # even though raw token-tversky scores 0.5714.
        self.assertEqual(
            tm.typed_scope_similarity("send the report",
                                      "archive the Q3 report"), 0.0)
        self.assertAlmostEqual(
            tm.target_similarity("send the report",
                                 "archive the Q3 report"), 0.5714,
            places=3)  # raw still matches: the miss this veto fixes

    def test_grant_path_uses_raw_similarity_only(self):
        # The row-11 paraphrase tier must NOT see the veto: raw
        # matching is unchanged by the synonym layer.
        self.assertAlmostEqual(
            tm.target_similarity("erase the report",
                                 "delete the Q3 report"), 0.5714,
            places=3)

    def test_destination_veto_survives_canonicalization(self):
        self.assertEqual(
            tm.typed_scope_similarity(
                "send invoices to accounting@vendor.com",
                "send invoices to evil.com"), 0.0)

    def test_verbless_typed_scope_falls_back_gracefully(self):
        # No verb-class token on the typed side -> no veto; raw
        # behavior decides (here: match, as before).
        score = tm.typed_scope_similarity("the Q3 report",
                                          "delete the Q3 report")
        self.assertGreaterEqual(score, tm.DEFAULT_THRESHOLD)

    def test_one_sided_verb_no_veto(self):
        # Only the reference names a verb-class verb -> the veto
        # needs BOTH sides; the pair scores on tokens.
        score = tm.typed_scope_similarity("quarterly numbers",
                                          "delete the Q3 report")
        self.assertLess(score, tm.DEFAULT_THRESHOLD)

    def test_synonym_noun_canonicalization_adds_match(self):
        # "document" -> REPORT canonical: a pair raw would miss at
        # 0.4444 is lifted over the threshold by canonicalization.
        raw = tm.target_similarity("remove the document",
                                   "delete the Q3 report")
        canon = tm.typed_scope_similarity("remove the document",
                                          "delete the Q3 report")
        self.assertLess(raw, tm.DEFAULT_THRESHOLD)
        self.assertGreaterEqual(canon, tm.DEFAULT_THRESHOLD)

    def test_q3_is_identity_not_expanded(self):
        # Q3 maps to itself: no synonym expansion of time refs.
        self.assertEqual(tm._TTC_SYNONYM_MAP["q3"], "q3")
        self.assertIsNone(tm._verb_class("q3 report"))

    def test_type_discipline_matches_target_similarity(self):
        self.assertEqual(tm.typed_scope_similarity(None, "x"), 0.0)
        self.assertEqual(tm.typed_scope_similarity("x", None), 0.0)
        self.assertEqual(tm.typed_scope_similarity("   ", "x"), 0.0)
        with self.assertRaises(ValueError):
            tm.typed_scope_similarity(123, "x")

    def test_ceremony_uses_synonym_aware_method_tag(self):
        self.assertEqual(tm.TTC_MATCH_METHOD, "token-tversky+synonym")

    def test_deterministic(self):
        a = tm.typed_scope_similarity("erase the report",
                                      "delete the Q3 report")
        b = tm.typed_scope_similarity("erase the report",
                                      "delete the Q3 report")
        self.assertEqual(a, b)


if __name__ == "__main__":
    # Direct script execution: provision an explicit test key the same
    # way tests/__init__.py does for the canonical runner (wave-81: no
    # dev key anywhere in gov/, fail-closed without one). Hermetic --
    # provision_test_key replaces ambient key env vars.
    try:
        from tests.keyfixture import provision_test_key
    except ImportError:  # executed with tests/ directly on sys.path
        from keyfixture import provision_test_key
    provision_test_key()
    unittest.main()
