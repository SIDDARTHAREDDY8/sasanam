"""Unit tests for approval-decision -> goal-resolution wiring (wave-134).

Seams under test:
  * gov.goals.apply_approval_resolution (goals seam): allow / deny /
    unknown ids / already-resolved / missing new goal / dedup /
    non-registry argument.
  * gov.goals.GoalRegistry.get_goal and set_status(approval_id=...).
  * gov.goals.conflict_review_goal_ids: shared extractor.
  * gov.approvals.ApprovalQueue.set_decision_hook: write-once, type
    check, hook fired from decide(), goal_ids on the approval_decision
    event, raising hook never breaks decide().

Expectations are hand-computed at the public seams.
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import make_run  # noqa: E402
from gov import goals
from gov.approvals import ApprovalQueue, DecisionHookAlreadySetError
from gov.log import ActionLog
from gov.policy import PolicyDecision


def _reg(events=None):
    """Registry with two conflicting goals; returns (reg, new, old)."""
    r = goals.GoalRegistry(audit=events.append if events is not None
                           else None)
    old, _ = r.register("agent-a", "run-1", "preserve temp files",
                        effects=[("preserve", "temp files")])
    new, conflicts = r.register(
        "agent-b", "run-1", "delete all temp files",
        effects=[("delete", "temp files")])
    assert conflicts, "test fixture: expected a conflict"
    return r, new, old


class GetGoalTest(unittest.TestCase):
    def test_get_goal_returns_record_or_none(self):
        r, new, _old = _reg()
        self.assertIs(r.get_goal(new["goal_id"]), new)
        self.assertIsNone(r.get_goal("no-such-goal"))


class ConflictReviewGoalIdsTest(unittest.TestCase):
    def test_order_dedup_and_shape(self):
        args = {"goal_id": "new-1",
                "conflicts": [{"existing_goal_id": "old-1"},
                              {"existing_goal_id": "old-2"},
                              {"existing_goal_id": "old-1"},
                              {"existing_goal_id": "new-1"},
                              {"no_id": True},
                              "not-a-dict"]}
        self.assertEqual(goals.conflict_review_goal_ids(args),
                         ["new-1", "old-1", "old-2"])

    def test_non_dict_args_empty(self):
        self.assertEqual(goals.conflict_review_goal_ids(None), [])
        self.assertEqual(goals.conflict_review_goal_ids("x"), [])
        self.assertEqual(goals.conflict_review_goal_ids({}), [])


class SetStatusApprovalRefTest(unittest.TestCase):
    def test_approval_id_rides_status_event(self):
        events = []
        r, new, _old = _reg(events)
        r.set_status(new["goal_id"], "superseded", approval_id="appr-1")
        changed = [e for e in events
                   if e.get("event") == "goal_status_changed"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["approval_id"], "appr-1")

    def test_approval_id_defaults_to_none(self):
        events = []
        r, new, _old = _reg(events)
        r.set_status(new["goal_id"], "superseded")
        changed = [e for e in events
                   if e.get("event") == "goal_status_changed"]
        self.assertIsNone(changed[0].get("approval_id"))


class ApplyApprovalResolutionTest(unittest.TestCase):
    def test_allow_supersedes_existing_new_stands(self):
        events = []
        r, new, old = _reg(events)
        summary = goals.apply_approval_resolution(
            r, new_goal_id=new["goal_id"],
            existing_goal_ids=[old["goal_id"]],
            approved=True, approval_id="appr-allow", audit=events.append)
        self.assertEqual(r.get_goal(new["goal_id"])["status"], "active")
        self.assertEqual(r.get_goal(old["goal_id"])["status"],
                         "superseded")
        self.assertEqual(summary["decision"], "approved")
        self.assertEqual(summary["superseded_goal_ids"], [old["goal_id"]])
        self.assertEqual(summary["standing_goal_ids"], [new["goal_id"]])
        self.assertEqual(summary["noop"], [])
        changed = [e for e in events
                   if e.get("event") == "goal_status_changed"
                   and e.get("goal_id") == old["goal_id"]]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["approval_id"], "appr-allow")
        resolutions = [e for e in events
                       if e.get("event") == "goal_resolution"]
        self.assertEqual(len(resolutions), 1)
        self.assertEqual(resolutions[0]["approval_id"], "appr-allow")

    def test_deny_supersedes_new_existing_untouched(self):
        events = []
        r, new, old = _reg(events)
        summary = goals.apply_approval_resolution(
            r, new_goal_id=new["goal_id"],
            existing_goal_ids=[old["goal_id"]],
            approved=False, approval_id="appr-deny", audit=events.append)
        self.assertEqual(r.get_goal(new["goal_id"])["status"],
                         "superseded")
        self.assertEqual(r.get_goal(old["goal_id"])["status"], "active")
        self.assertEqual(summary["decision"], "rejected")
        self.assertEqual(summary["superseded_goal_ids"], [new["goal_id"]])
        # Deny leaves the existing goals standing (unaffected, not noop).
        self.assertIn(old["goal_id"], summary["standing_goal_ids"])
        self.assertEqual(summary["noop"], [])

    def test_unknown_ids_noop_loud_no_raise(self):
        events = []
        r, _new, old = _reg(events)
        summary = goals.apply_approval_resolution(
            r, new_goal_id="goal-missing",
            existing_goal_ids=["goal-also-missing"],
            approved=True, approval_id="appr-x", audit=events.append)
        self.assertEqual(len(summary["noop"]), 2)
        noops = [e for e in events
                 if e.get("event") == "goal_resolution_noop"]
        self.assertEqual(len(noops), 2)
        self.assertTrue(all(e.get("flag") == "goal_resolution_noop"
                            for e in noops))
        self.assertTrue(all(e.get("approval_id") == "appr-x"
                            for e in noops))
        # Nothing transitioned.
        self.assertEqual([e for e in events
                          if e.get("event") == "goal_status_changed"],
                         [])
        self.assertEqual(r.get_goal(old["goal_id"])["status"], "active")

    def test_already_resolved_noop_not_reapplied(self):
        events = []
        r, new, old = _reg(events)
        r.set_status(old["goal_id"], "superseded")  # resolved separately
        n_changed = len([e for e in events
                         if e.get("event") == "goal_status_changed"])
        summary = goals.apply_approval_resolution(
            r, new_goal_id=new["goal_id"],
            existing_goal_ids=[old["goal_id"]],
            approved=True, approval_id="appr-y", audit=events.append)
        self.assertEqual(len([e for e in events
                              if e.get("event") == "goal_status_changed"]),
                         n_changed)
        self.assertEqual(len(summary["noop"]), 1)
        self.assertEqual(summary["noop"][0][0], old["goal_id"])

    def test_allow_when_new_already_superseded_noops(self):
        events = []
        r, new, old = _reg(events)
        r.set_status(new["goal_id"], "superseded")
        summary = goals.apply_approval_resolution(
            r, new_goal_id=new["goal_id"],
            existing_goal_ids=[old["goal_id"]],
            approved=True, approval_id="appr-z", audit=events.append)
        # Fail-closed: an allow does NOT reactivate a separately
        # superseded new goal.
        self.assertEqual(r.get_goal(new["goal_id"])["status"],
                         "superseded")
        self.assertTrue(any(gid == new["goal_id"]
                            for gid, _r in summary["noop"]))

    def test_missing_new_goal_id_noops(self):
        events = []
        r, _new, old = _reg(events)
        summary = goals.apply_approval_resolution(
            r, new_goal_id=None, existing_goal_ids=[old["goal_id"]],
            approved=True, approval_id="appr-n", audit=events.append)
        self.assertEqual(len(summary["noop"]), 1)
        self.assertEqual(summary["noop"][0][0], None)
        # The allow still resolves the known half of the conflict.
        self.assertEqual(r.get_goal(old["goal_id"])["status"],
                         "superseded")

    def test_duplicate_existing_ids_deduped(self):
        events = []
        r, new, old = _reg(events)
        summary = goals.apply_approval_resolution(
            r, new_goal_id=new["goal_id"],
            existing_goal_ids=[old["goal_id"], old["goal_id"],
                               new["goal_id"]],
            approved=True, approval_id="appr-d", audit=events.append)
        self.assertEqual(summary["superseded_goal_ids"], [old["goal_id"]])

    def test_non_registry_rejected(self):
        with self.assertRaises(ValueError):
            goals.apply_approval_resolution(
                {"not": "a registry"}, new_goal_id="x",
                existing_goal_ids=[], approved=True, approval_id="a")


class AttestedExistingIdsTest(unittest.TestCase):
    """F179: detector attestation at decision time."""

    def _fixture(self, events):
        r = goals.GoalRegistry(audit=events.append)
        victim, vconf = r.register("agent-v", "run-1",
                                   "keep the archive intact",
                                   effects=[("preserve", "archive")])
        assert not vconf
        fresh, fconf = r.register("agent-f", "run-1", "tidy the desk",
                                  effects=[("write", "desk notes")])
        assert not fconf
        return r, fresh, victim

    def test_unattested_arg_named_goal_never_superseded_loud_noop(self):
        events = []
        r, fresh, victim = self._fixture(events)
        vid = victim["goal_id"]
        summary = goals.apply_approval_resolution(
            r, new_goal_id=fresh["goal_id"],
            existing_goal_ids=[vid],
            approved=True, approval_id="appr-f179",
            audit=events.append, attested_existing_ids=set())
        self.assertEqual(r.get_goal(vid)["status"], "active")
        self.assertEqual(summary["superseded_goal_ids"], [])
        noops = [e for e in events
                 if e.get("event") == "goal_resolution_noop"
                 and e.get("goal_id") == vid
                 and e.get("approval_id") == "appr-f179"]
        self.assertEqual(len(noops), 1)
        self.assertEqual(noops[0]["flag"], "goal_resolution_noop")
        self.assertIn("not attested by the conflict detector at "
                      "decision time", noops[0]["reason"])

    def test_attested_goal_still_superseded(self):
        events = []
        r, fresh, victim = self._fixture(events)
        vid = victim["goal_id"]
        summary = goals.apply_approval_resolution(
            r, new_goal_id=fresh["goal_id"],
            existing_goal_ids=[vid],
            approved=True, approval_id="appr-f179-ok",
            audit=events.append,
            attested_existing_ids={vid})
        self.assertEqual(r.get_goal(vid)["status"], "superseded")
        self.assertEqual(summary["superseded_goal_ids"], [vid])
        self.assertEqual(summary["noop"], [])

    def test_none_preserves_legacy_behavior(self):
        # attested_existing_ids=None (default): exactly the old
        # behavior -- the arg-named goal is superseded.
        events = []
        r, fresh, victim = self._fixture(events)
        vid = victim["goal_id"]
        summary = goals.apply_approval_resolution(
            r, new_goal_id=fresh["goal_id"],
            existing_goal_ids=[vid],
            approved=True, approval_id="appr-f179-legacy",
            audit=events.append)
        self.assertEqual(r.get_goal(vid)["status"], "superseded")
        self.assertEqual(summary["superseded_goal_ids"], [vid])


class ForgedReviewHookTest(unittest.TestCase):
    """F179 hook-level: a forged goal_conflict_review (crib of the
    wave-134 red-audit b1) decided allow through a real
    executor+queue."""

    def test_forged_review_allow_leaves_victim_active(self):
        from gov.log import read_entries
        ctx = make_run()
        ex, q = ctx["executor"], ctx["approvals"]
        ident = ctx["mint_identity"]("agent-x", "worker", "user-1")
        victim, _ = ex.register_goal("agent-v", "keep the archive intact",
                                     effects=[("preserve", "archive")],
                                     identity=ident)
        fresh, _ = ex.register_goal("agent-f", "tidy the desk",
                                    effects=[("write", "desk notes")],
                                    identity=ident)
        vid, fid = victim["goal_id"], fresh["goal_id"]
        aid = q.queue(
            {"tool": "goal_conflict_review",
             "args": {"goal_id": fid,
                      "conflicts": [{"existing_goal_id": vid,
                                     "type": "forged",
                                     "explanation": "forged by test"}]},
             "identity": ident.as_dict(),
             "agent_justification": None,
             "redactions": []},
            PolicyDecision("require_approval", "forged review test",
                           policy_id="goal-registry",
                           flag="goal_conflict"),
            "agent_direct", "forged review", caller_identity=ident)
        q.decide(aid, True, "human allows", decided_by="human-operator")
        # The victim is uninvolved: never superseded, still active.
        self.assertEqual(ex._goal_registry.get_goal(vid)["status"],
                         "active")
        # The decision itself still records.
        self.assertEqual(q.get(aid)["status"], "approved")
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        dec = [e for e in evts
               if e.get("event") == "approval_decision"
               and e.get("approval_id") == aid]
        self.assertTrue(dec)
        # ... and the forgery is LOUD, never silent.
        noops = [e for e in evts
                 if e.get("event") == "goal_resolution_noop"
                 and e.get("goal_id") == vid
                 and e.get("approval_id") == aid]
        self.assertEqual(len(noops), 1)
        self.assertEqual(noops[0]["flag"], "goal_resolution_noop")
        self.assertIn("not attested by the conflict detector at "
                      "decision time", noops[0]["reason"])
        # No status change was chained for the victim.
        changed = [e for e in evts
                   if e.get("event") == "goal_status_changed"
                   and e.get("goal_id") == vid]
        self.assertEqual(changed, [])


class HookFailureLoudTest(unittest.TestCase):
    """F180: an inner failure of the executor's post-decision hook
    must reach the queue's LOUD decision_hook_failed handler (the
    single choke point) -- never be swallowed inside the hook."""

    def test_inner_resolution_failure_audited_loud(self):
        from gov.log import read_entries
        ctx = make_run()
        ex, q = ctx["executor"], ctx["approvals"]
        ia = ctx["mint_identity"]("agent-a", "worker", "user-1")
        ib = ctx["mint_identity"]("agent-b", "worker", "user-1")
        _old, _ = ex.register_goal("agent-a",
                                   "preserve temp files for audit",
                                   effects=[("preserve", "temp files")],
                                   identity=ia)
        _new, conflicts = ex.register_goal(
            "agent-b", "delete all temp files",
            effects=[("delete", "temp files")], identity=ib)
        self.assertTrue(conflicts)
        queued = [r for r in q.all()
                  if r.get("tool") == "goal_conflict_review"]
        self.assertTrue(queued)
        aid = queued[0]["id"]
        orig = goals.apply_approval_resolution

        def boom(*a, **k):
            raise RuntimeError("simulated resolution bug")

        goals.apply_approval_resolution = boom
        try:
            q.decide(aid, True, "human allows",
                     decided_by="human-operator")
        finally:
            goals.apply_approval_resolution = orig
        evts = read_entries(ctx["run_dir"] / "actions.jsonl")
        loud = [e for e in evts
                if e.get("event") == "decision_hook_failed"
                and e.get("approval_id") == aid]
        self.assertTrue(loud,
                        "inner hook failure was silent: no LOUD "
                        "decision_hook_failed event")
        self.assertEqual(loud[0]["flag"], "decision_hook_failed")
        # The human decision still stands and is recorded.
        self.assertEqual(q.get(aid)["status"], "approved")
        dec = [e for e in evts
               if e.get("event") == "approval_decision"
               and e.get("approval_id") == aid]
        self.assertTrue(dec)


class DecisionHookTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="goalres_hook_")
        self.log = ActionLog(os.path.join(self.tmp, "actions.jsonl"))
        self.q = ApprovalQueue(self.tmp, self.log)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_set_decision_hook_write_once(self):
        self.q.set_decision_hook(lambda *a: None)
        with self.assertRaises(DecisionHookAlreadySetError):
            self.q.set_decision_hook(lambda *a: None)

    def test_set_decision_hook_rejects_non_callable(self):
        with self.assertRaises(TypeError):
            self.q.set_decision_hook("not-callable")

    def test_goal_review_goal_ids_helper(self):
        from gov.approvals import _goal_review_goal_ids
        rec = {"tool": "goal_conflict_review",
               "args": {"goal_id": "new-1",
                        "conflicts": [{"existing_goal_id": "old-1"},
                                      {"existing_goal_id": "old-2"},
                                      {"existing_goal_id": "old-1"}]}}
        self.assertEqual(_goal_review_goal_ids(rec),
                         ["new-1", "old-1", "old-2"])
        self.assertIsNone(_goal_review_goal_ids({"tool": "http_post",
                                                 "args": {}}))
        self.assertIsNone(_goal_review_goal_ids(None))


if __name__ == "__main__":
    unittest.main()
