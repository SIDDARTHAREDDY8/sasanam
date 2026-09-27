"""Executor-level tests for vague-goal registration hardening (wave-135).

Seams under test:
  * ToolExecutor.register_goal: vague -> pending_specificity + exactly
    one goal_specificity_review queued (LOUD on queue failure);
    specific -> active, no review.
  * ToolExecutor.narrow_goal: identity required (F42), still-vague
    re-narrowing re-queues, conflicting narrowing queues conflict
    review, specific narrowing activates with no ack flag.
  * The approval-decision hook: goal_specificity_review allow/deny
    resolves the goal (active+acknowledged / superseded); unrelated
    decisions touch no goal; unknown goal ids noop LOUD.

Expectations are hand-computed at the public seams.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import make_run  # noqa: E402


def _specificity_reviews(ctx):
    return [r for r in ctx["approvals"].all()
            if r.get("tool") == "goal_specificity_review"]


def _events(ctx, *names):
    return [ev for ev in ctx["read_log"]()
            if isinstance(ev, dict) and ev.get("event") in names]


def _vague(ctx, ident):
    return ctx["executor"].register_goal(
        ident.agent_id, "do whatever is needed",
        effects=[("send", "*")], identity=ident)


class SpecificityQueueingTest(unittest.TestCase):
    def test_vague_registration_queues_exactly_one_review(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, conflicts = _vague(ctx, ident)
        self.assertEqual(g["status"], "pending_specificity")
        self.assertFalse(g["broad_scope_acknowledged"])
        self.assertEqual(conflicts, [])
        reviews = _specificity_reviews(ctx)
        self.assertEqual(len(reviews), 1)
        args = reviews[0]["args"]
        self.assertEqual(args["goal_id"], g["goal_id"])
        self.assertTrue(args["specificity_reasons"])
        pending = _events(ctx, "goal_specificity_pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].get("flag"), "goal_specificity")
        self.assertEqual(pending[0]["goal_id"], g["goal_id"])

    def test_specific_registration_queues_no_review(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-s", "researcher", "p1")
        g, conflicts = ex.register_goal(
            ident.agent_id, "sync vendor reports",
            effects=[("send", "vendor.synthetic.local")], identity=ident)
        self.assertEqual(g["status"], "active")
        self.assertEqual(conflicts, [])
        self.assertEqual(_specificity_reviews(ctx), [])
        self.assertEqual(_events(ctx, "goal_specificity_pending"), [])

    def test_queue_failure_stays_loud(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        with mock.patch.object(ctx["approvals"], "queue",
                               side_effect=RuntimeError("queue down")):
            g, _conflicts = _vague(ctx, ident)
        # The pending signal is LOUD in the log even though the
        # human review item never got queued.
        self.assertEqual(g["status"], "pending_specificity")
        self.assertEqual(_specificity_reviews(ctx), [])
        failed = _events(ctx, "goal_specificity_queue_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].get("flag"), "goal_specificity")
        self.assertEqual(failed[0]["goal_id"], g["goal_id"])

    def test_specificity_helper_signatures(self):
        # The routing helpers shared by register_goal and narrow_goal
        # must stay in sync: one review type, one queueing path.
        ex = make_run()["executor"]
        self.assertTrue(callable(ex._queue_specificity_review))
        self.assertTrue(callable(ex._queue_conflict_review))


class SpecificityDecisionHookTest(unittest.TestCase):
    def _vague_with_review(self):
        ctx = make_run()
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, _conflicts = _vague(ctx, ident)
        reviews = _specificity_reviews(ctx)
        self.assertEqual(len(reviews), 1)
        return ctx, ident, g, reviews[0]

    def test_allow_decision_activates_and_acknowledges(self):
        ctx, _ident, g, review = self._vague_with_review()
        ctx["approvals"].decide(review["id"], True,
                                reason="operator accepts the mandate",
                                decided_by="human-op")
        rec = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(rec["status"], "active")
        self.assertTrue(rec["broad_scope_acknowledged"])
        resolved = _events(ctx, "goal_specificity_resolved")
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["decision"], "acknowledged")
        self.assertTrue(resolved[0]["broad_scope_acknowledged"])
        self.assertEqual(resolved[0]["approval_id"], review["id"])

    def test_deny_decision_supersedes(self):
        ctx, _ident, g, review = self._vague_with_review()
        ctx["approvals"].decide(review["id"], False,
                                reason="operator withdraws the mandate",
                                decided_by="human-op")
        rec = ctx["executor"]._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(rec["status"], "superseded")
        self.assertFalse(rec["broad_scope_acknowledged"])
        resolved = _events(ctx, "goal_specificity_resolved")
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["decision"], "withdrawn")
        self.assertFalse(resolved[0]["broad_scope_acknowledged"])

    def test_decision_on_non_goal_record_touches_no_goal(self):
        ctx, _ident, g, review = self._vague_with_review()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-u", "researcher", "p1")
        # An unrelated approval item (an http_post) goes through
        # decide(): the specificity hook must ignore it.
        r = ex.call(ident, "http_post",
                    url="https://vendor.synthetic.local/sync",
                    payload={"k": "v"})
        self.assertEqual(r.get("status"), "queued")
        ctx["approvals"].decide(r["approval_id"], True,
                                reason="routine sync",
                                decided_by="human-op")
        rec = ex._goal_registry.get_goal(g["goal_id"])
        self.assertEqual(rec["status"], "pending_specificity")
        self.assertEqual(_events(ctx, "goal_specificity_resolved"), [])
        self.assertEqual(_events(ctx, "goal_specificity_noop"), [])

    def test_decision_on_unknown_goal_noops_loud(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        # Hand-crafted review naming an unknown goal (what a forged
        # or stale review record would look like): the hook must
        # noop LOUD, not silently skip and not touch any real goal.
        g, _c = _vague(ctx, ident)
        from gov.policy import PolicyDecision
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
        self.assertEqual(ex._goal_registry.get_goal(
            g["goal_id"])["status"], "pending_specificity")
        noops = _events(ctx, "goal_specificity_noop")
        self.assertEqual(len(noops), 1)
        self.assertEqual(noops[0]["goal_id"], "no-such-goal")


class NarrowGoalExecutorTest(unittest.TestCase):
    def test_narrow_specific_replacement_activates_without_ack(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, _c = _vague(ctx, ident)
        new_g, conflicts = ex.narrow_goal(
            g["goal_id"], effects=[("send", "vendor.synthetic.local")],
            identity=ident, note="operator narrows")
        self.assertEqual(new_g["status"], "active")
        self.assertFalse(new_g.get("broad_scope_acknowledged"))
        self.assertEqual(conflicts, [])
        self.assertEqual(ex._goal_registry.get_goal(
            g["goal_id"])["status"], "superseded")
        narrowed = _events(ctx, "goal_narrowed")
        self.assertEqual(len(narrowed), 1)
        self.assertEqual(narrowed[0]["old_goal_id"], g["goal_id"])
        self.assertEqual(narrowed[0]["new_goal_id"], new_g["goal_id"])
        # The narrowed replacement is specific: no new review queued.
        self.assertEqual(len(_specificity_reviews(ctx)), 1)

    def test_narrow_still_vague_requeues_review(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, _c = _vague(ctx, ident)
        new_g, _conflicts = ex.narrow_goal(
            g["goal_id"], effects=[("send", "*")],
            identity=ident, note="operator still vague")
        self.assertEqual(new_g["status"], "pending_specificity")
        # One review per vague registration: the original and the
        # re-narrowing's own review.
        reviews = _specificity_reviews(ctx)
        self.assertEqual(len(reviews), 2)
        self.assertEqual(
            {r["args"]["goal_id"] for r in reviews},
            {g["goal_id"], new_g["goal_id"]})

    def test_narrow_requires_identity(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        g, _c = _vague(ctx, ident)
        with self.assertRaises(TypeError):
            ex.narrow_goal(g["goal_id"],
                           effects=[("send", "vendor.synthetic.local")])
        # Fail-closed: the pending goal is untouched.
        self.assertEqual(ex._goal_registry.get_goal(
            g["goal_id"])["status"], "pending_specificity")

    def test_narrow_conflicting_replacement_queues_conflict_review(self):
        ctx = make_run()
        ex = ctx["executor"]
        ident = ctx["mint_identity"]("agent-v", "researcher", "p1")
        # An active goal the narrowing will conflict with.
        other, _ = ex.register_goal(
            ident.agent_id, "preserve vendor data",
            effects=[("preserve", "vendor.synthetic.local")],
            identity=ident)
        self.assertEqual(other["status"], "active")
        g, _c = _vague(ctx, ident)
        new_g, conflicts = ex.narrow_goal(
            g["goal_id"], effects=[("delete", "vendor.synthetic.local")],
            identity=ident, note="operator narrows into conflict")
        self.assertTrue(conflicts)
        self.assertEqual(new_g["status"], "active")
        conflict_reviews = [r for r in ctx["approvals"].all()
                            if r.get("tool") == "goal_conflict_review"]
        self.assertEqual(len(conflict_reviews), 1)
        self.assertEqual(conflict_reviews[0]["args"]["goal_id"],
                         new_g["goal_id"])


if __name__ == "__main__":
    unittest.main()
