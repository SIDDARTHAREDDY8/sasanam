"""Unit tests for gov.goals: registration, conflict detection, chaining."""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import goals  # noqa: E402


class NormalizeTargetTest(unittest.TestCase):
    def test_case_and_whitespace_insensitive(self):
        self.assertEqual(goals.normalize_target("  Temp   FILES "),
                         "temp files")

    def test_no_fuzzy_matching(self):
        # Deliberate: exact normalized matching only.
        self.assertNotEqual(goals.normalize_target("temp files"),
                            goals.normalize_target("temp_files"))
        self.assertNotEqual(goals.normalize_target("temp files"),
                            goals.normalize_target("temporary storage"))


class RegisterValidationTest(unittest.TestCase):
    def setUp(self):
        self.reg = goals.GoalRegistry()

    def test_unknown_verb_refused(self):
        with self.assertRaises(ValueError):
            self.reg.register("a", "r", "d", effects=[("vaporize", "x")])

    def test_unknown_constraint_kind_refused(self):
        with self.assertRaises(ValueError):
            self.reg.register("a", "r", "d",
                              constraints=[("maybe", "delete", "x")])

    def test_malformed_atom_refused(self):
        with self.assertRaises(ValueError):
            self.reg.register("a", "r", "d", effects=[("delete",)])

    def test_empty_description_refused(self):
        with self.assertRaises(ValueError):
            self.reg.register("a", "r", "   ")

    def test_targets_normalized_at_registration(self):
        g, _ = self.reg.register("a", "r", "d",
                                 effects=[("delete", "  Temp FILES ")])
        self.assertEqual(g["effects"], [["delete", "temp files"]])


class DetectConflictTest(unittest.TestCase):
    def setUp(self):
        self.reg = goals.GoalRegistry()

    def _mk(self, effects=(), constraints=()):
        return {"goal_id": "new", "effects": list(effects),
                "constraints": list(constraints), "status": "active"}

    def test_contradiction(self):
        old, _ = self.reg.register("a", "r", "keep", effects=[
            ("preserve", "temp files")])
        cs = goals.detect_conflict(
            self._mk(effects=[("delete", "temp files")]),
            self.reg.active_goals())
        self.assertEqual(len(cs), 1)
        self.assertEqual(cs[0]["type"], "contradiction")
        self.assertEqual(cs[0]["existing_goal_id"], old["goal_id"])

    def test_no_contradiction_different_target(self):
        self.reg.register("a", "r", "keep", effects=[
            ("preserve", "temp files")])
        cs = goals.detect_conflict(
            self._mk(effects=[("delete", "cache")]),
            self.reg.active_goals())
        self.assertEqual(cs, [])

    def test_exclusive_write_collision(self):
        self.reg.register("a", "r", "own", effects=[
            ("exclusive_write", "ledger")])
        cs = goals.detect_conflict(
            self._mk(effects=[("exclusive_write", "ledger")]),
            self.reg.active_goals())
        self.assertTrue(any(c["type"] == "resource_contention"
                            for c in cs))

    def test_exclusive_write_vs_plain_write(self):
        self.reg.register("a", "r", "own", effects=[
            ("exclusive_write", "ledger")])
        cs = goals.detect_conflict(
            self._mk(effects=[("write", "ledger")]),
            self.reg.active_goals())
        self.assertTrue(any(c["type"] == "resource_contention"
                            for c in cs))

    def test_plain_writes_do_not_contend(self):
        self.reg.register("a", "r", "w", effects=[("write", "ledger")])
        cs = goals.detect_conflict(
            self._mk(effects=[("write", "ledger")]),
            self.reg.active_goals())
        self.assertEqual(cs, [])

    def test_constraint_violation(self):
        self.reg.register("a", "r", "safe", effects=[("write", "t")],
                          constraints=[("forbid", "delete", "t")])
        cs = goals.detect_conflict(
            self._mk(effects=[("delete", "t")]),
            self.reg.active_goals())
        self.assertTrue(any(c["type"] == "constraint_violation"
                            for c in cs))

    def test_reverse_constraint_violation(self):
        self.reg.register("a", "r", "cleaner", effects=[("delete", "t")])
        cs = goals.detect_conflict(
            self._mk(constraints=[("forbid", "delete", "t")]),
            self.reg.active_goals())
        self.assertTrue(any(c["type"] == "constraint_violation"
                            for c in cs))

    def test_superseded_goals_ignored(self):
        g, _ = self.reg.register("a", "r", "keep",
                                 effects=[("preserve", "t")])
        self.reg.set_status(g["goal_id"], "superseded")
        cs = goals.detect_conflict(
            self._mk(effects=[("delete", "t")]),
            self.reg.active_goals())
        self.assertEqual(cs, [])

    def test_paraphrase_dodge_misses(self):
        # Honest ceiling: different normalized targets do not collide.
        self.reg.register("a", "r", "keep", effects=[
            ("preserve", "temp files")])
        cs = goals.detect_conflict(
            self._mk(effects=[("delete", "temporary storage")]),
            self.reg.active_goals())
        self.assertEqual(cs, [])


class ChainTest(unittest.TestCase):
    def test_chain_verifies(self):
        reg = goals.GoalRegistry()
        reg.register("a", "r", "one", effects=[("read", "x")])
        reg.register("b", "r", "two", effects=[("read", "y")])
        ok, reason = reg.verify_chain()
        self.assertTrue(ok, reason)

    def test_tamper_breaks_chain(self):
        reg = goals.GoalRegistry()
        g, _ = reg.register("a", "r", "one", effects=[("read", "x")])
        reg.register("b", "r", "two", effects=[("read", "y")])
        g["effects"] = [["delete", "x"]]
        ok, _ = reg.verify_chain()
        self.assertFalse(ok)

    def test_audit_events_fire(self):
        events = []
        reg = goals.GoalRegistry(audit=events.append)
        reg.register("a", "r", "keep", effects=[("preserve", "t")])
        reg.register("b", "r", "drop", effects=[("delete", "t")])
        kinds = [e["event"] for e in events]
        self.assertEqual(kinds.count("goal_registered"), 2)
        self.assertEqual(kinds.count("goal_conflict"), 1)
        self.assertEqual(events[-1]["flag"], "goal_conflict")

    def test_set_status_unknown_goal(self):
        reg = goals.GoalRegistry()
        with self.assertRaises(ValueError):
            reg.set_status("nope", "superseded")


if __name__ == "__main__":
    unittest.main()
