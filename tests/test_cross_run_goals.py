"""Unit tests for cross-run goal persistence + laundering detection.

Seams under test: GoalRegistry.save / GoalRegistry.load,
GoalPersistenceError, the set_status/verify_chain fix, and
detect_cross_run_laundering. Expectations are hand-computed at the
public seams.
"""
import json
import os
import shutil
import tempfile
import unittest

from gov import goals


def _reg_with(agent="a1", run="run-1"):
    r = goals.GoalRegistry()
    g, _ = r.register(agent, run, "read-only audit",
                     effects=[("read", "sandbox/reports/note.txt")],
                     constraints=[("forbid", "write",
                                   "sandbox/reports/note.txt")])
    return r, g


class PersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="goalx_")
        self.path = os.path.join(self.tmp, "goals.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip_preserves_records_statuses_and_chain(self):
        r, g = _reg_with()
        r.set_status(g["goal_id"], "superseded")
        r.save(self.path)
        r2 = goals.GoalRegistry.load(self.path)
        self.assertEqual(len(r2._goals), 1)
        self.assertEqual(r2._goals[0]["goal_id"], g["goal_id"])
        self.assertEqual(r2._goals[0]["status"], "superseded")
        ok, reason = r2.verify_chain()
        self.assertTrue(ok, reason)
        # The chain continues: new registrations extend the same
        # tamper-evident history.
        g2, _ = r2.register("a1", "run-2", "migrate",
                            effects=[("write", "sandbox/reports/note.txt")])
        self.assertEqual(r2._goals[-1]["prev_goal_digest"],
                         g["goal_digest"])
        ok, reason = r2.verify_chain()
        self.assertTrue(ok, reason)
        self.assertEqual(r2._prev_digest, g2["goal_digest"])

    def test_set_status_does_not_break_chain(self):
        # Regression: resolving a goal must not read as "tampered".
        r, g = _reg_with()
        r.set_status(g["goal_id"], "superseded")
        ok, reason = r.verify_chain()
        self.assertTrue(ok, reason)

    def test_effect_tamper_still_breaks_chain(self):
        r, g = _reg_with()
        r.set_status(g["goal_id"], "superseded")
        g["effects"] = [["delete", "sandbox/reports/note.txt"]]
        ok, _ = r.verify_chain()
        self.assertFalse(ok)

    def test_tampered_file_refused(self):
        r, _ = _reg_with()
        r.save(self.path)
        lines = open(self.path).read().splitlines()
        rec = json.loads(lines[1])
        rec["description"] = "forged description"
        lines[1] = json.dumps(rec, sort_keys=True,
                              separators=(",", ":"))
        open(self.path, "w").write("\n".join(lines) + "\n")
        with self.assertRaises(goals.GoalPersistenceError):
            goals.GoalRegistry.load(self.path)

    def test_truncated_file_refused(self):
        r, _ = _reg_with()
        r.save(self.path)
        lines = open(self.path).read().splitlines()
        open(self.path, "w").write("\n".join(lines[:-1]) + "\n")
        with self.assertRaises(goals.GoalPersistenceError):
            goals.GoalRegistry.load(self.path)

    def test_swapped_chain_tip_refused(self):
        # Two valid stores; splicing one's records under the other's
        # header must fail closed.
        r, _ = _reg_with()
        r.save(self.path)
        other = os.path.join(self.tmp, "other.jsonl")
        r2 = goals.GoalRegistry()
        r2.register("evil", "run-9", "evil goal",
                    effects=[("delete", "everything")])
        r2.save(other)
        a = open(self.path).read().splitlines()
        b = open(other).read().splitlines()
        open(self.path, "w").write("\n".join([a[0]] + b[1:]) + "\n")
        with self.assertRaises(goals.GoalPersistenceError):
            goals.GoalRegistry.load(self.path)

    def test_missing_file_refused(self):
        with self.assertRaises(goals.GoalPersistenceError):
            goals.GoalRegistry.load(os.path.join(self.tmp, "nope.jsonl"))

    def test_empty_registry_roundtrip(self):
        r = goals.GoalRegistry()
        r.save(self.path)
        r2 = goals.GoalRegistry.load(self.path)
        self.assertEqual(r2._goals, [])
        ok, _ = r2.verify_chain()
        self.assertTrue(ok)

    def test_persistence_error_is_value_error(self):
        self.assertTrue(issubclass(goals.GoalPersistenceError,
                                   ValueError))


class LaunderingTest(unittest.TestCase):
    def _run1(self, agent="agent-7"):
        # Run 1: agent registers read-only, but executes a write.
        r = goals.GoalRegistry()
        g1, _ = r.register(agent, "run-1", "read-only audit",
                           effects=[("read", "sandbox/reports/note.txt")],
                           constraints=[("forbid", "write",
                                         "sandbox/reports/note.txt")])
        hist = {(agent, "run-1"): [("write",
                                     "sandbox/reports/note.txt")]}
        return r, g1, hist

    def test_launders_violation_flagged(self):
        r, g1, hist = self._run1()
        g2, _ = r.register("agent-7", "run-2", "data migration",
                           effects=[("write",
                                     "sandbox/reports/note.txt")])
        finds = goals.detect_cross_run_laundering(r, g2,
                                                  executed_history=hist)
        types = [f["type"] for f in finds]
        self.assertIn("registration_launders_violation", types)
        f = next(f for f in finds
                 if f["type"] == "registration_launders_violation")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["detail"]["executed_run_id"], "run-1")
        self.assertEqual(f["detail"]["prior_goal_id"],
                         g1["goal_id"])

    def test_clean_history_silent(self):
        r = goals.GoalRegistry()
        r.register("agent-7", "run-1", "read-only audit",
                   effects=[("read", "sandbox/reports/note.txt")],
                   constraints=[("forbid", "write",
                                 "sandbox/reports/note.txt")])
        hist = {("agent-7", "run-1"): [("read",
                                        "sandbox/reports/note.txt")]}
        g2, _ = r.register("agent-7", "run-2", "data migration",
                           effects=[("write",
                                     "sandbox/reports/note.txt")])
        finds = goals.detect_cross_run_laundering(r, g2,
                                                  executed_history=hist)
        self.assertEqual(
            [f for f in finds
             if f["type"] == "registration_launders_violation"], [])

    def test_history_contradicts_registration(self):
        r = goals.GoalRegistry()
        hist = {("agent-7", "run-1"): [("send", "evil.example")]}
        g, _ = r.register("agent-7", "run-2", "tight policy",
                          effects=[("read", "inbox")],
                          constraints=[("forbid", "send",
                                        "evil.example")])
        finds = goals.detect_cross_run_laundering(r, g,
                                                  executed_history=hist)
        types = [f["type"] for f in finds]
        self.assertIn("history_contradicts_registration", types)

    def test_dormant_goal_flagged_at_third_run(self):
        r = goals.GoalRegistry()
        eff = [("send", "vendor.synthetic.local")]
        hist = {}
        last = None
        for i in ("1", "2", "3"):
            g, _ = r.register("agent-7", "run-" + i, "nightly sync",
                              effects=eff)
            last = g
            hist[("agent-7", "run-" + i)] = []  # never exercised
        finds = goals.detect_cross_run_laundering(r, last,
                                                  executed_history=hist)
        types = [f["type"] for f in finds]
        self.assertIn("dormant_goal", types)
        f = next(f for f in finds if f["type"] == "dormant_goal")
        self.assertEqual(f["severity"], "info")
        self.assertEqual(len(f["detail"]["matching_runs"]), 3)

    def test_dormant_silent_when_exercised(self):
        r = goals.GoalRegistry()
        eff = [("send", "vendor.synthetic.local")]
        hist = {}
        last = None
        for i, exercised in (("1", False), ("2", True), ("3", False)):
            g, _ = r.register("agent-7", "run-" + i, "nightly sync",
                              effects=eff)
            last = g
            hist[("agent-7", "run-" + i)] = (
                [("send", "vendor.synthetic.local")] if exercised
                else [])
        finds = goals.detect_cross_run_laundering(r, last,
                                                  executed_history=hist)
        self.assertEqual(
            [f for f in finds if f["type"] == "dormant_goal"], [])

    def test_dormant_silent_without_history(self):
        # No executed history: cannot distinguish dormant from
        # unobserved -- stays silent rather than firing blind.
        r = goals.GoalRegistry()
        eff = [("send", "vendor.synthetic.local")]
        last = None
        for i in ("1", "2", "3"):
            last, _ = r.register("agent-7", "run-" + i,
                                 "nightly sync", effects=eff)
        finds = goals.detect_cross_run_laundering(r, last)
        self.assertEqual(
            [f for f in finds if f["type"] == "dormant_goal"], [])

    def test_dormant_ignores_read_only_goals(self):
        r = goals.GoalRegistry()
        last = None
        hist = {}
        for i in ("1", "2", "3"):
            last, _ = r.register("agent-7", "run-" + i, "look",
                                 effects=[("read", "inbox")])
            hist[("agent-7", "run-" + i)] = []
        finds = goals.detect_cross_run_laundering(r, last,
                                                  executed_history=hist)
        self.assertEqual(
            [f for f in finds if f["type"] == "dormant_goal"], [])

    def test_composition_conflict_with_explicit_prior(self):
        # Fresh registry (no persistence): the prior goal is supplied
        # explicitly; the new registration conflicts with it.
        r = goals.GoalRegistry()
        prior, _ = r.register("agent-7", "run-1", "keep data",
                              effects=[("preserve", "sandbox/data/x")])
        fresh = goals.GoalRegistry()
        g2, conflicts = fresh.register(
            "agent-7", "run-2", "drop data",
            effects=[("delete", "sandbox/data/x")])
        self.assertEqual(conflicts, [])  # fresh registry sees nothing
        finds = goals.detect_cross_run_laundering(
            fresh, g2, prior_goals=[prior])
        types = [f["type"] for f in finds]
        self.assertIn("cross_run_composition_conflict", types)
        f = next(f for f in finds
                 if f["type"] == "cross_run_composition_conflict")
        self.assertEqual(f["detail"]["prior_run_id"], "run-1")

    def test_persisted_flow_no_double_composition_flag(self):
        # Regression (spec review, wave-132): in the persisted flow,
        # register() already flags conflicts against loaded prior-run
        # goals via detect_conflict. detect_cross_run_laundering must
        # not re-flag the same atom pair as
        # cross_run_composition_conflict (triple-fire).
        tmp = tempfile.mkdtemp(prefix="goalx_")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, "goals.jsonl")
        r1 = goals.GoalRegistry()
        r1.register("agent-7", "run-1", "preserve records",
                    effects=[("preserve", "sandbox/records")],
                    constraints=[("forbid", "write",
                                  "sandbox/records")])
        r1.save(path)
        events = []
        r2 = goals.GoalRegistry.load(path, audit=events.append)
        g2, _ = r2.register("agent-7", "run-2", "rewrite records",
                            effects=[("write", "sandbox/records")])
        self.assertIn("goal_conflict",
                      [e.get("event") for e in events])
        finds = goals.detect_cross_run_laundering(r2, g2)
        types = [f["type"] for f in finds]
        self.assertNotIn("cross_run_composition_conflict", types)
        cross = [e for e in events
                 if e.get("event") == "goal_cross_run_flag"]
        self.assertFalse(any(
            e["detail"].get("type") == "cross_run_composition_conflict"
            for e in cross))

    def test_unregistered_candidate_gets_composition_flag(self):
        # The composition check exists for priors the registry never
        # saw: a never-registered candidate goal is still flagged.
        r = goals.GoalRegistry()
        r.register("agent-7", "run-1", "preserve records",
                   effects=[("preserve", "sandbox/records")],
                   constraints=[("forbid", "write",
                                 "sandbox/records")])
        candidate = {"goal_id": "cand-1", "agent_id": "agent-7",
                     "run_id": "run-2",
                     "effects": [["write", "sandbox/records"]],
                     "constraints": [], "status": "active"}
        finds = goals.detect_cross_run_laundering(r, candidate)
        types = [f["type"] for f in finds]
        self.assertIn("cross_run_composition_conflict", types)

    def test_goal_signature_rejects_malformed_atoms(self):
        # Fail-closed consistency: a malformed atom raises rather
        # than being silently skipped (a skip would make two
        # different goals compare "identical").
        with self.assertRaises(ValueError):
            goals._goal_signature({"effects": [["write"]],
                                   "constraints": []})
        with self.assertRaises(ValueError):
            goals._goal_signature(
                {"effects": [["teleport", "x"]], "constraints": []})
        with self.assertRaises(ValueError):
            goals._goal_signature(
                {"effects": [], "constraints": [["forbid", "x"]]})

    def test_other_agent_ignored(self):
        r = goals.GoalRegistry()
        r.register("agent-9", "run-1", "read-only audit",
                   effects=[("read", "sandbox/reports/note.txt")],
                   constraints=[("forbid", "write",
                                 "sandbox/reports/note.txt")])
        hist = {("agent-9", "run-1"): [("write",
                                        "sandbox/reports/note.txt")]}
        g2, _ = r.register("agent-7", "run-2", "data migration",
                           effects=[("write",
                                     "sandbox/reports/note.txt")])
        finds = goals.detect_cross_run_laundering(r, g2,
                                                  executed_history=hist)
        self.assertEqual(finds, [])

    def test_loud_audit_event_emitted(self):
        events = []
        r = goals.GoalRegistry(audit=events.append)
        g1, _ = r.register("agent-7", "run-1", "read-only audit",
                           effects=[("read", "sandbox/reports/note.txt")],
                           constraints=[("forbid", "write",
                                         "sandbox/reports/note.txt")])
        hist = {("agent-7", "run-1"): [("write",
                                        "sandbox/reports/note.txt")]}
        g2, _ = r.register("agent-7", "run-2", "data migration",
                           effects=[("write",
                                     "sandbox/reports/note.txt")])
        goals.detect_cross_run_laundering(r, g2,
                                          executed_history=hist)
        flags = [e for e in events
                 if e.get("event") == "goal_cross_run_flag"]
        self.assertTrue(flags)
        self.assertEqual(flags[0]["flag"], "goal_cross_run")

    def test_malformed_inputs_fail_closed(self):
        r = goals.GoalRegistry()
        g, _ = r.register("a", "r", "x", effects=[("read", "t")])
        with self.assertRaises(ValueError):
            goals.detect_cross_run_laundering(r, "not-a-dict")
        with self.assertRaises(ValueError):
            goals.detect_cross_run_laundering(
                r, {"goal_id": "x"})  # no agent_id
        with self.assertRaises(ValueError):
            goals.detect_cross_run_laundering(
                r, g, executed_history={("a", "r-prior"): [("nuke", "t")]})
        with self.assertRaises(ValueError):
            goals.detect_cross_run_laundering(
                r, g, executed_history={"bad-key": []})


if __name__ == "__main__":
    unittest.main()
