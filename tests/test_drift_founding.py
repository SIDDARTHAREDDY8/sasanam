"""Unit tests for the row-9 founding-evidence gate (gov/drift_budget.py).

Public seams under test: BudgetStore.note_founding_signal /
confirm_founding / _founding_fold, FoundingSignalNote, the founding
mark's enforcement floor in BudgetStore.check, and the new
BudgetPolicy knobs (founding_window_runs, founding_confirm_runs).

Deterministic, stdlib only, $0 spend. Follows the conventions of
tests/test_drift_budget.py (module-level calibrated WARN, per-test
fresh store, explicit audit sink).
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.drift import RunFingerprint, fingerprint_tool_distance
from gov.drift_budget import (
    BudgetPolicy,
    BudgetStore,
    FoundingSignalNote,
)

BASE_TOOLS = {"search": 90, "summarize": 80, "email": 60,
              "read_file": 40, "http_post": 10}


def _fp(tools, run_seq=0):
    return RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": 0},
        approvals_requested=0, approvals_granted=0, approvals_denied=0,
        egress_events=1, egress_bytes=1000,
        run_seq=run_seq, run_id="r%d" % run_seq)


def _shifted(x):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["http_post"] += x
    return t


BASE_FP = _fp(BASE_TOOLS)
_D10 = fingerprint_tool_distance(_fp(_shifted(10)), BASE_FP)
WARN = _D10 / 0.4  # a 10-call shift is exactly 0.4 threshold-equivalents

# Largest shift (x <= 89 keeps every count positive) with a
# 0.6 <= ratio < 0.95 fingerprint: a solidly contributing run that
# cannot trip an unmarked plain-policy budget alone.
_SHIFT_07 = None
for _x in range(89, 0, -1):
    _r = fingerprint_tool_distance(_fp(_shifted(_x)), BASE_FP) / WARN
    if 0.6 <= _r < 0.95:
        _SHIFT_07 = _x
        break
assert _SHIFT_07 is not None, "no 0.6-0.95 shift in scan range"


def _policy(**kw):
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                min_contributing_runs=2)
    args.update(kw)
    return BudgetPolicy(**args)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_drift_founding_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)

    def note(self, agent, seq, kind="dlp_entropy_flag", detail=None,
             audit=True):
        return self.store.note_founding_signal(
            agent, seq, kind, detail=detail, policy=self.policy,
            audit=self.events.append if audit else None)

    def kinds(self, agent):
        return [r.get("kind") for r in self.store._read_all(agent)]

    def marked(self, agent):
        return self.store._founding_fold(
            self.store._read_all(agent))[0]

    def loud(self, event):
        return [e for e in self.events
                if e.get("severity") == "LOUD"
                and e.get("event") == event]


class TestFoundingPolicyKnobs(_Harness):
    def test_defaults(self):
        p = BudgetPolicy(WARN)
        self.assertEqual(p.founding_window_runs, 5)
        self.assertEqual(p.founding_confirm_runs, 3)

    def test_bad_window(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(WARN, founding_window_runs=0)
        with self.assertRaises(ValueError):
            BudgetPolicy(WARN, founding_window_runs="5")

    def test_bad_confirm_runs(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(WARN, founding_confirm_runs=0)

    def test_custom_window_honored(self):
        p = _policy(founding_window_runs=2)
        note = self.store.note_founding_signal(
            "a", 3, "canary_trip", policy=p,
            audit=self.events.append)
        self.assertFalse(note.in_window)
        self.assertFalse(note.marked)


class TestNoteFoundingSignal(_Harness):
    def test_in_window_signal_marks_and_emits_loud(self):
        note = self.note("mallory", 2, "dlp_entropy_flag",
                         detail={"egress": "http_post"})
        self.assertIsInstance(note, FoundingSignalNote)
        self.assertTrue(note.in_window)
        self.assertTrue(note.mark_set)
        self.assertTrue(note.marked)
        self.assertTrue(self.marked("mallory"))
        loud = self.loud("founding_evidence_suspect")
        self.assertEqual(len(loud), 1)
        self.assertEqual(loud[0]["signal_kind"], "dlp_entropy_flag")
        self.assertEqual(loud[0]["run_seq"], 2)
        kinds = self.kinds("mallory")
        self.assertIn("founding_signal", kinds)
        self.assertIn("founding_suspect", kinds)
        self.assertTrue(self.store.verify_chain("mallory"))

    def test_late_signal_recorded_but_no_mark(self):
        note = self.note("bob", 9, "canary_trip")
        self.assertFalse(note.in_window)
        self.assertFalse(note.mark_set)
        self.assertFalse(note.marked)
        self.assertFalse(self.marked("bob"))
        self.assertEqual(self.loud("founding_evidence_suspect"), [])
        noted = [e for e in self.events
                 if e.get("event") == "founding_signal_noted"]
        self.assertEqual(len(noted), 1)
        self.assertIn("founding_signal", self.kinds("bob"))
        self.assertNotIn("founding_suspect", self.kinds("bob"))

    def test_duplicate_signal_while_marked_no_second_loud(self):
        first = self.note("mallory", 1, "dlp_entropy_flag")
        second = self.note("mallory", 3, "canary_trip")
        self.assertTrue(first.mark_set)
        self.assertFalse(second.mark_set)  # already marked
        self.assertTrue(second.marked)
        self.assertEqual(len(self.loud("founding_evidence_suspect")),
                         1)
        # Both signals are chained; exactly one suspect record.
        kinds = self.kinds("mallory")
        self.assertEqual(kinds.count("founding_signal"), 2)
        self.assertEqual(kinds.count("founding_suspect"), 1)
        self.assertTrue(self.store.verify_chain("mallory"))

    def test_note_validates_inputs(self):
        with self.assertRaises(ValueError):
            self.note("a", 0, "x")
        with self.assertRaises(ValueError):
            self.note("a", 1, "")
        with self.assertRaises(ValueError):
            self.note("a", 1, "x" * 129)
        with self.assertRaises(TypeError):
            self.note("a", 1, "x", detail=["not", "a", "dict"])
        with self.assertRaises(ValueError):
            self.note("a", 1, "x", detail={1: "non-string key"})

    def test_audit_before_write_fail_closed(self):
        def _boom(event):
            raise RuntimeError("audit sink down")
        with self.assertRaises(RuntimeError):
            self.store.note_founding_signal("mallory", 1, "x",
                                            policy=self.policy,
                                            audit=_boom)
        # Fail-closed: nothing was appended.
        self.assertEqual(self.store._read_all("mallory"), [])
        self.assertEqual(self.events, [])


class TestConfirmFounding(_Harness):
    def test_human_confirm_clears(self):
        self.note("mallory", 2, "erosion_signal")
        self.assertTrue(self.marked("mallory"))
        cleared = self.store.confirm_founding(
            "mallory", audit=self.events.append)
        self.assertTrue(cleared)
        self.assertFalse(self.marked("mallory"))
        ev = [e for e in self.events
              if e.get("event") == "founding_evidence_confirmed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["reason"], "human")
        self.assertNotEqual(ev[0].get("severity"), "LOUD")
        self.assertIn("founding_confirmed", self.kinds("mallory"))
        self.assertTrue(self.store.verify_chain("mallory"))

    def test_confirm_noop_when_unmarked(self):
        cleared = self.store.confirm_founding(
            "alice", audit=self.events.append)
        self.assertFalse(cleared)
        self.assertEqual(self.store._read_all("alice"), [])
        self.assertEqual(self.events, [])

    def test_remark_after_confirm(self):
        self.note("erin", 2, "dlp_entropy_flag")
        self.assertTrue(
            self.store.confirm_founding("erin",
                                        audit=self.events.append))
        note = self.note("erin", 4, "canary_trip")
        self.assertTrue(note.mark_set)
        self.assertTrue(self.marked("erin"))
        self.assertEqual(len(self.loud("founding_evidence_suspect")),
                         2)


class TestAutoConfirm(_Harness):
    def test_auto_confirm_after_three_signal_free_runs(self):
        self.note("carol", 2, "approval_denied")
        for seq in (3, 4):
            self.record("carol", BASE_TOOLS, seq)
            self.assertTrue(self.marked("carol"),
                            "cleared too early at seq %d" % seq)
        self.record("carol", BASE_TOOLS, 5)
        self.assertFalse(self.marked("carol"))
        ev = [e for e in self.events
              if e.get("event") == "founding_evidence_confirmed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["reason"], "auto")
        recs = [r for r in self.store._read_all("carol")
                if r.get("kind") == "founding_confirmed"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["reason"], "auto")

    def test_second_signal_restarts_count(self):
        self.note("dave", 2, "dlp_entropy_flag")
        self.record("dave", BASE_TOOLS, 3)
        self.note("dave", 4, "canary_trip")  # anchor moves to seq 4
        self.record("dave", BASE_TOOLS, 5)
        self.record("dave", BASE_TOOLS, 6)
        self.assertTrue(self.marked("dave"),
                        "cleared before 3 runs after latest signal")
        self.record("dave", BASE_TOOLS, 7)
        self.assertFalse(self.marked("dave"))


class TestFoundingEnforcementFloor(_Harness):
    def test_marked_single_contribution_trips(self):
        self.note("mallory", 1, "dlp_entropy_flag")
        c = self.record("mallory", _shifted(_SHIFT_07), 1)
        self.assertTrue(c.contributes)
        chk = self.store.check("mallory", self.policy,
                               audit=self.events.append)
        self.assertEqual(chk.status, "tripped")
        trip_ev = [e for e in self.events
                   if e.get("event") == "drift_budget_tripped"]
        self.assertEqual(len(trip_ev), 1)
        self.assertIs(trip_ev[0]["founding_suspect"], True)

    def test_unmarked_identical_run_stays_ok(self):
        c = self.record("mallory", _shifted(_SHIFT_07), 1)
        self.assertTrue(c.contributes)
        chk = self.store.check("mallory", self.policy,
                               audit=self.events.append)
        self.assertEqual(chk.status, "ok")

    def test_confirm_restores_unmarked_limits(self):
        self.note("mallory", 2, "erosion_signal")
        self.store.confirm_founding("mallory",
                                    audit=self.events.append)
        self.record("mallory", _shifted(_SHIFT_07), 3)
        chk = self.store.check("mallory", self.policy,
                               audit=self.events.append)
        self.assertEqual(chk.status, "ok")

    def test_mark_does_not_change_drift_population_state(self):
        # The gate is budget-local: the same baseline validates the
        # same way against the peer population whether or not the
        # budget marked the agent founding-suspect.
        from gov.drift import validate_baseline_against_population
        peers = [("peer%d" % i, _fp(BASE_TOOLS, run_seq=i))
                 for i in range(4)]
        new_fp = _fp(BASE_TOOLS, run_seq=99)
        before = validate_baseline_against_population(
            "mallory", new_fp, peers)
        self.note("mallory", 1, "dlp_entropy_flag")
        self.assertTrue(self.marked("mallory"))
        after = validate_baseline_against_population(
            "mallory", new_fp, peers)
        self.assertEqual(before.status, after.status)
        self.assertEqual(before.agent_distance, after.agent_distance)


if __name__ == "__main__":
    unittest.main()
