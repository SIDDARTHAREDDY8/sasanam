"""Unit tests for wave-152 row-9 state-continuity auditing.

Public seams: AdaptiveBudgetPolicy churn_window/churn_max_breaks,
the ``churn_break`` / ``churn_breaks`` / ``churn_suspect`` fields on
chained reset records, and the LOUD ``drift_state_churn_suspect``
triage event (edge-triggered, never blocking, never tightening).
Deterministic, $0, stdlib-only.
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.drift import RunFingerprint, fingerprint_tool_distance
from gov.drift_budget import (
    AdaptiveBudgetPolicy,
    BudgetPolicy,
    BudgetStore,
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


def _flip_fwd(x):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    return t


def _flip_rev(x):
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    return t


BASE_FP = _fp(BASE_TOOLS)
_D10 = fingerprint_tool_distance(_fp(_flip_fwd(10)), BASE_FP)
WARN = _D10 / 0.4  # a 10-call shift is exactly 0.4 threshold-equivalents


def _scan_09x():
    """Largest shift with fraction in [0.85, 1.0): a near-trip paced
    burst that stays sub-threshold (no single-run trip)."""
    best = None
    for x in range(1, 60):
        f = fingerprint_tool_distance(_fp(_flip_fwd(x)), BASE_FP) / WARN
        if f < 1.0:
            best = (x, f)
    assert best is not None and best[1] >= 0.85, best
    return best


X09, F09 = _scan_09x()


def _policy(**kw):
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5)
    args.update(kw)
    return AdaptiveBudgetPolicy(**args)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_statechurn_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)

    def churn_events(self):
        return [e for e in self.events
                if e.get("event") == "drift_state_churn_suspect"]

    def reset_records(self, agent):
        return [r for r in self.store._read_all(agent)
                if r.get("kind") == "reset"]


class TestChurnPolicy(unittest.TestCase):
    def test_defaults(self):
        p = AdaptiveBudgetPolicy(100.0)
        self.assertEqual(p.churn_window, 10)
        self.assertEqual(p.churn_max_breaks, 2)

    def test_validation(self):
        with self.assertRaises(ValueError):
            AdaptiveBudgetPolicy(100.0, churn_window=1)
        with self.assertRaises(ValueError):
            AdaptiveBudgetPolicy(100.0, churn_max_breaks=0)
        with self.assertRaises(ValueError):
            AdaptiveBudgetPolicy(100.0, churn_window="10")

    def test_to_dict_includes_churn(self):
        d = AdaptiveBudgetPolicy(100.0).to_dict()
        self.assertIn("churn_window", d)
        self.assertIn("churn_max_breaks", d)

    def test_plain_policy_has_no_churn(self):
        p = BudgetPolicy(100.0)
        self.assertFalse(hasattr(p, "churn_window"))
        self.assertFalse(hasattr(p, "churn_max_breaks"))


class TestChurnSeam(_Harness):
    def test_break_recorded_when_armed_hunt_cleared(self):
        # run1 burst (paced defuse D1 arms the flip hunt), run2 clean
        # (D1: hunt not yet armed -> no break), run3 clean (D2: armed
        # hunt cleared by the non-paced cycle -> break).
        self.record("a", _flip_fwd(X09), 1)
        self.record("a", dict(BASE_TOOLS), 2)
        self.record("a", dict(BASE_TOOLS), 3)
        recs = self.reset_records("a")
        self.assertEqual(len(recs), 2)
        self.assertFalse(recs[0]["churn_break"])
        self.assertTrue(recs[1]["churn_break"])
        self.assertEqual(recs[1]["churn_breaks"], 1)
        self.assertFalse(recs[1]["churn_suspect"])

    def test_no_break_when_hunt_never_armed(self):
        for seq in range(1, 6):
            self.record("a", dict(BASE_TOOLS), seq)
        recs = self.reset_records("a")
        self.assertTrue(all(not r["churn_break"] for r in recs))
        self.assertTrue(all(r["churn_breaks"] == 0 for r in recs))

    def test_no_break_on_paced_defuse(self):
        # A paced defuse arms (or extends) the hunt -- it does not
        # break it.
        self.record("a", _flip_fwd(X09), 1)
        self.record("a", dict(BASE_TOOLS), 2)
        recs = self.reset_records("a")
        self.assertEqual(len(recs), 1)
        self.assertFalse(recs[0]["churn_break"])

    def test_loud_event_on_bound_crossed(self):
        # [burst, clean, clean] x3 alternating: breaks at D2, D4, D6;
        # the 3rd break crosses the bound (3 > 2) -> exactly one LOUD
        # triage event, chain-linked.
        seq = 0
        for burst in (_flip_fwd(X09), _flip_rev(X09), _flip_fwd(X09)):
            for tools in (burst, dict(BASE_TOOLS), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        evs = self.churn_events()
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual(ev["severity"], "LOUD")
        self.assertEqual(ev["flag"], "drift_state_churn")
        self.assertEqual(ev["churn_breaks"], 3)
        self.assertEqual(ev["churn_window"], 10)
        self.assertEqual(ev["churn_max_breaks"], 2)
        self.assertIn("digest", ev)
        self.assertIn("prev_digest", ev)
        self.assertTrue(self.store.verify_chain("a"))

    def test_edge_trigger_no_repeat_while_above_bound(self):
        seq = 0
        for burst in (_flip_fwd(X09), _flip_rev(X09), _flip_fwd(X09),
                      _flip_rev(X09), _flip_fwd(X09)):
            for tools in (burst, dict(BASE_TOOLS), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        # Breaks keep coming (D8, D10) but the count never drops
        # below the bound -> no second emission.
        self.assertEqual(len(self.churn_events()), 1)

    def test_refire_after_drop_and_recross(self):
        seq = 0
        for burst in (_flip_fwd(X09), _flip_rev(X09), _flip_fwd(X09)):
            for tools in (burst, dict(BASE_TOOLS), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        self.assertEqual(len(self.churn_events()), 1)
        # 14 clean defuses slide the window past the breaks.
        for _ in range(14):
            seq += 1
            self.record("a", dict(BASE_TOOLS), seq)
        recs = self.reset_records("a")
        self.assertFalse(recs[-1]["churn_suspect"])
        self.assertEqual(len(self.churn_events()), 1)
        # Re-attack: the bound is crossed again -> second emission.
        for burst in (_flip_fwd(X09), _flip_rev(X09), _flip_fwd(X09)):
            for tools in (burst, dict(BASE_TOOLS), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        self.assertEqual(len(self.churn_events()), 2)
        self.assertTrue(self.store.verify_chain("a"))

    def test_triage_only_never_tightens(self):
        # Churn alone never tightens the budget and never trips it:
        # no drift_budget_adapted with a churn trigger, and the
        # budget check stays untripped by the churn path.
        seq = 0
        for burst in (_flip_fwd(X09), _flip_rev(X09), _flip_fwd(X09)):
            for tools in (burst, dict(BASE_TOOLS), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        self.assertEqual(len(self.churn_events()), 1)
        adapts = [e for e in self.events
                  if e.get("event") == "drift_budget_adapted"]
        self.assertEqual(
            [e.get("trigger") for e in adapts], [])
        chk = self.store.check("a", self.policy)
        self.assertNotEqual(chk.status, "tripped")

    def test_plain_policy_defuse_has_no_churn_fields(self):
        policy = BudgetPolicy(warn_distance=WARN, budget_limit=1.0,
                              window_runs=8, noise_floor=0.1,
                              min_consistency=0.5)
        for seq in range(1, 4):
            self.store.record_run("a", seq, "run-%d" % seq,
                                  _fp(dict(BASE_TOOLS), run_seq=seq),
                                  BASE_FP, policy)
        recs = [r for r in self.store._read_all("a")
                if r.get("kind") == "reset"]
        self.assertTrue(recs)
        self.assertTrue(all("churn_break" not in r for r in recs))


if __name__ == "__main__":
    unittest.main()
