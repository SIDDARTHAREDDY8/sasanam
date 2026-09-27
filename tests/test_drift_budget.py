"""Unit tests for gov/drift_budget.py (wave-138, row 9).

Public seams: BudgetPolicy, BudgetStore.record_run / check / reset /
contributions / verify_chain, BudgetContribution, BudgetCheck,
signed_tool_deltas.
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.drift import RunFingerprint, fingerprint_tool_distance
from gov.drift_budget import (
    BudgetCheck,
    BudgetContribution,
    BudgetPolicy,
    BudgetStore,
    default_store_dir,
    signed_tool_deltas,
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


def _policy(**kw):
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                min_contributing_runs=2)
    args.update(kw)
    return BudgetPolicy(**args)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_drift_budget_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)


class TestPolicyValidation(unittest.TestCase):
    def test_defaults(self):
        p = BudgetPolicy(100.0)
        self.assertEqual(p.warn_distance, 100.0)
        self.assertEqual(p.budget_limit, 1.0)
        self.assertEqual(p.window_runs, 8)

    def test_bad_warn_distance(self):
        for bad in (0, -1.0, "x", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                BudgetPolicy(bad)

    def test_bad_budget_limit(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, budget_limit=0)

    def test_bad_window_runs(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, window_runs=1)
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, window_runs=2.5)

    def test_bad_noise_floor(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, noise_floor=1.0)
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, noise_floor=-0.1)

    def test_bad_consistency(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, min_consistency=1.5)

    def test_bad_min_contributing_runs(self):
        with self.assertRaises(ValueError):
            BudgetPolicy(10.0, min_contributing_runs=0)


class TestSignedDeltas(unittest.TestCase):
    def test_known_values(self):
        d = signed_tool_deltas(_fp(_shifted(10)), BASE_FP)
        self.assertAlmostEqual(d["search"], -10.0)
        self.assertAlmostEqual(d["http_post"], 10.0)
        self.assertAlmostEqual(d["summarize"], 0.0)

    def test_identical_is_zero(self):
        d = signed_tool_deltas(BASE_FP, BASE_FP)
        self.assertTrue(all(v == 0.0 for v in d.values()))


class TestRecordRun(_Harness):
    def test_sub_threshold_contributes(self):
        c = self.record("a", _shifted(10), 1)
        self.assertIsInstance(c, BudgetContribution)
        self.assertTrue(c.contributes)
        self.assertEqual(c.reason, "sub_threshold")
        self.assertAlmostEqual(c.threshold_equivalents, 0.4, places=6)

    def test_clean_run_defuses(self):
        self.record("a", _shifted(10), 1)
        c = self.record("a", dict(BASE_TOOLS), 2)
        self.assertFalse(c.contributes)
        self.assertTrue(c.clean)
        self.assertEqual(c.reason, "clean")
        names = [e.get("event") for e in self.events]
        self.assertIn("drift_budget_reset", names)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.cumulative, 0.0)
        self.assertEqual(chk.status, "ok")

    def test_above_warn_does_not_accrue(self):
        c = self.record("a", _shifted(18), 1)  # ~1.21 x warn
        self.assertFalse(c.contributes)
        self.assertEqual(c.reason, "single_run_path")
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.cumulative, 0.0)

    def test_insufficient_data(self):
        tiny = RunFingerprint(
            tool_counts={"search": 3},
            decisions={"allow": 3, "require_approval": 0, "deny": 0},
            run_seq=0, run_id="tiny")
        c = self.store.record_run("a", 0, "tiny", tiny, BASE_FP,
                                  self.policy)
        self.assertFalse(c.contributes)
        self.assertEqual(c.reason, "insufficient_data")

    def test_type_validation(self):
        with self.assertRaises(TypeError):
            self.store.record_run("a", 0, "x", "not-a-fp", BASE_FP,
                                  self.policy)
        with self.assertRaises(TypeError):
            self.store.record_run("a", 0, "x", BASE_FP, BASE_FP,
                                  "not-a-policy")
        with self.assertRaises(ValueError):
            self.store.record_run("a", -1, "x", BASE_FP, BASE_FP,
                                  self.policy)

    def test_audit_failure_is_fail_closed(self):
        def boom(event):
            raise RuntimeError("audit down")
        n_before = len(self.store.contributions("a"))
        with self.assertRaises(RuntimeError):
            self.store.record_run("a", 0, "x", _fp(_shifted(10)),
                                  BASE_FP, self.policy, audit=boom)
        self.assertEqual(len(self.store.contributions("a")), n_before)


class TestCheck(_Harness):
    def test_trip_on_sustained_boil(self):
        for i in range(3):
            self.record("a", _shifted(10), i + 1)
        chk = self.store.check("a", self.policy)
        self.assertIsInstance(chk, BudgetCheck)
        self.assertEqual(chk.status, "tripped")
        self.assertGreaterEqual(chk.cumulative, 1.0)
        self.assertGreaterEqual(chk.consistency, 0.5)
        self.assertEqual(chk.contributing_runs, 3)
        trips = [e for e in self.events
                 if e.get("event") == "drift_budget_tripped"]
        self.assertEqual(len(trips), 1)
        self.assertEqual(trips[0].get("severity"), "LOUD")

    def test_no_double_emit_while_tripped(self):
        for i in range(4):
            self.record("a", _shifted(10), i + 1)
        self.store.check("a", self.policy)
        self.store.check("a", self.policy)
        trips = [e for e in self.events
                 if e.get("event") == "drift_budget_tripped"]
        self.assertEqual(len(trips), 1)

    def test_single_run_never_trips(self):
        # 0.97 threshold-equivalents in ONE run: below budget and
        # below min_contributing_runs -- detect_drift's territory.
        c = self.record("a", _shifted(16), 1)
        self.assertTrue(c.contributes)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.status, "ok")

    def test_oscillation_does_not_trip(self):
        def osc(sign):
            t = dict(BASE_TOOLS)
            t["search"] -= sign * 8
            t["http_post"] += sign * 8
            return t
        for i in range(10):
            self.record("a", osc(1 if i % 2 == 0 else -1), i + 1)
        chk = self.store.check("a", self.policy)
        self.assertGreaterEqual(chk.cumulative, 1.0)  # would trip on size
        self.assertLess(chk.consistency, 0.5)
        self.assertEqual(chk.status, "ok")

    def test_window_expiry(self):
        pol = _policy(window_runs=4)
        store = BudgetStore(self.tmp / "w", audit=self.events.append)
        store.record_run("a", 1, "r1", _fp(_shifted(10), run_seq=1),
                         BASE_FP, pol)
        for seq in (2, 3, 4, 5):
            store.record_run("a", seq, "r%d" % seq,
                             _fp(_shifted(18), run_seq=seq), BASE_FP,
                             pol)
        chk = store.check("a", pol)
        self.assertEqual(chk.cumulative, 0.0)
        self.assertEqual(chk.status, "ok")

    def test_manual_reset(self):
        for i in range(2):
            self.record("a", _shifted(10), i + 1)
        self.store.reset("a", reason="operator")
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.cumulative, 0.0)
        self.assertEqual(chk.status, "ok")
        names = [e.get("event") for e in self.events]
        self.assertIn("drift_budget_reset", names)

    def test_retrip_after_decay_reemits(self):
        pol = _policy(window_runs=4, budget_limit=1.0)
        store = BudgetStore(self.tmp / "rt", audit=self.events.append)
        for i in range(3):
            store.record_run("a", i + 1, "r%d" % (i + 1),
                             _fp(_shifted(10), run_seq=i + 1), BASE_FP,
                             pol)
        self.assertEqual(store.check("a", pol).status, "tripped")
        # Window slides past the trip's contributions (above-WARN
        # runs neither accrue nor reset): live status decays to ok.
        for seq in (4, 5, 6, 7):
            store.record_run("a", seq, "r%d" % seq,
                             _fp(_shifted(18), run_seq=seq), BASE_FP,
                             pol)
        self.assertEqual(store.check("a", pol).status, "ok")
        # Fresh boil re-trips and MUST re-emit the LOUD event.
        for seq in (8, 9, 10):
            store.record_run("a", seq, "r%d" % seq,
                             _fp(_shifted(10), run_seq=seq), BASE_FP,
                             pol)
        self.assertEqual(store.check("a", pol).status, "tripped")
        trips = [e for e in self.events
                 if e.get("event") == "drift_budget_tripped"]
        self.assertEqual(len(trips), 2)

    def test_every_contribution_audited(self):
        for i in range(3):
            self.record("a", _shifted(10), i + 1)
        accrues = [e for e in self.events
                   if e.get("event") == "drift_budget_accrue"
                   and e.get("contributes")]
        self.assertEqual(len(accrues), 3)


class TestChain(_Harness):
    def test_verify_chain(self):
        for i in range(3):
            self.record("a", _shifted(10), i + 1)
        self.assertTrue(self.store.verify_chain("a"))

    def test_tamper_detected(self):
        self.record("a", _shifted(10), 1)
        p = self.store._path("a")
        lines = p.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace("0.4", "0.9")
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertFalse(self.store.verify_chain("a"))

    def test_default_store_dir(self):
        d = default_store_dir()
        self.assertIsInstance(d, Path)
        self.assertTrue(str(d).endswith("drift_budget"))


if __name__ == "__main__":
    unittest.main()
