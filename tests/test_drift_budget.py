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


# ------------------------------------------------- wave-139 adaptation

def _frac(tools):
    return fingerprint_tool_distance(_fp(tools), BASE_FP) / WARN


def _scan_below(ceiling=1.0, want_at_least=0.85, hi=80):
    best = None
    for x in range(1, hi + 1):
        f = _frac(_shifted(x))
        if f < ceiling:
            best = (x, f)
    assert best is not None and best[1] >= want_at_least
    return best


_X09, _F09 = _scan_below()  # ~0.9 threshold-equivalents, deterministic


def _rev_shifted(x):
    t = dict(BASE_TOOLS)
    t["email"] -= x
    t["search"] += x
    return t


def _adaptive_policy(**kw):
    from gov.drift_budget import AdaptiveBudgetPolicy
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                min_contributing_runs=2)
    args.update(kw)
    return AdaptiveBudgetPolicy(**args)


class _AdaptiveHarness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_adaptdrift_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _adaptive_policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)

    def event_names(self):
        return [e.get("event") for e in self.events]


class TestAdaptivePolicyValidation(unittest.TestCase):
    def test_defaults(self):
        from gov.drift_budget import AdaptiveBudgetPolicy
        p = AdaptiveBudgetPolicy(100.0)
        self.assertEqual(p.adapt_near_floor, 0.75)
        self.assertEqual(p.adapt_cycles, 2)
        self.assertEqual(p.adapt_factor, 0.6)
        self.assertEqual(p.adapt_contrib_floor, 0.75)
        self.assertEqual(p.adapt_strikes, 3)
        self.assertEqual(p.adapt_max_level, 3)
        self.assertEqual(p.budget_limit, 1.0)  # base fields inherited

    def test_bad_params_raise(self):
        from gov.drift_budget import AdaptiveBudgetPolicy
        for kw in (dict(adapt_near_floor=0), dict(adapt_near_floor=1.5),
                   dict(adapt_cycles=0), dict(adapt_factor=1.0),
                   dict(adapt_factor=0), dict(adapt_contrib_floor=1.0),
                   dict(adapt_strikes=1), dict(adapt_max_level=0),
                   dict(slow_weight=0), dict(slow_weight=1.5),
                   dict(slow_clean_decay=0), dict(slow_clean_decay=1.0),
                   dict(slow_trip=0), dict(slow_trip=-0.1),
                   dict(slow_window_factor=1), dict(slow_min_runs=1),
                   dict(slow_window_factor=2.5)):
            with self.assertRaises(ValueError, msg=kw):
                AdaptiveBudgetPolicy(100.0, **kw)

    def test_slow_burn_defaults_and_serialization(self):
        from gov.drift_budget import AdaptiveBudgetPolicy
        p = AdaptiveBudgetPolicy(100.0)
        self.assertEqual(p.slow_weight, 0.5)
        self.assertEqual(p.slow_clean_decay, 0.5)
        self.assertEqual(p.slow_trip, 0.3)
        self.assertEqual(p.slow_window_factor, 3)
        self.assertEqual(p.slow_min_runs, 3)
        d = p.to_dict()
        for k in ("slow_weight", "slow_clean_decay", "slow_trip",
                  "slow_window_factor", "slow_min_runs"):
            self.assertIn(k, d)

    def test_to_dict_covers_both_slot_sets(self):
        from gov.drift_budget import AdaptiveBudgetPolicy
        d = AdaptiveBudgetPolicy(100.0).to_dict()
        for k in ("warn_distance", "budget_limit", "adapt_near_floor",
                  "adapt_cycles", "adapt_factor", "adapt_max_level"):
            self.assertIn(k, d)

    def test_static_policy_has_no_adaptive_fields(self):
        # Zero-behavior-change contract: a plain BudgetPolicy never
        # writes adaptive record fields.
        h = _Harness()
        h.setUp()
        h.record("a", _shifted(_X09), 1)
        h.record("a", dict(BASE_TOOLS), 2)
        for r in h.store.contributions("a"):
            self.assertNotIn("near_trip", r)
            self.assertNotIn("adapt_level", r)


class TestAdaptiveTighten(_AdaptiveHarness):
    def test_two_near_trip_cycles_tighten_loud(self):
        for i in range(2):
            self.record("a", _shifted(_X09), 2 * i + 1)
            self.record("a", dict(BASE_TOOLS), 2 * i + 2)
        adapted = [e for e in self.events
                   if e.get("event") == "drift_budget_adapted"]
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0].get("severity"), "LOUD")
        self.assertEqual(adapted[0]["adapt_level"], 1)
        self.assertAlmostEqual(adapted[0]["effective_limit"], 0.6)
        self.assertEqual(adapted[0]["trigger"], "near_trip_cycle")
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.detail["adapt_level"], 1)
        self.assertAlmostEqual(chk.detail["effective_limit"], 0.6)
        self.assertEqual(chk.detail["effective_window"], 7)

    def test_pacer_trips_after_adaptation(self):
        tripped_at = None
        for i in range(3):
            self.record("a", _shifted(_X09), 2 * i + 1)
            if self.store.check("a", self.policy).status == "tripped":
                tripped_at = 2 * i + 1
                break
            self.record("a", dict(BASE_TOOLS), 2 * i + 2)
            if self.store.check("a", self.policy).status == "tripped":
                tripped_at = 2 * i + 2
                break
        self.assertEqual(tripped_at, 5)
        self.assertIn("drift_budget_tripped", self.event_names())
        self.assertTrue(self.store.verify_chain("a"))

    def test_alternating_direction_bursts_do_not_adapt(self):
        seq = 0
        for i, (fn, x) in enumerate(
                [(_shifted, _X09), (_rev_shifted, 20), (_shifted, _X09),
                 (_rev_shifted, 20)]):
            seq += 1
            self.record("a", fn(x), seq)
            seq += 1
            self.record("a", dict(BASE_TOOLS), seq)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.status, "ok")
        self.assertNotIn("drift_budget_adapted", self.event_names())

    def test_benign_cycle_relaxes(self):
        for i in range(2):  # adapt to level 1
            self.record("a", _shifted(_X09), 2 * i + 1)
            self.record("a", dict(BASE_TOOLS), 2 * i + 2)
        self.assertEqual(self.store.check("a", self.policy)
                         .detail["adapt_level"], 1)
        # Benign cycle: one 0.4 contribution, then defuse.
        self.record("a", _shifted(10), 5)
        self.record("a", dict(BASE_TOOLS), 6)
        relaxed = [e for e in self.events
                   if e.get("event") == "drift_budget_relaxed"]
        self.assertEqual(len(relaxed), 1)
        self.assertNotEqual(relaxed[0].get("severity"), "LOUD")
        self.assertEqual(self.store.check("a", self.policy)
                         .detail["adapt_level"], 0)

    def test_single_run_does_not_adapt(self):
        self.record("a", _shifted(_X09), 1)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.status, "ok")
        self.assertNotIn("drift_budget_adapted", self.event_names())

    def test_contribution_streak_trigger_under_high_limit(self):
        # budget_limit=3.0: three same-direction ~0.9 runs (2.7) never
        # trip statically, but the streak trigger tightens LOUD.
        self.policy = _adaptive_policy(budget_limit=3.0)
        for i in range(3):
            self.record("a", _shifted(_X09), i + 1)
        adapted = [e for e in self.events
                   if e.get("event") == "drift_budget_adapted"]
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0]["trigger"], "contribution_streak")
        self.assertEqual(adapted[0].get("severity"), "LOUD")
        chk = self.store.check("a", self.policy)
        self.assertAlmostEqual(chk.detail["effective_limit"], 1.8)
        # 2.7 cumulative vs the adapted 1.8 limit -> trips (the point of
        # the streak trigger: earlier escalation, still LOUD).
        self.assertEqual(chk.status, "tripped")
        self.assertIn("drift_budget_tripped", self.event_names())


def _shifted_rev(x):
    # Exact opposite of _shifted: alternating the two nets to zero
    # direction, which is what the slow-burn consistency gate needs
    # to see through. (Unused where tool headroom is one-sided; see
    # _alt_shift/_alt_shift_rev.)
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["http_post"] -= x
    return t


def _alt_shift(x):
    # Two-sided-headroom shift for the alternating-direction test:
    # search/summarize both have room for +/- x at the magnitudes
    # the sub-floor scan finds.
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["summarize"] += x
    return t


def _alt_shift_rev(x):
    # Exact opposite of _alt_shift.
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["summarize"] -= x
    return t


def _scan_subfloor(ceiling, want_at_least, fn=None):
    fn = _shifted if fn is None else fn
    best = None
    for x in range(1, 81):
        f = _frac(fn(x))
        if f < ceiling:
            best = (x, f)
    assert best is not None and best[1] >= want_at_least
    return best


class TestSlowBurn(_AdaptiveHarness):
    """Wave-146 row 9: the slow-burn accumulator seam.

    Public seam: BudgetStore.check detail slow_burn_* fields, the
    LOUD drift_budget_slow_burn audit event, and the adapt
    tightening it drives.
    """

    def _drive_pacer(self, agent, shift_fn, x, cycles):
        seq = 0
        for _ in range(cycles):
            for tools in (shift_fn(x), dict(BASE_TOOLS)):
                seq += 1
                self.record(agent, tools, seq)
                chk = self.store.check(agent, self.policy)
        return chk

    def test_subfloor_pacer_trips_loud_and_tightens(self):
        x, fr = _scan_subfloor(ceiling=0.6, want_at_least=0.4)
        self.assertLess(fr, 0.75)  # sub-floor by construction
        # 3 cycles: the trip lands on run 5 (3rd contributing run);
        # stop before a second slow-burn epoch can tighten again.
        self._drive_pacer("pacer", _shifted, x, 3)
        names = self.event_names()
        self.assertIn("drift_budget_slow_burn", names)
        slow = [e for e in self.events
                if e.get("event") == "drift_budget_slow_burn"][0]
        self.assertEqual(slow.get("severity"), "LOUD")
        adapted = [e for e in self.events
                   if e.get("event") == "drift_budget_adapted"
                   and e.get("trigger") == "slow_burn"]
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0]["adapt_level"], 1)
        chk = self.store.check("pacer", self.policy)
        self.assertAlmostEqual(chk.detail["effective_limit"], 0.6)

    def test_slower_pacer_never_trips_documents_residual(self):
        # Below slow_trip the within-cycle peak converges under the
        # bar: the documented slower-boil residual (battery s2 pins
        # this at the eval level).
        x, fr = _scan_subfloor(ceiling=0.3, want_at_least=0.2)
        self.assertLess(fr, 0.3)
        self._drive_pacer("slow", _shifted, x, 15)
        self.assertNotIn("drift_budget_slow_burn", self.event_names())
        self.assertNotIn("drift_budget_adapted", self.event_names())

    def test_alternating_directions_stay_quiet(self):
        # Direction-inert scaffolding: alternating exact-opposite
        # sub-floor bursts net to zero, so the consistency gate
        # blocks even though the accumulator would otherwise fill.
        x, fr = _scan_subfloor(ceiling=0.6, want_at_least=0.4,
                               fn=_alt_shift)
        seq = 0
        for i in range(8):
            fn = _alt_shift if i % 2 == 0 else _alt_shift_rev
            for tools in (fn(x), dict(BASE_TOOLS)):
                seq += 1
                self.record("alt", tools, seq)
                self.store.check("alt", self.policy)
        self.assertNotIn("drift_budget_slow_burn", self.event_names())
        self.assertNotIn("drift_budget_adapted", self.event_names())

    def test_single_large_drift_takes_original_path(self):
        x, fr = _scan_below(ceiling=1.5, want_at_least=1.2)
        c = self.record("spike", _shifted(x), 1)
        self.assertEqual(c.reason, "single_run_path")
        chk = self.store.check("spike", self.policy)
        self.assertNotIn("drift_budget_slow_burn", self.event_names())
        self.assertEqual(chk.detail.get("slow_burn_accum"), 0)

    def test_static_policy_has_no_slow_burn_seam(self):
        # Zero-behavior-change contract: a plain BudgetPolicy never
        # emits the slow-burn event, tightens, or reports an active
        # slow-burn seam (detail fields present but inert, matching
        # the adapt_level: 0 precedent).
        h = _Harness()
        h.setUp()
        x, fr = _scan_subfloor(ceiling=0.6, want_at_least=0.4)
        seq = 0
        for _ in range(5):
            for tools in (_shifted(x), dict(BASE_TOOLS)):
                seq += 1
                h.record("a", tools, seq)
                chk = h.store.check("a", h.policy)
        self.assertNotIn("drift_budget_slow_burn",
                         [e.get("event") for e in h.events])
        self.assertNotIn("drift_budget_adapted",
                         [e.get("event") for e in h.events])
        self.assertFalse(chk.detail["slow_burn_tripped"])
        self.assertEqual(chk.detail["slow_burn_accum"], 0)
        self.assertIsNone(chk.detail["slow_burn_threshold"])


class TestContinuity(_AdaptiveHarness):
    """Unit tests for the wave-148 row-9 continuity digest seam."""

    KEY = b"wave148-unit-test-continuity-key"

    def _pace_to_level_1(self, agent="a"):
        for i in range(2):
            self.record(agent, _shifted(_X09), 2 * i + 1)
            self.record(agent, dict(BASE_TOOLS), 2 * i + 2)
        self.assertEqual(
            self.store.check(agent, self.policy).detail["adapt_level"],
            1)

    def test_none_key_resolves_via_chokepoint(self):
        # Wave-148 key-path fix: hmac_key=None resolves through the
        # guarded key chokepoint (gov.keyprovider.resolve_active_key,
        # provisioned for the suite by tests/__init__.py), not through
        # a dev fallback. The chokepoint-keyed digest must import
        # cleanly with hmac_key=None.
        self._pace_to_level_1()
        d = self.store.export_continuity("a", self.policy, None)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        store2 = BudgetStore(tmp2 / "budget")
        self.assertTrue(store2.import_continuity("a", d, None, 5))

    def test_none_key_unprovisioned_fails_closed(self):
        # With no key provisioned, the None path fails closed
        # (NoKeyConfiguredError) instead of inventing key material.
        from gov.keys import NoKeyConfiguredError
        from tests.keyfixture import scrub_key_env
        self._pace_to_level_1()
        digest = self.store.export_continuity("a", self.policy, self.KEY)
        restore = scrub_key_env()
        try:
            with self.assertRaises(NoKeyConfiguredError):
                self.store.export_continuity("a", self.policy, None)
            tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
            store2 = BudgetStore(tmp2 / "budget")
            with self.assertRaises(NoKeyConfiguredError):
                store2.import_continuity("a", digest, None, 5)
        finally:
            restore()

    def test_export_digest_shape(self):
        from gov.drift_budget import _CONTINUITY_VERSION
        self._pace_to_level_1()
        d = self.store.export_continuity("a", self.policy, self.KEY)
        for k in ("v", "agent_id", "run_seq", "adapt_level",
                  "paced_cycles", "rot_history", "slow_accum",
                  "slow_runs", "mac"):
            self.assertIn(k, d)
        self.assertEqual(d["v"], _CONTINUITY_VERSION)
        self.assertEqual(d["agent_id"], "a")
        self.assertEqual(d["adapt_level"], 1)
        self.assertGreaterEqual(d["paced_cycles"], 1)
        self.assertEqual(d["run_seq"], 4)

    def test_export_mac_independent_verification(self):
        # Recompute the MAC without _continuity_mac to prove the
        # scheme (domain separation + canonical JSON) is exactly as
        # documented.
        import hashlib
        import hmac
        from gov.chained_store import canonical
        from gov.drift_budget import _CONTINUITY_MAC_DOMAIN
        self._pace_to_level_1()
        d = self.store.export_continuity("a", self.policy, self.KEY)
        body = {k: v for k, v in d.items() if k != "mac"}
        msg = (_CONTINUITY_MAC_DOMAIN + "\n"
               + canonical(body)).encode("utf-8")
        expected = hmac.new(self.KEY, msg,
                            hashlib.sha256).hexdigest()
        self.assertEqual(d["mac"], expected)

    def test_export_is_deterministic(self):
        self._pace_to_level_1()
        d1 = self.store.export_continuity("a", self.policy, self.KEY)
        d2 = self.store.export_continuity("a", self.policy, self.KEY)
        self.assertEqual(d1, d2)

    def test_import_restores_tightness_and_emits_loud(self):
        self._pace_to_level_1()
        digest = self.store.export_continuity("a", self.policy,
                                             self.KEY)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        events2 = []
        store2 = BudgetStore(tmp2 / "budget",
                             audit=events2.append)
        self.assertTrue(store2.import_continuity("a", digest,
                                                 self.KEY, 5))
        self.assertTrue(store2.verify_chain("a"))
        restored = [e for e in events2
                    if e.get("event") == "drift_state_restored"]
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].get("severity"), "LOUD")
        self.assertEqual(restored[0]["adapt_level"], 1)
        kinds = [r.get("kind")
                 for r in store2.contributions("a")]
        self.assertIn("continuity_restore", kinds)
        # The restored store enforces the tightened limit: check()
        # reports level 1 and the 0.6 effective limit.
        chk = store2.check("a", self.policy)
        self.assertEqual(chk.detail["adapt_level"], 1)
        self.assertAlmostEqual(chk.detail["effective_limit"], 0.6)

    def test_import_tampered_body_refused_loud_no_state_change(self):
        self._pace_to_level_1()
        digest = self.store.export_continuity("a", self.policy,
                                             self.KEY)
        tampered = dict(digest, adapt_level=0)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        events2 = []
        store2 = BudgetStore(tmp2 / "budget",
                             audit=events2.append)
        self.assertFalse(store2.import_continuity("a", tampered,
                                                  self.KEY, 5))
        forged = [e for e in events2
                  if e.get("event")
                  == "drift_digest_forgery_attempt"]
        self.assertEqual(len(forged), 1)
        self.assertEqual(forged[0].get("severity"), "LOUD")
        self.assertEqual(forged[0]["reason"], "bad_mac")
        self.assertEqual(store2.contributions("a"), [])
        self.assertTrue(store2.verify_chain("a"))

    def test_import_wrong_key_refused_loud(self):
        self._pace_to_level_1()
        digest = self.store.export_continuity("a", self.policy,
                                             self.KEY)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        events2 = []
        store2 = BudgetStore(tmp2 / "budget",
                             audit=events2.append)
        self.assertFalse(store2.import_continuity(
            "a", digest, b"wrong-key-0123456789abcdef", 5))
        forged = [e for e in events2
                  if e.get("event") == "drift_digest_forgery_attempt"]
        self.assertEqual(len(forged), 1)
        self.assertEqual(forged[0].get("severity"), "LOUD")
        self.assertEqual(store2.contributions("a"), [])

    def test_import_agent_mismatch_refused(self):
        self._pace_to_level_1()
        digest = self.store.export_continuity("a", self.policy,
                                             self.KEY)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        store2 = BudgetStore(tmp2 / "budget", audit=lambda e: None)
        self.assertFalse(store2.import_continuity("b", digest,
                                                  self.KEY, 5))
        self.assertEqual(store2.contributions("b"), [])

    def test_import_stale_replay_refused(self):
        self._pace_to_level_1()
        new_digest = self.store.export_continuity("a", self.policy,
                                                 self.KEY)
        tmp2 = Path(tempfile.mkdtemp(prefix="test_adaptdrift2_"))
        events2 = []
        store2 = BudgetStore(tmp2 / "budget",
                             audit=events2.append)
        self.assertTrue(store2.import_continuity("a", new_digest,
                                                 self.KEY, 5))
        # A stale digest (older run_seq) re-imported into the same
        # store is refused as a downgrade attempt.
        from gov.drift_budget import _continuity_mac
        old_body = dict(new_digest)
        old_body["run_seq"] = 2
        del old_body["mac"]
        old = dict(old_body,
                   mac=_continuity_mac(self.KEY, old_body))
        events2.clear()
        self.assertFalse(store2.import_continuity("a", old,
                                                  self.KEY, 6))
        forged = [e for e in events2
                  if e.get("event")
                  == "drift_digest_forgery_attempt"]
        self.assertEqual(len(forged), 1)
        self.assertEqual(forged[0]["reason"], "stale_seq")
        # The newer state survives: still level 1.
        self.assertEqual(store2.check("a", self.policy)
                         .detail["adapt_level"], 1)

    def test_import_seeds_slow_burn_accumulator(self):
        # A synthetic-but-MAC-valid digest seeds the slow-burn
        # accumulator and sub-floor run count; later contributions
        # fold on top of the seed.
        from gov.drift_budget import _continuity_mac
        body = {"v": 1, "agent_id": "a", "run_seq": 3,
                "adapt_level": 0, "paced_cycles": 0,
                "rot_history": [], "slow_accum": 0.5,
                "slow_runs": 4}
        digest = dict(body,
                      mac=_continuity_mac(self.KEY, body))
        self.assertTrue(self.store.import_continuity("a", digest,
                                                     self.KEY, 4))
        records = self.store.contributions("a")
        accum, consistency, runs, _ = \
            self.store._slow_burn_state(records, self.policy, 0)
        self.assertAlmostEqual(accum, 0.5)
        self.assertEqual(runs, 4)

    def test_export_rejects_non_policy(self):
        # export_continuity needs the slow-burn fold of the same
        # policy family; a non-BudgetPolicy is rejected loudly.
        with self.assertRaises(TypeError):
            self.store.export_continuity("a", object(), self.KEY)


if __name__ == "__main__":
    unittest.main()
