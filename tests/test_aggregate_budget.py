#!/usr/bin/env python3
"""Unit tests for gov/aggregate_budget.py (wave-242 lane A, W242-1).

Cumulative cross-act budget keyed by (scope, window): refuses
``aggregate-budget-exhausted`` when the aggregate would exceed the
cap even though each act is within its own budget. Deterministic;
no network; stdlib only.
"""

import unittest

from gov import aggregate_budget as ab


class _Clock(object):
    def __init__(self, start=1_000_000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _agg(**kw):
    clock = _Clock()
    agg = ab.AggregateBudget(now=clock, **kw)
    return agg, clock


class DeclareTest(unittest.TestCase):
    def test_declare_and_state(self):
        agg, _ = _agg()
        declared = agg.declare_scope("deploy", 100, window_seconds=3600)
        self.assertEqual(declared["cap"], 100)
        state = agg.state("deploy")
        self.assertEqual(state["aggregate_total"], 0)
        self.assertEqual(state["cap"], 100)

    def test_declare_bad_cap_malformed(self):
        agg, _ = _agg()
        for bad in (0, -1, "100", None):
            with self.assertRaises(ab.AggregateBudgetError) as ctx:
                agg.declare_scope("s", bad, window_seconds=60)
            self.assertEqual(ctx.exception.code,
                             "aggregate-budget-malformed")

    def test_declare_bad_window_malformed(self):
        agg, _ = _agg()
        for bad in (0, -60, "60", None):
            with self.assertRaises(ab.AggregateBudgetError) as ctx:
                agg.declare_scope("s", 100, window_seconds=bad)
            self.assertEqual(ctx.exception.code,
                             "aggregate-budget-malformed")

    def test_redeclare_scope_malformed(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.declare_scope("deploy", 200, window_seconds=3600)
        self.assertEqual(ctx.exception.code, "aggregate-budget-malformed")

    def test_state_undeclared_malformed(self):
        agg, _ = _agg()
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.state("nope")
        self.assertEqual(ctx.exception.code,
                         "aggregate-budget-scope-undeclared")


class ChargeTest(unittest.TestCase):
    def test_charge_accumulates(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        e1 = agg.charge("deploy", "iss", "jti-1", 30)
        e2 = agg.charge("deploy", "iss", "jti-2", 30)
        self.assertEqual(e1["aggregate_total"], 30)
        self.assertEqual(e2["aggregate_total"], 60)
        self.assertEqual(agg.state("deploy")["aggregate_total"], 60)

    def test_exact_cap_passes(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        agg.charge("deploy", "iss", "jti-1", 60)
        entry = agg.charge("deploy", "iss", "jti-2", 40)
        self.assertEqual(entry["aggregate_total"], 100)

    def test_over_cap_exhausted(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        agg.charge("deploy", "iss", "jti-1", 60)
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.charge("deploy", "iss", "jti-2", 41)
        self.assertEqual(ctx.exception.code, "aggregate-budget-exhausted")
        # The refused charge did not move the total.
        self.assertEqual(agg.state("deploy")["aggregate_total"], 60)

    def test_duplicate_jti_already_charged(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        agg.charge("deploy", "iss", "jti-1", 10)
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.charge("deploy", "iss", "jti-1", 10)
        self.assertEqual(ctx.exception.code,
                         "aggregate-budget-already-charged")
        self.assertEqual(agg.state("deploy")["aggregate_total"], 10)

    def test_scopes_are_independent(self):
        agg, _ = _agg()
        agg.declare_scope("a", 50, window_seconds=3600)
        agg.declare_scope("b", 50, window_seconds=3600)
        agg.charge("a", "iss", "jti-1", 50)
        agg.charge("b", "iss", "jti-1", 50)  # same jti, other scope: OK
        self.assertEqual(agg.state("a")["aggregate_total"], 50)
        self.assertEqual(agg.state("b")["aggregate_total"], 50)

    def test_bad_amounts_malformed(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        for bad in (0, -3, "10", None, float("nan"), float("inf")):
            with self.assertRaises(ab.AggregateBudgetError) as ctx:
                agg.charge("deploy", "iss", "jti-bad", bad)
            self.assertEqual(ctx.exception.code,
                             "aggregate-budget-malformed")

    def test_state_returns_copies(self):
        agg, _ = _agg()
        agg.declare_scope("deploy", 100, window_seconds=3600)
        st = agg.state("deploy")
        st["aggregate_total"] = 9999
        self.assertEqual(agg.state("deploy")["aggregate_total"], 0)


class RolloverTest(unittest.TestCase):
    def test_rollover_resets_aggregate_keeps_entries(self):
        agg, clock = _agg()
        agg.declare_scope("deploy", 100, window_seconds=60)
        agg.charge("deploy", "iss", "jti-old", 90)
        clock.advance(61)
        rolled = agg.roll_window("deploy")
        self.assertEqual(rolled["aggregate_total"], 0)
        # New jti can spend again in the new window.
        entry = agg.charge("deploy", "iss", "jti-new", 90)
        self.assertEqual(entry["aggregate_total"], 90)
        # Old jti is still recorded: no replay.
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.charge("deploy", "iss", "jti-old", 10)
        self.assertEqual(ctx.exception.code,
                         "aggregate-budget-already-charged")

    def test_auto_roll_on_charge(self):
        agg, clock = _agg()
        agg.declare_scope("deploy", 100, window_seconds=60)
        agg.charge("deploy", "iss", "jti-1", 90)
        clock.advance(120)  # past window; charge auto-rolls
        entry = agg.charge("deploy", "iss", "jti-2", 90)
        self.assertEqual(entry["aggregate_total"], 90)

    def test_roll_undeclared_malformed(self):
        agg, _ = _agg()
        with self.assertRaises(ab.AggregateBudgetError) as ctx:
            agg.roll_window("nope")
        self.assertEqual(ctx.exception.code,
                         "aggregate-budget-scope-undeclared")


if __name__ == "__main__":
    unittest.main()
