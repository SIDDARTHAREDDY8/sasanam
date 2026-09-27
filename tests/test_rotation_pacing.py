"""Unit tests for the wave-145 N-period rotation pacing seam (row 9).

Public seams: AdaptiveBudgetPolicy validation, BudgetStore.record_run /
check / verify_chain, the chained reset records' ``rot_history`` /
``rotation_confirmed`` / ``rotation_period`` fields,
``BudgetStore._rotation_fold`` (including backward compatibility when
old records lack ``rot_history``), the pure
``_rotation_period_score`` helper, and the LOUD
``drift_budget_adapted`` event with trigger
``rotation_pacing_confirmed``.

The rotation tripwire: paced defuse cycles (near-trip at >=
``adapt_flip_floor`` -- the SAME floor and direction-consistency
gating the wave-144 flip detector uses) append their direction
signature to a rotation history riding the chained reset records.
For periods p in 3..K (K=4), a trailing window whose last 2p
signatures are two clean back-to-back repetitions of one period-p
pattern (autocorrelation at lag p = 1.0) with >= 2 distinct
directions confirms pacing LOUD -- exactly like a confirmed flip.
Period 2 stays the flip tripwire's; period 1 (single direction)
stays the near-trip streak's; sub-floor cycles never enter the
history; non-paced cycles clear it.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.drift import RunFingerprint, fingerprint_tool_distance
from gov.drift_budget import (
    AdaptiveBudgetPolicy,
    BudgetStore,
    _ROTATION_MAX_PERIOD,
    _rotation_period_score,
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


def _wob_x(x, w):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    t["read_file"] -= w
    t["http_post"] += w
    return t


def _wob_y(x):
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    return t


def _wob_z(x, w):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    t["read_file"] += w
    t["http_post"] -= w
    return t


def _wob_w(x, w):
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    t["read_file"] -= w
    t["http_post"] += w
    return t


def _wob_e(x):
    t = dict(BASE_TOOLS)
    t["email"] -= x
    t["summarize"] += x
    return t


def _wob_e_rev(x):
    # Exact opposite of _wob_e: alternating the two keeps a
    # breaker train net-zero in direction (wave-146: a
    # same-direction sub-floor breaker train is the slow-burn
    # accumulator's attack shape, and that seam legitimately
    # fires on it -- the scaffolding must stay direction-inert).
    t = dict(BASE_TOOLS)
    t["email"] += x
    t["summarize"] -= x
    return t


def _abc_a(x):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    return t


def _abc_b(x):
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    return t


def _abc_c(x):
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["summarize"] += x
    return t


_WOBBLE_FNS = (_wob_x, _wob_y, _wob_z, _wob_w)
_WOB = 1


def _wob_tools(fn, x):
    return fn(x) if fn is _wob_y else fn(x, _WOB)


BASE_FP = _fp(BASE_TOOLS)
_D10 = fingerprint_tool_distance(_fp(_abc_a(10)), BASE_FP)
WARN = _D10 / 0.4


def _frac(tools):
    return fingerprint_tool_distance(_fp(tools), BASE_FP) / WARN


def _scan_wobble(ceiling=1.0, want_at_least=0.85):
    """Largest uniform x with all four wobble bursts under ceiling."""
    best = None
    for x in range(1, 60):
        frs = [_frac(_wob_tools(fn, x)) for fn in _WOBBLE_FNS]
        if all(f < ceiling for f in frs):
            best = (x, frs)
    if best is None or min(best[1]) < want_at_least:
        raise AssertionError("no wobble shape in scan range")
    return best


def _scan_below(fn, ceiling=1.0, want_at_least=0.85):
    best = None
    for x in range(1, 60):
        f = _frac(fn(x))
        if f < ceiling:
            best = (x, f)
    if best is None or best[1] < want_at_least:
        raise AssertionError("no ~0.9 burst in scan range")
    return best


_XW, _FW = _scan_wobble()  # ~0.9x wobble, deterministic
_XA, _FA = _scan_below(_abc_a)
_XB, _FB = _scan_below(_abc_b)
_XC, _FC = _scan_below(_abc_c)


def _policy(**kw):
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                min_contributing_runs=2)
    args.update(kw)
    return AdaptiveBudgetPolicy(**args)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_rotpace_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)

    def drive(self, agent, tools_seq):
        seq = 0
        for tools in tools_seq:
            seq += 1
            self.record(agent, tools, seq)
            if self.store.check(agent, self.policy).status == "tripped":
                return seq
        return None

    def _records(self, agent):
        path = self.tmp / "budget" / ("%s.jsonl" % agent)
        if not path.exists():
            return []
        return [json.loads(line) for line in
                path.read_text().splitlines() if line.strip()]

    def _resets(self, agent):
        return [r for r in self._records(agent)
                if r.get("kind") == "reset"]

    def rotation_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "rotation_pacing_confirmed"]

    def flip_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "direction_pacing_confirmed"]

    def streak_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"
                and e.get("trigger") == "near_trip_cycle"]

    def any_adapts(self):
        return [e for e in self.events
                if e.get("event") == "drift_budget_adapted"]


class RotationScoreTests(unittest.TestCase):
    def test_exact_repetition_scores_one(self):
        self.assertEqual(
            _rotation_period_score(
                ["a", "b", "c", "d", "a", "b", "c", "d"], 4), 1.0)
        self.assertEqual(
            _rotation_period_score(["a", "b", "c"] * 2, 3), 1.0)

    def test_short_history_scores_zero(self):
        self.assertEqual(
            _rotation_period_score(["a", "b", "c", "d"], 4), 0.0)
        self.assertEqual(_rotation_period_score([], 3), 0.0)

    def test_mismatch_below_one(self):
        s = _rotation_period_score(
            ["a", "b", "c", "d", "a", "b", "X", "d"], 4)
        self.assertEqual(s, 0.75)

    def test_single_direction_scores_one_but_needs_distinctness(self):
        # The score is pure autocorrelation; the >= 2 distinct
        # directions rule lives in the confirmation logic (a single
        # repeated direction belongs to the near-trip streak).
        self.assertEqual(
            _rotation_period_score(["a"] * 8, 4), 1.0)


class RotationFoldTests(_Harness):
    def test_fold_empty_without_records(self):
        self.assertEqual(BudgetStore._rotation_fold([]), [])

    def test_fold_missing_history_backward_compatible(self):
        # Pre-wave-145 reset records carry no rot_history.
        recs = [{"kind": "reset", "run_seq": 1},
                {"kind": "reset", "run_seq": 2,
                 "direction_sig": "email:+1|search:-1"}]
        self.assertEqual(BudgetStore._rotation_fold(recs), [])

    def test_fold_takes_latest_reset_history(self):
        recs = [{"kind": "reset", "run_seq": 1,
                 "rot_history": ["a", "b"]},
                {"kind": "reset", "run_seq": 2,
                 "rot_history": ["a", "b", "c"]}]
        self.assertEqual(BudgetStore._rotation_fold(recs),
                         ["a", "b", "c"])

    def test_fold_cleared_by_reset_directions_adapt(self):
        recs = [{"kind": "reset", "run_seq": 1,
                 "rot_history": ["a", "b", "c", "d"]},
                {"kind": "adapt", "run_seq": 2,
                 "reset_directions": True}]
        self.assertEqual(BudgetStore._rotation_fold(recs), [])

    def test_fold_keeps_history_through_streak_adapt(self):
        # near_trip_cycle tightens with reset_streak only (no
        # reset_directions): the rotation hunt survives.
        recs = [{"kind": "reset", "run_seq": 1,
                 "rot_history": ["a", "b"]},
                {"kind": "adapt", "run_seq": 2,
                 "reset_streak": True}]
        self.assertEqual(BudgetStore._rotation_fold(recs), ["a", "b"])

    def test_fold_ignores_non_string_entries(self):
        recs = [{"kind": "reset", "run_seq": 1,
                 "rot_history": ["a", None, 7, "b"]}]
        self.assertEqual(BudgetStore._rotation_fold(recs), ["a", "b"])


class Period4ConfirmationTests(_Harness):
    def _wobble_drive(self, agent, cycles):
        seq_tools = []
        for _ in range(cycles // 4):
            for fn in _WOBBLE_FNS:
                seq_tools += [_wob_tools(fn, _XW), dict(BASE_TOOLS)]
        return seq_tools

    def test_period4_confirms_at_eighth_paced_cycle(self):
        agent = "rot4"
        tripped = self.drive(agent, self._wobble_drive(agent, 8))
        self.assertIsNone(tripped)  # 16 runs: no trip yet
        confirmed = self.rotation_adapts()
        self.assertEqual(len(confirmed), 1)
        ev = confirmed[0]
        self.assertEqual(ev.get("severity"), "LOUD")
        self.assertEqual(ev.get("event"), "drift_budget_adapted")
        evidence = ev.get("evidence", {})
        self.assertEqual(evidence.get("rotation_period"), 4)
        self.assertEqual(len(evidence.get("rotation_pattern", [])), 4)
        self.assertIn("pacing_floor", evidence)
        self.assertIn("cycle_cumulative", evidence)
        self.assertIn("cycle_consistency", evidence)
        # The confirming reset record carries the rotation fields.
        resets = self._resets(agent)
        self.assertTrue(resets[-1].get("rotation_confirmed"))
        self.assertEqual(resets[-1].get("rotation_period"), 4)
        # And the next contributing run trips under the tightened
        # limit.
        seq = 17
        self.record(agent, _wob_tools(_wob_x, _XW), seq)
        chk = self.store.check(agent, self.policy)
        self.assertEqual(chk.status, "tripped")
        self.assertIn("drift_budget_tripped",
                      [e.get("event") for e in self.events])
        self.assertTrue(self.store.verify_chain(agent))

    def test_seven_paced_cycles_not_enough(self):
        # Two FULL periods are required: 7 paced cycles stay quiet.
        agent = "rot4short"
        seq_tools = self._wobble_drive(agent, 8)[:-2]  # 7 cycles
        tripped = self.drive(agent, seq_tools)
        self.assertIsNone(tripped)
        self.assertEqual(self.rotation_adapts(), [])
        self.assertEqual(self.any_adapts(), [])

    def test_max_period_constant_is_four(self):
        self.assertEqual(_ROTATION_MAX_PERIOD, 4)


class Period3ConfirmationTests(_Harness):
    def test_period3_confirms_with_streak_isolated(self):
        # Odd-period paced rotations cannot evade the default
        # near-trip streak (parity argument), so period-3
        # confirmation is exercised with the streak, the direction
        # buckets, and the static trip all isolated via operator
        # calibration -- the rotation seam itself must still
        # confirm a clean 3-period repetition.
        self.policy = _policy(adapt_cycles=100,
                              adapt_dir_threshold=100.0,
                              min_contributing_runs=100)
        agent = "rot3"
        seq_tools = []
        for _ in range(2):
            for fn, bx in ((_abc_a, _XA), (_abc_b, _XB),
                           (_abc_c, _XC)):
                seq_tools += [fn(bx), dict(BASE_TOOLS)]
        tripped = self.drive(agent, seq_tools)
        self.assertIsNone(tripped)
        confirmed = self.rotation_adapts()
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(
            confirmed[0].get("evidence", {}).get("rotation_period"),
            3)
        self.assertEqual(self.flip_adapts(), [])
        self.assertEqual(self.streak_adapts(), [])
        self.assertTrue(self.store.verify_chain(agent))


class GatingTests(_Harness):
    def test_subfloor_cycles_never_enter_history(self):
        xw, _frs = _scan_wobble(ceiling=0.6, want_at_least=0.4)
        self.assertLess(max(_frs), 0.75)
        agent = "subfloor"
        seq_tools = []
        for _ in range(8):
            for fn in _WOBBLE_FNS:
                seq_tools += [_wob_tools(fn, xw), dict(BASE_TOOLS)]
        tripped = self.drive(agent, seq_tools)
        self.assertIsNone(tripped)
        self.assertEqual(self.any_adapts(), [])
        for r in self._resets(agent):
            self.assertEqual(r.get("rot_history"), [])

    def test_breaker_cycle_clears_history(self):
        xe, _fe = _scan_below(_wob_e, ceiling=0.6, want_at_least=0.4)
        agent = "breaker"
        seq_tools = []
        # Breaker direction alternates E / reverse-E (net zero):
        # the breakers are non-paced scaffolding and must stay
        # direction-inert (see _wob_e_rev).
        bi = 0
        for fn in _WOBBLE_FNS:
            brk = _wob_e(xe) if bi % 2 == 0 else _wob_e_rev(xe)
            bi += 1
            seq_tools += [_wob_tools(fn, _XW), dict(BASE_TOOLS),
                          brk, dict(BASE_TOOLS)]
        tripped = self.drive(agent, seq_tools)
        self.assertIsNone(tripped)
        self.assertEqual(self.any_adapts(), [])
        # Every other defuse is the sub-floor breaker: its reset
        # record carries an empty rotation history.
        resets = self._resets(agent)
        breaker_resets = resets[1::2]
        self.assertTrue(breaker_resets)
        for r in breaker_resets:
            self.assertEqual(r.get("rot_history"), [])
            self.assertFalse(r.get("rotation_confirmed"))

    def test_persisted_state_deterministic(self):
        agent = "persist"
        seq_tools = []
        for fn in _WOBBLE_FNS:
            seq_tools += [_wob_tools(fn, _XW), dict(BASE_TOOLS)]
        self.drive(agent, seq_tools)  # 4 paced cycles
        before = BudgetStore._rotation_fold(
            [r for r in self._records(agent)])
        # Reopen the store on the same directory: the fold must be
        # identical (persisted chained records, no memory state).
        reopened = BudgetStore(self.tmp / "budget",
                               audit=self.events.append)
        after = BudgetStore._rotation_fold(
            [r for r in reopened.contributions(agent)])
        self.assertEqual(before, after)
        self.assertEqual(len(after), 4)


class NoRegressionTests(_Harness):
    def test_two_period_still_flip_owned(self):
        agent = "flip2"
        seq_tools = []
        for _ in range(4):
            seq_tools += [_abc_a(_XA), dict(BASE_TOOLS),
                          _abc_b(_XB), dict(BASE_TOOLS)]
        tripped = self.drive(agent, seq_tools)
        self.assertEqual(tripped, 7)
        self.assertEqual(len(self.flip_adapts()), 1)
        self.assertEqual(self.rotation_adapts(), [])

    def test_single_direction_static_trip_no_rotation(self):
        # Period 1 (a single repeated direction) never enters the
        # rotation confirmation: two same-direction 0.9x bursts
        # already trip the static budget (cum 1.8 >= 1.0) before any
        # rotation depth is reachable.
        agent = "single"
        seq_tools = []
        for _ in range(4):
            seq_tools += [_abc_a(_XA), dict(BASE_TOOLS)]
        tripped = self.drive(agent, seq_tools)
        self.assertEqual(tripped, 5)
        self.assertEqual(self.rotation_adapts(), [])


if __name__ == "__main__":
    unittest.main()
