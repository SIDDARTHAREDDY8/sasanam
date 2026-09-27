"""Unit tests for the wave-141 flip-direction pacing seam (row 9).

Public seams: AdaptiveBudgetPolicy validation/serialization,
_direction_key, BudgetStore.record_run / check / verify_chain,
the chained reset records' direction_scores, and the LOUD
drift_budget_adapted event with trigger "direction_pacing".
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov.drift import RunFingerprint, fingerprint_tool_distance
from gov.drift_budget import (
    AdaptiveBudgetPolicy,
    BudgetStore,
    _direction_key,
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
    """Exact-opposite pair, forward: search -> email."""
    t = dict(BASE_TOOLS)
    t["search"] -= x
    t["email"] += x
    return t


def _flip_rev(x):
    """Exact-opposite pair, reverse: email -> search."""
    t = dict(BASE_TOOLS)
    t["search"] += x
    t["email"] -= x
    return t


BASE_FP = _fp(BASE_TOOLS)
_D10 = fingerprint_tool_distance(_fp(_flip_fwd(10)), BASE_FP)
WARN = _D10 / 0.4


def _scan_below(ceiling=1.0, want_at_least=0.85, hi=59):
    """Largest x whose flip burst stays under ``ceiling`` (>= floor)."""
    best = None
    for x in range(1, hi + 1):
        f = (fingerprint_tool_distance(_fp(_flip_fwd(x)), BASE_FP)
             / WARN)
        if f < ceiling:
            best = (x, f)
    if best is None or best[1] < want_at_least:
        raise AssertionError("no ~0.9 flip burst in scan range")
    return best


_X09, _F09 = _scan_below()  # ~0.9 threshold-equivalents, deterministic
_F09_REV = (fingerprint_tool_distance(_fp(_flip_rev(_X09)), BASE_FP)
            / WARN)  # reverse direction is slightly asymmetric


def _policy(**kw):
    args = dict(warn_distance=WARN, budget_limit=1.0, window_runs=8,
                noise_floor=0.1, min_consistency=0.5,
                min_contributing_runs=2)
    args.update(kw)
    return AdaptiveBudgetPolicy(**args)


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="test_flippace_"))
        self.events = []
        self.store = BudgetStore(self.tmp / "budget",
                                 audit=self.events.append)
        self.policy = _policy()

    def record(self, agent, tools, seq):
        return self.store.record_run(agent, seq, "run-%d" % seq,
                                     _fp(tools, run_seq=seq), BASE_FP,
                                     self.policy)

    def event_names(self):
        return [e.get("event") for e in self.events]

    def _reset_records(self, agent):
        recs = []
        path = self.tmp / "budget" / ("%s.jsonl" % agent)
        if path.exists():
            import json
            recs = [json.loads(line) for line in
                    path.read_text().splitlines() if line.strip()]
        return [r for r in recs if r.get("kind") == "reset"]

    def _adapt_records(self, agent):
        recs = []
        path = self.tmp / "budget" / ("%s.jsonl" % agent)
        if path.exists():
            import json
            recs = [json.loads(line) for line in
                    path.read_text().splitlines() if line.strip()]
        return [r for r in recs if r.get("kind") == "adapt"]


class TestDirectionKey(unittest.TestCase):
    def test_exact_opposites_give_different_nonempty_keys(self):
        fwd_net = {"search": -5.0, "email": 5.0}
        rev_net = {"search": 5.0, "email": -5.0}
        kf = _direction_key(fwd_net)
        kr = _direction_key(rev_net)
        self.assertTrue(kf)
        self.assertTrue(kr)
        self.assertNotEqual(kf, kr)

    def test_same_direction_same_key(self):
        a = {"search": -5.0, "email": 5.0, "summarize": 0.0}
        b = {"search": -12.0, "email": 3.0}
        # magnitude and zero deltas do not affect the key
        self.assertEqual(_direction_key(a), _direction_key(b))

    def test_empty_net_gives_empty_key(self):
        self.assertEqual(_direction_key({}), "")
        self.assertEqual(_direction_key({"search": 0.0}), "")

    def test_deterministic_ordering(self):
        net = {"email": 2.0, "search": -2.0, "read_file": 1.0}
        self.assertEqual(_direction_key(net), _direction_key(net))
        parts = _direction_key(net).split("|")
        self.assertEqual(parts, sorted(parts))


class TestDirectionPolicyValidation(unittest.TestCase):
    def test_defaults(self):
        p = AdaptiveBudgetPolicy(100.0)
        self.assertEqual(p.adapt_dir_decay, 0.9)
        self.assertEqual(p.adapt_dir_threshold, 2.4)

    def test_bad_decay_rejected(self):
        for bad in (0, 1, 1.5, -0.1, "x", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AdaptiveBudgetPolicy(100.0, adapt_dir_decay=bad)

    def test_bad_threshold_rejected(self):
        for bad in (0, -1.0, "x", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                AdaptiveBudgetPolicy(100.0, adapt_dir_threshold=bad)

    def test_serialized(self):
        p = AdaptiveBudgetPolicy(100.0, adapt_dir_decay=0.85,
                                 adapt_dir_threshold=2.2)
        d = p.to_dict()
        self.assertEqual(d["adapt_dir_decay"], 0.85)
        self.assertEqual(d["adapt_dir_threshold"], 2.2)


class TestFlipPacingBuckets(_Harness):
    def test_flip_pacer_tightens_loud_with_direction_trigger(self):
        seq = 0
        tripped_at = None
        for _ in range(4):
            for tools in (_flip_fwd(_X09), dict(BASE_TOOLS),
                          _flip_rev(_X09), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
                if self.store.check("a", self.policy).status == "tripped":
                    tripped_at = seq
                    break
            if tripped_at is not None:
                break
        adapted = [e for e in self.events
                   if e.get("event") == "drift_budget_adapted"]
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0].get("severity"), "LOUD")
        self.assertEqual(adapted[0]["trigger"], "direction_pacing")
        evidence = adapted[0]["evidence"]
        # The tripping bucket is the forward one (it accrued the most
        # recent burst): the evidence must name the max bucket, not
        # just the current cycle.
        fwd_sig = _direction_key({"search": -1.0, "email": 1.0})
        self.assertEqual(evidence["direction_sig"], fwd_sig)
        self.assertGreaterEqual(evidence["direction_score"],
                                self.policy.adapt_dir_threshold)
        self.assertEqual(evidence["direction_threshold"],
                         self.policy.adapt_dir_threshold)
        adapts = self._adapt_records("a")
        self.assertEqual(len(adapts), 1)
        self.assertTrue(adapts[0]["reset_directions"])
        self.assertIsNotNone(tripped_at)
        self.assertIn("drift_budget_tripped", self.event_names())
        self.assertTrue(self.store.verify_chain("a"))

    def test_buckets_decay_instead_of_resetting_on_flip(self):
        # F, clean, R, clean, F, clean: after the R-cycle the
        # forward bucket must be decayed, not zeroed.
        seq = 0
        for tools in (_flip_fwd(_X09), dict(BASE_TOOLS),
                      _flip_rev(_X09), dict(BASE_TOOLS),
                      _flip_fwd(_X09), dict(BASE_TOOLS)):
            seq += 1
            self.record("a", tools, seq)
        resets = self._reset_records("a")
        self.assertEqual(len(resets), 3)  # one per defuse cycle
        fwd_sig = _direction_key({"search": -1.0, "email": 1.0})
        rev_sig = _direction_key({"search": 1.0, "email": -1.0})
        # After cycle 1: only the forward bucket, ~0.9.
        s1 = resets[0]["direction_scores"]
        self.assertAlmostEqual(s1[fwd_sig], _F09, places=5)
        self.assertNotIn(rev_sig, s1)
        # After cycle 2 (reverse): forward bucket decayed, reverse
        # bucket holds one burst.
        s2 = resets[1]["direction_scores"]
        self.assertAlmostEqual(s2[fwd_sig], _F09 * 0.9, places=5)
        self.assertAlmostEqual(s2[rev_sig], _F09_REV, places=5)
        # After cycle 3: forward bucket = decayed + new burst.
        s3 = resets[2]["direction_scores"]
        self.assertAlmostEqual(s3[fwd_sig], _F09 * 0.9 ** 2 + _F09,
                               places=5)

    def test_benign_alternation_never_adapts(self):
        xf, f = _scan_below(ceiling=0.9, want_at_least=0.8)
        seq = 0
        for _ in range(3):
            for tools in (_flip_fwd(xf), dict(BASE_TOOLS),
                          _flip_rev(xf), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.status, "ok")
        self.assertNotIn("drift_budget_adapted", self.event_names())
        self.assertEqual(chk.detail["adapt_level"], 0)

    def test_same_direction_streak_still_fires_first(self):
        # Two same-direction ~0.9 cycles: the near_trip_cycle streak
        # trigger fires before the direction bucket (0.97*1.9 < 2.4).
        seq = 0
        for _ in range(2):
            for tools in (_flip_fwd(_X09), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        adapted = [e for e in self.events
                   if e.get("event") == "drift_budget_adapted"]
        self.assertEqual(len(adapted), 1)
        self.assertEqual(adapted[0]["trigger"], "near_trip_cycle")

    def test_relax_after_direction_tighten(self):
        seq = 0
        for _ in range(4):
            for tools in (_flip_fwd(_X09), dict(BASE_TOOLS),
                          _flip_rev(_X09), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        self.assertEqual(self.store.check("a", self.policy)
                         .detail["adapt_level"], 1)
        # Benign cycles relax the level back down; the
        # reset_directions flag on the tighten must not break the fold.
        for i in range(2):
            seq += 1
            self.record("a", _flip_fwd(5), seq)
            seq += 1
            self.record("a", dict(BASE_TOOLS), seq)
        chk = self.store.check("a", self.policy)
        self.assertEqual(chk.status, "ok")
        self.assertEqual(chk.detail["adapt_level"], 0)

    def test_backward_compat_fold_ignores_missing_fields(self):
        # An old chained log (pre-wave-141, no direction_scores on
        # reset records, no reset_directions on adapt records) must
        # fold cleanly to empty buckets.
        seq = 0
        for _ in range(2):  # adapt to level 1 via streak trigger
            for tools in (_flip_fwd(_X09), dict(BASE_TOOLS)):
                seq += 1
                self.record("a", tools, seq)
        import json
        path = self.tmp / "budget" / "a.jsonl"
        recs = [json.loads(line) for line in
                path.read_text().splitlines() if line.strip()]
        stripped = []
        for r in recs:
            r = dict(r)
            r.pop("direction_scores", None)
            r.pop("direction_sig", None)
            r.pop("direction_trip", None)
            r.pop("reset_directions", None)
            stripped.append(r)
        path.write_text("\n".join(json.dumps(r) for r in stripped)
                        + "\n")
        store2 = BudgetStore(self.tmp / "budget",
                             audit=self.events.append)
        chk = store2.check("a", self.policy)
        self.assertEqual(chk.detail["adapt_level"], 1)
        # New flip pattern still detected from the stripped log.
        seq2 = 100
        for _ in range(4):
            for tools in (_flip_fwd(_X09), dict(BASE_TOOLS),
                          _flip_rev(_X09), dict(BASE_TOOLS)):
                seq2 += 1
                store2.record_run("a", seq2, "run-%d" % seq2,
                                  _fp(tools, run_seq=seq2), BASE_FP,
                                  self.policy)
        self.assertIn("drift_budget_adapted", self.event_names())


if __name__ == "__main__":
    unittest.main()
