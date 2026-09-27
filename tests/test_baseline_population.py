#!/usr/bin/env python3
"""Unit tests for wave-134 population-relative baseline validation.

Covers gov.drift.PopulationStore, validate_baseline_against_population,
cap_drift_verdict, fingerprint_tool_distance, and the chi-square
refactor (behavioral equivalence with the pre-wave-134 signal).
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import drift as _drift  # noqa: E402


def _fp(tools, egress=4_000, run_seq=0):
    return _drift.RunFingerprint(
        tool_counts=dict(tools),
        decisions={"allow": sum(tools.values()), "require_approval": 0,
                   "deny": 0},
        egress_bytes=egress, run_seq=run_seq)


_NORMAL = {"search": 40, "summarize": 30, "email": 20, "read_file": 10}
_ATTACK = {"http_post": 90, "email": 10}


def _pop_store():
    root = Path(tempfile.mkdtemp(prefix="poptest_"))
    return _drift.PopulationStore(root / "population")


def _peers(n=5):
    out = []
    for i in range(n):
        tools = dict(_NORMAL)
        tools["search"] += i
        out.append(("peer-%d" % i, _fp(tools)))
    return out


class TestChi2Refactor(unittest.TestCase):
    def test_helper_matches_inline_math(self):
        base = {"search": 40, "summarize": 30, "email": 20, "read_file": 10}
        win = {"search": 10, "summarize": 30, "email": 20, "read_file": 10,
               "http_post": 30}
        res = _drift._chi2_stat(base, win)
        self.assertIsNotNone(res)
        stat, df, novel = res
        self.assertEqual(df, 4)
        self.assertGreater(stat, 0)
        self.assertGreater(novel, 0)  # http_post is novel
        p = _drift.chi_square_sf(stat, df)
        self.assertLess(p, 0.05)

    def test_helper_none_on_small_mass(self):
        self.assertIsNone(_drift._chi2_stat({"a": 3}, {"a": 30}))
        self.assertIsNone(_drift._chi2_stat({"a": 30}, {"a": 3}))

    def test_helper_none_single_category(self):
        self.assertIsNone(_drift._chi2_stat({"a": 50}, {"a": 60}))

    def test_signal_unchanged_behavior(self):
        # The refactored _signal_tool_distribution must behave as
        # before: strong shift on a moved distribution, None on
        # identical ones.
        base = [{"fingerprint": _fp(_NORMAL).to_dict()}]
        same = [{"fingerprint": _fp(_NORMAL).to_dict()}]
        moved = [{"fingerprint": _fp(
            {"search": 5, "http_post": 60, "email": 35}).to_dict()}]
        self.assertIsNone(_drift._signal_tool_distribution(base, same))
        sig = _drift._signal_tool_distribution(base, moved)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.kind, "tool_distribution")


class TestDistance(unittest.TestCase):
    def test_identical_not_an_outlier(self):
        # Spec-relevant property, implementation-agnostic: a newcomer
        # identical to every peer must validate trusted (its distance
        # cannot exceed the peer-pairwise threshold).
        peers = [("peer-%d" % i, _fp(_NORMAL)) for i in range(5)]
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), peers)
        self.assertEqual(res.status, "trusted")

    def test_distance_orders_attacker_above_normal(self):
        d_attack = _drift.fingerprint_tool_distance(
            _fp(_ATTACK), _fp(_NORMAL))
        d_normal = _drift.fingerprint_tool_distance(
            _fp(_NORMAL), _fp(_NORMAL))
        self.assertIsNotNone(d_attack)
        self.assertIsNotNone(d_normal)
        self.assertGreater(d_attack, d_normal)

    def test_none_on_small_mass(self):
        self.assertIsNone(
            _drift.fingerprint_tool_distance(_fp({"a": 5}), _fp(_NORMAL)))

    def test_type_checked(self):
        with self.assertRaises(TypeError):
            _drift.fingerprint_tool_distance("x", _fp(_NORMAL))


class TestValidate(unittest.TestCase):
    def test_attacker_provisional(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_ATTACK), _peers())
        self.assertEqual(res.status, "provisional_untrusted")
        self.assertGreater(res.agent_distance, res.threshold)
        self.assertEqual(res.n_peers, 5)

    def test_normal_trusted(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), _peers())
        self.assertEqual(res.status, "trusted")

    def test_self_excluded(self):
        peers = _peers() + [("new", _fp(_ATTACK))]
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), peers)
        self.assertEqual(res.status, "trusted")
        self.assertEqual(res.n_peers, 5)

    def test_no_population(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), [])
        self.assertEqual(res.status, "unvalidated_no_population")
        self.assertIn("no_population", str(res.detail))

    def test_too_few_peers(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), _peers(2))
        self.assertEqual(res.status, "unvalidated_no_population")

    def test_insufficient_new_mass(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp({"a": 5}), _peers())
        self.assertEqual(res.status, "unvalidated_insufficient_data")

    def test_custom_quantile(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_ATTACK), _peers(), outlier_quantile=0.5)
        self.assertEqual(res.status, "provisional_untrusted")

    def test_bad_quantile_rejected(self):
        with self.assertRaises(ValueError):
            _drift.validate_baseline_against_population(
                "new", _fp(_NORMAL), _peers(), outlier_quantile=1.5)

    def test_bad_status_rejected(self):
        with self.assertRaises(ValueError):
            _drift.BaselineValidationResult("bogus")

    def test_to_dict(self):
        res = _drift.validate_baseline_against_population(
            "new", _fp(_NORMAL), _peers())
        d = res.to_dict()
        self.assertEqual(d["status"], "trusted")
        self.assertEqual(d["n_peers"], 5)


class TestPopulationStore(unittest.TestCase):
    def test_record_and_verify(self):
        pop = _pop_store()
        rec = pop.record_baseline("a1", "user-1", _fp(_NORMAL))
        self.assertEqual(rec["baseline_trust"], "trusted")
        self.assertTrue(pop.verify_chain())
        bl = pop.all_baselines()
        self.assertEqual(len(bl), 1)
        self.assertEqual(bl[0][0], "a1")
        self.assertEqual(bl[0][1].tool_counts["search"], 40)

    def test_provisional_recorded(self):
        pop = _pop_store()
        for i, (a, f) in enumerate(_peers()):
            pop.record_baseline(a, "user-1", f)
        res = _drift.validate_baseline_against_population(
            "evil", _fp(_ATTACK), pop.all_baselines())
        pop.record_baseline("evil", "user-1", _fp(_ATTACK),
                            validation=res)
        trust, _ = pop.trust_of("evil")
        self.assertEqual(trust, "provisional")
        self.assertTrue(pop.verify_chain())

    def test_tamper_detected(self):
        pop = _pop_store()
        pop.record_baseline("a1", "user-1", _fp(_NORMAL))
        p = pop._path()
        p.write_text(p.read_text()[:-12] + "deadbeef\n")
        self.assertFalse(pop.verify_chain())
        with self.assertRaises(_drift.PopulationCorruptedError):
            pop.all_baselines()
        with self.assertRaises(_drift.PopulationCorruptedError):
            pop.trust_of("a1")
        with self.assertRaises(_drift.PopulationCorruptedError):
            pop.record_baseline("a2", "user-1", _fp(_NORMAL))

    def test_garbage_file_fail_closed(self):
        pop = _pop_store()
        pop._path().write_text("this is not json\n")
        self.assertFalse(pop.verify_chain())
        with self.assertRaises(_drift.PopulationCorruptedError):
            pop.all_baselines()

    def test_confirm_baseline(self):
        pop = _pop_store()
        pop.record_baseline("w", "user-1", _fp(_NORMAL),
                            validation=_drift.BaselineValidationResult(
                                "provisional_untrusted", agent_id="w"))
        self.assertEqual(pop.trust_of("w")[0], "provisional")
        pop.confirm_baseline("w")
        trust, detail = pop.trust_of("w")
        self.assertEqual(trust, "trusted")
        self.assertEqual(detail["reason"], "human_confirm")
        self.assertTrue(pop.verify_chain())

    def test_auto_converge(self):
        pop = _pop_store()
        for a, f in _peers():
            pop.record_baseline(a, "user-1", f)
        weird = {"translate": 80, "search": 20}
        res = _drift.validate_baseline_against_population(
            "w", _fp(weird), pop.all_baselines())
        self.assertEqual(res.status, "provisional_untrusted")
        pop.record_baseline("w", "user-1", _fp(weird), validation=res)
        for i in range(2):
            peers = [(a, f) for a, f in pop.all_baselines() if a != "w"]
            trust, detail = pop.note_run("w", _fp(_NORMAL), peers,
                                         auto_confirm_runs=3)
            self.assertEqual(trust, "provisional")
            self.assertEqual(detail["consecutive_trusted"], i + 1)
        peers = [(a, f) for a, f in pop.all_baselines() if a != "w"]
        trust, detail = pop.note_run("w", _fp(_NORMAL), peers,
                                     auto_confirm_runs=3)
        self.assertEqual(trust, "trusted")
        self.assertTrue(detail["auto_converged"])
        self.assertEqual(pop.trust_of("w")[0], "trusted")

    def test_converge_reset_on_deviation(self):
        pop = _pop_store()
        for a, f in _peers():
            pop.record_baseline(a, "user-1", f)
        res = _drift.BaselineValidationResult(
            "provisional_untrusted", agent_id="w")
        pop.record_baseline("w", "user-1", _fp(_NORMAL), validation=res)
        peers = [(a, f) for a, f in pop.all_baselines() if a != "w"]
        pop.note_run("w", _fp(_NORMAL), peers, auto_confirm_runs=3)
        # A deviating run resets the counter.
        trust, detail = pop.note_run("w", _fp(_ATTACK), peers,
                                     auto_confirm_runs=3)
        self.assertEqual(trust, "provisional")
        self.assertEqual(detail["consecutive_trusted"], 0)

    def test_note_run_noop_when_trusted(self):
        pop = _pop_store()
        pop.record_baseline("a1", "user-1", _fp(_NORMAL))
        trust, detail = pop.note_run("a1", _fp(_NORMAL), [])
        self.assertEqual(trust, "trusted")
        self.assertTrue(detail["already_trusted"])

    def test_trust_of_unknown_agent(self):
        pop = _pop_store()
        trust, detail = pop.trust_of("ghost")
        self.assertEqual(trust, "trusted")
        self.assertIn("no_baseline", str(detail))

    def test_audit_before_mutation(self):
        pop = _pop_store()

        def bad_audit(evt):
            raise RuntimeError("audit down")

        with self.assertRaises(RuntimeError):
            pop.record_baseline("a1", "user-1", _fp(_NORMAL),
                                audit=bad_audit)
        # The failed audit left the store unchanged.
        self.assertEqual(pop.all_baselines(), [])


class TestCap(unittest.TestCase):
    def _res(self, level):
        return _drift.DriftResult(level, agent_id="a",
                                  baseline_n=5, window_n=8,
                                  reason="evaluated")

    def test_silent_to_warn(self):
        out = _drift.cap_drift_verdict(self._res("silent"))
        self.assertEqual(out.level, "warn")
        self.assertIn("provisional_baseline", out.reason)

    def test_hold_to_warn(self):
        out = _drift.cap_drift_verdict(self._res("hold"))
        self.assertEqual(out.level, "warn")

    def test_warn_stays_warn(self):
        out = _drift.cap_drift_verdict(self._res("warn"))
        self.assertEqual(out.level, "warn")
        self.assertIn("provisional_baseline", out.reason)

    def test_signals_preserved(self):
        sig = _drift.DriftSignal("deny_rate", "strong", {"x": 1}, "e")
        r = _drift.DriftResult("hold", signals=[sig], agent_id="a")
        out = _drift.cap_drift_verdict(r)
        self.assertEqual(len(out.signals), 1)
        self.assertEqual(out.signals[0].kind, "deny_rate")

    def test_type_checked(self):
        with self.assertRaises(TypeError):
            _drift.cap_drift_verdict("nope")


class TestQuantileMedian(unittest.TestCase):
    def test_quantile(self):
        self.assertEqual(_drift._quantile([1, 2, 3, 4], 0.99), 4)
        self.assertEqual(_drift._quantile([1, 2, 3, 4], 0.5), 2)
        self.assertEqual(_drift._quantile([7], 0.99), 7)

    def test_median(self):
        self.assertEqual(_drift._median([1, 2, 3]), 2)
        self.assertEqual(_drift._median([1, 2, 3, 4]), 2.5)


if __name__ == "__main__":
    unittest.main()
