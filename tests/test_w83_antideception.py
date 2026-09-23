"""Wave-83 detection anti-deception: reset-laundering fix (F129),
evidence-export surface, boundary pins (2026-09-23).

Load-bearing claims under test
(workstreams/architect/DETECTION_ANTIDECEPTION_DESIGN.md):
- F129: the recorded trip kind is adversary-influenced -- a deliberate
  spike on one signal shadows an in-progress drift on another -- so it
  must not gate CUSUM carry-forward. Every reset carries sh forward
  capped at h*sigma; the drift clock is never restarted by a reset.
- Wave-76 phantom-trip fix preserved: half-open still closes after a
  huge spike trip (a capped sh decays below the trip line on quiet
  buckets); a continuing spike re-trips on fresh evidence; EWMA is
  still reseeded to the baseline mean; the reset stays named+chained.
- Evidence export: ``BehavioralMonitor.export_snapshot`` renders
  per-identity baseline windows, thresholds, current EWMA/CUSUM
  levels, and breaker state, plus the explicit slow-boil boundary;
  ``provenance_export(..., detection_snapshot=...)`` renders the
  ``detection`` section; without a snapshot the section is honest
  absence (trip history still from the chained ``detector_trip``
  records; baselines are never invented).
- Boundaries re-pinned (stated, not filed): sub-k sustained drift
  never trips; no cross-signal aggregate; attempts counted, not bytes.

Hermetic: temp dirs, dev key via tests/__init__ opt-in, no network.
Deterministic (no randomness anywhere).
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import detection as _det  # noqa: E402
from gov import provenance as _prov  # noqa: E402


def _make_report():
    """Load demo/make_report.py by path (demo/ is not a package)."""
    path = Path(_REPO_MAIN, "demo", "make_report.py")
    spec = importlib.util.spec_from_file_location("make_report", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ident(agent_id="a1", role="scout", principal="u1", run_id="r1"):
    return {"agent_id": agent_id, "role": role,
            "principal": principal, "run_id": run_id}


def _spike_shadowed(mon, key):
    """F129 recipe: 12 quiet buckets, 6 buckets of +1-sigma-ish egress
    drift (sh=1.50, under h), then a deliberate tool_call_rate spike.
    Returns (identity_key, sh_before_spike)."""
    for _ in range(12):
        mon.observe_bucket(key, {"tool_call_rate": 4,
                                 "egress_attempts": 0})
    for _ in range(6):
        mon.observe_bucket(key, {"tool_call_rate": 4,
                                 "egress_attempts": 0.7})
    ik = _det.identity_key_of(key)
    sh_before = mon._signals[ik]["egress_attempts"].cusum.sh
    assert abs(sh_before - 1.5) < 1e-9, sh_before
    trips = mon.observe_bucket(key, {"tool_call_rate": 40,
                                     "egress_attempts": 0.7})
    assert trips, "setup: the deliberate spike did not trip"
    recorded = mon.pending_trips()
    assert recorded and recorded[0]["trip_kind"] == "ewma_spike", \
        "setup: recorded trip was not the spike: %r" % (
            recorded[0]["trip_kind"] if recorded else None)
    return ik, sh_before


class TestResetCarryForward(unittest.TestCase):
    """F129 regression: a spike on signal A must not let a reset wipe
    the CUSUM suspicion on signal B."""

    def test_spike_shadowed_reset_carries_capped_cusum(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        ik, sh_before = _spike_shadowed(mon, key)
        payload = mon.reset(key, reset_by="op-1")
        self.assertIsNotNone(payload, "human reset failed")
        est = mon._signals[ik]["egress_attempts"]
        mean, sigma, _ = est.reference()
        sigma = max(sigma, _det.SIGMA_FLOOR)
        cap = _det.CUSUM_H * sigma
        # Carried forward, not zeroed; never above the decision
        # interval (the wave-76 phantom-trip fix lives in the cap).
        # Note: the spike bucket itself added one more drift
        # increment before the reset (sh 1.50 -> 1.75).
        self.assertGreater(est.cusum.sh, 0.0)
        self.assertLessEqual(est.cusum.sh, cap)
        self.assertAlmostEqual(est.cusum.sh, 1.75)
        # The payload stays named and states the carry explicitly.
        self.assertEqual(payload["prior_trip_kind"], "ewma_spike")
        self.assertTrue(payload["cusum_carried"])
        self.assertEqual(payload["cusum_cap_sigmas"], _det.CUSUM_H)
        self.assertEqual(payload["reset_by"], "op-1")
        self.assertEqual(payload["new_state"], "half_open")
        # The drift clock survived: continued drift re-trips fast.
        lag = None
        for i in range(1, 60):
            trips = mon.observe_bucket(key, {"tool_call_rate": 4,
                                             "egress_attempts": 0.7})
            if any(t["trip_kind"] == "cusum_drift"
                   and t["signal"] == "egress_attempts" for t in trips):
                lag = i
                break
        self.assertIsNotNone(
            lag, "post-reset drift NEVER re-tripped: fully laundered")
        self.assertLessEqual(lag, 5)

    def test_plain_drift_trip_reset_still_carries(self):
        # The pre-F129 correct case: reset after a genuine drift trip
        # keeps carrying (now uniformly, not conditionally). Recipe is
        # the wave-76 measured-lag shape: 12 quiet buckets, then a
        # +1-sigma drift that CUSUM trips at bucket 11 (EWMA stays
        # under its line on this gradual shape by design).
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        lag = None
        for i in range(1, 60):
            trips = mon.observe_bucket(key, {"egress_attempts": 0.7})
            if any(t["trip_kind"] == "cusum_drift" for t in trips):
                lag = i
                break
        self.assertIsNotNone(lag, "setup: +1-sigma drift never tripped")
        ik = _det.identity_key_of(key)
        sh_before = mon._signals[ik]["egress_attempts"].cusum.sh
        payload = mon.reset(key, reset_by="op-1")
        sh_after = mon._signals[ik]["egress_attempts"].cusum.sh
        self.assertEqual(payload["prior_trip_kind"], "cusum_drift")
        self.assertGreater(sh_after, 0.0)
        self.assertLessEqual(sh_after, sh_before)
        # Continued drift re-trips fast: the clock was not restarted.
        lag2 = None
        for i in range(1, 60):
            trips = mon.observe_bucket(key, {"egress_attempts": 0.7})
            if trips:
                lag2 = i
                break
        self.assertIsNotNone(lag2)
        self.assertLessEqual(lag2, 2)

    def test_half_open_closes_after_huge_spike(self):
        # The wave-76 phantom-trip fix must survive the cap change: a
        # capped sh decays below the trip line on quiet buckets, so
        # half-open still closes; it does not re-trip on nothing.
        mon = _det.BehavioralMonitor()
        key = _ident(agent_id="a2")
        ik = _det.identity_key_of(key)
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        mon.observe_bucket(key, {"tool_call_rate": 40})
        self.assertEqual(mon.breaker_state(ik), "open")
        mon.reset(key, reset_by="op-2")
        st = mon._signals[ik]["tool_call_rate"]
        _, sigma, _ = st.reference()
        sigma = max(sigma, _det.SIGMA_FLOOR)
        self.assertLessEqual(st.cusum.sh, _det.CUSUM_H * sigma)
        for _ in range(20):
            trips = mon.observe_bucket(key, {"tool_call_rate": 4})
            self.assertFalse(
                [t for t in trips if t["signal"] == "tool_call_rate"
                 and t["trip_kind"] == "cusum_drift"],
                "phantom re-trip on quiet traffic after a spike reset")
        self.assertEqual(mon.breaker_state(ik), "closed")

    def test_continuing_spike_still_retrips(self):
        # The cap must not buy forgiveness for an ongoing spike: fresh
        # evidence above the limit re-trips from half-open.
        mon = _det.BehavioralMonitor()
        key = _ident(agent_id="a3")
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        mon.observe_bucket(key, {"tool_call_rate": 40})
        mon.reset(key, reset_by="op-3")
        trips = mon.observe_bucket(key, {"tool_call_rate": 40})
        self.assertTrue(
            any(t["trip_kind"] == "ewma_spike" for t in trips),
            "a continuing spike did not re-trip after reset")

    def test_ewma_reseeded_to_baseline_mean(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        _spike_shadowed(mon, key)
        mon.reset(key, reset_by="op-1")
        ik = _det.identity_key_of(key)
        for sig, st in mon._signals[ik].items():
            mean, _, _ = st.reference()
            self.assertEqual(st.ewma.z, mean, sig)

    def test_reset_returns_none_when_not_open(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        mon.observe_bucket(key, {"tool_call_rate": 4})
        self.assertIsNone(mon.reset(key, reset_by="op-1"))


class TestExportSnapshot(unittest.TestCase):
    def test_snapshot_fields(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(30):
            mon.observe_bucket(key, {"egress_attempts": 0})
        mon.observe_bucket(key, {"egress_attempts": 30})
        ik = _det.identity_key_of(key)
        snap = mon.export_snapshot()
        self.assertIn(ik, snap["identities"])
        row = snap["identities"][ik]
        self.assertEqual(row["role"], "scout")
        self.assertEqual(row["breaker_state"], "open")
        sig = row["signals"]["egress_attempts"]
        for field in ("basis", "window_buckets", "buckets_seen",
                      "baseline_mean", "baseline_sigma",
                      "spike_threshold", "spike_z", "ewma_alpha",
                      "cusum_threshold", "cusum_k_sigmas",
                      "cusum_h_sigmas", "ewma_level", "cusum_sh",
                      "baseline_training"):
            self.assertIn(field, sig, field)
        self.assertEqual(sig["cusum_k_sigmas"], 0.5)
        self.assertEqual(sig["cusum_h_sigmas"], 5.0)
        params = snap["parameters"]
        self.assertEqual(params["measured_cusum_lag_buckets"], 11)
        slow = snap["slow_boil_boundary"]
        self.assertIn("never trips", slow["statement"])
        claims = " ".join(m["claim"] for m in slow["measurements"])
        self.assertIn("0.4-sigma", claims)
        self.assertIn("k=0.5", slow["statement"])

    def test_snapshot_empty_monitor(self):
        snap = _det.BehavioralMonitor().export_snapshot()
        self.assertEqual(snap["identities"], {})

    def test_snapshot_deterministic(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(30):
            mon.observe_bucket(key, {"egress_attempts": 0})
        a = mon.export_snapshot()
        b = mon.export_snapshot()
        self.assertEqual(a["identities"], b["identities"])

    def test_export_boundary_includes_slow_boil_boundary(self):
        b = _det.BehavioralMonitor().export_boundary()
        # The wave-76 sentence stays (back-compat).
        self.assertIn("never trips", b["slow_boil"])
        slow = b["slow_boil_boundary"]
        self.assertTrue(len(slow["measurements"]) >= 5)
        for m in slow["measurements"]:
            self.assertIn("id", m)
            self.assertIn("claim", m)


class TestProvenanceDetectionSection(unittest.TestCase):
    def _trip_entry(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(30):
            mon.observe_bucket(key, {"egress_attempts": 0})
        mon.observe_bucket(key, {"egress_attempts": 30})
        trip = mon.pending_trips()[0]
        entry = _det.build_detector_trip(
            trip, session_id="s1",
            session_open="2026-09-23T00:00:00+00:00")
        entry["seq"] = 1
        entry["epoch_id"] = "e1"
        return mon, entry

    def test_detection_section_with_snapshot(self):
        mon, entry = self._trip_entry()
        snap = mon.export_snapshot()
        exp = _prov.provenance_export(
            [entry], {"epochs": []}, detection_snapshot=snap)
        det = exp.get("detection")
        self.assertIsInstance(det, dict)
        ik = _det.identity_key_of(_ident())
        self.assertIn(ik, det["identities"])
        row = det["identities"][ik]
        self.assertEqual(row["breaker_state"], "open")
        self.assertIn("egress_attempts", row["signals"])
        hist = det["trip_history"]
        self.assertTrue(any(h["signal"] == "egress_attempts"
                            for h in hist))
        self.assertEqual(hist[0]["trip_kind"], "ewma_spike")
        self.assertIn("never trips",
                      det["slow_boil_boundary"]["statement"])

    def test_detection_section_absent_snapshot_is_honest(self):
        _, entry = self._trip_entry()
        exp = _prov.provenance_export([entry], {"epochs": []})
        det = exp.get("detection")
        self.assertIsInstance(det, dict)
        # Baselines are never invented...
        self.assertIsNone(det["identities"])
        self.assertIn("not included", det["note"])
        self.assertIsNone(det["parameters"])
        # ...but the chained trip history still renders from the log.
        self.assertTrue(det["trip_history"])
        self.assertEqual(det["trip_history"][0]["signal"],
                         "egress_attempts")
        # And the boundary statement is still available (module
        # constant, not per-run state).
        self.assertIn("never trips",
                      det["slow_boil_boundary"]["statement"])

    def test_legacy_callers_unaffected(self):
        # Two-arg call (pre-wave-83) keeps working and keeps the
        # section honest.
        _, entry = self._trip_entry()
        exp = _prov.provenance_export([entry], {"epochs": []})
        self.assertIn("detection", exp)


class TestDetectionStateText(unittest.TestCase):
    def test_renders_identity_rows_trip_history_and_boundary(self):
        make_report = _make_report()
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(30):
            mon.observe_bucket(key, {"egress_attempts": 0})
        mon.observe_bucket(key, {"egress_attempts": 30})
        trip = mon.pending_trips()[0]
        entry = _det.build_detector_trip(
            trip, session_id="s1",
            session_open="2026-09-23T00:00:00+00:00")
        entry["seq"] = 1
        entry["epoch_id"] = "e1"
        exp = _prov.provenance_export(
            [entry], {"epochs": []},
            detection_snapshot=mon.export_snapshot())
        text = make_report.provenance_export_text(exp)
        ik = _det.identity_key_of(key)
        self.assertIn(ik, text)
        self.assertIn("egress_attempts", text)
        self.assertIn("breaker open", text)
        self.assertIn("ewma_spike", text)
        self.assertIn("Slow-boil boundary", text)
        self.assertIn("0.4-sigma", text)

    def test_renders_honest_absence(self):
        make_report = _make_report()
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(30):
            mon.observe_bucket(key, {"egress_attempts": 0})
        mon.observe_bucket(key, {"egress_attempts": 30})
        trip = mon.pending_trips()[0]
        entry = _det.build_detector_trip(
            trip, session_id="s1",
            session_open="2026-09-23T00:00:00+00:00")
        entry["seq"] = 1
        entry["epoch_id"] = "e1"
        exp = _prov.provenance_export([entry], {"epochs": []})
        text = make_report.detection_state_text(exp["detection"])
        self.assertIn("not included in this rendering", text)
        self.assertIn("ewma_spike", text)


class TestBoundaryPins(unittest.TestCase):
    """Stated boundaries, re-pinned (not findings)."""

    def test_sub_k_sustained_drift_never_trips(self):
        # 0.4-sigma drift: CUSUM sh stays exactly 0; zero trips.
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        for _ in range(80):
            trips = mon.observe_bucket(key, {"egress_attempts": 0.4})
            self.assertFalse(trips)
        ik = _det.identity_key_of(key)
        est = mon._signals[ik]["egress_attempts"]
        self.assertEqual(est.cusum.sh, 0.0)
        self.assertEqual(mon.breaker_state(ik), "closed")

    def test_no_cross_signal_aggregate(self):
        # +0.4 sigma on each of the 5 count signals: the aggregate is
        # invisible per signal; 60 buckets, zero trips.
        spread = {
            "tool_call_rate": (4.0, 2.0),
            "priv_escalation_attempts": (0.0, 0.5),
            "egress_attempts": (0.2, 0.5),
            "denial_rate": (0.3, 0.6),
            "approval_denials": (0.1, 0.5),
        }
        mon = _det.BehavioralMonitor()
        key = _ident()
        zero = {s: 0.0 for s in spread}
        for _ in range(12):
            mon.observe_bucket(key, dict(zero))
        vals = {s: m + 0.4 * sg for s, (m, sg) in spread.items()}
        for _ in range(60):
            trips = mon.observe_bucket(key, dict(vals))
            self.assertFalse(trips)

    def test_attempts_counted_not_bytes(self):
        # 1 attempt every 4 buckets (after the 12-bucket quiet lead-in):
        # the signal counts attempts; each attempt could carry
        # arbitrary bytes and the layer would not see it. 60 buckets,
        # zero trips.
        mon = _det.BehavioralMonitor()
        key = _ident()
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        for i in range(60):
            trips = mon.observe_bucket(
                key, {"egress_attempts": 1 if i % 4 == 0 else 0})
            self.assertFalse(trips)


if __name__ == "__main__":
    unittest.main()
