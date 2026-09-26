"""Wave-76 detection: behavioral circuit breakers over the audit stream (2026-09-22).

Load-bearing claims under test (workstreams/architect/DETECTION_DESIGN.md):
- EWMA(alpha=0.3) spikes + CUSUM(k=0.5, h=5.0) drift over per-identity
  baselines keyed to wave-74 identity refs; direction-of-badness
  filtering (improvement never trips)
- measured CUSUM lag: +1.0-sigma sustained shift trips in 11 buckets;
  a 0.4-sigma patient drift never trips (stated boundary, pinned)
- cold start: purpose-group defaults are applied, never trained on;
  bad behavior in the default window trips fast
- the baseline never absorbs drift: training freezes while CUSUM
  suspicion is active or the breaker is not CLOSED; winsorized updates
- anchor downgrade (head_match=False) is a boolean tripwire raising a
  monitor-level latch the agent cannot see coming
- trip -> enforcement wiring: breaker OPEN downgrades allow verdicts on
  high-risk tools to require_approval (flag behavioral_breaker_open),
  fail-closed; human reset -> HALF_OPEN with carried-forward CUSUM;
  named re-baseline for benign level shifts
- the monitor is read-only: trip records are built, not appended; the
  baseline store lives in the operator run dir

Hermetic: temp dirs, synthetic deterministic streams, no network.
Deterministic except wall-clock ts (never asserted on).
"""

import json
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
from gov import log as _log  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402

_BASE_POLICY = Path(_REPO_MAIN, "policies", "default.yaml").read_text()


def _ident(agent_id="a1", role="scout", principal="u1", run_id="r1"):
    return {"agent_id": agent_id, "role": role,
            "principal": principal, "run_id": run_id}


class TestParameters(unittest.TestCase):
    def test_prior_art_constants(self):
        # The commoditized pair, stated as prior art (ACR / Montgomery).
        self.assertEqual(_det.EWMA_ALPHA, 0.3)
        self.assertEqual(_det.SPIKE_Z, 2.5)
        self.assertEqual(_det.CUSUM_K, 0.5)
        self.assertEqual(_det.CUSUM_H, 5.0)
        self.assertEqual(_det.BUCKET_SECONDS, 300)

    def test_signal_set_matches_founder_shape(self):
        self.assertEqual(set(_det.SIGNAL_NAMES), {
            "tool_call_rate", "priv_escalation_attempts",
            "egress_attempts", "denial_rate", "approval_denials",
            "anchor_downgrades"})

    def test_all_rate_signals_are_up_only(self):
        # Direction-of-badness filtering: a symmetric z-score fires on
        # improvement too; every rate signal declares "up".
        for sig, cfg in _det.SIGNAL_CONFIGS.items():
            if sig != "anchor_downgrades":
                self.assertEqual(cfg["direction"], "up", sig)


class TestIdentityKeys(unittest.TestCase):
    def test_agent_identity_key(self):
        ident = AgentIdentity(agent_id="a1", role="scout", run_id="r1",
                              principal="u1")
        self.assertEqual(_det.identity_key_of(ident), "u:u1/a:a1/d:r1")

    def test_token_ref_key_preferred(self):
        entry = {"agent_id": "a1",
                 "identity_token_refs": {
                     "user_token_ref": "u" * 64,
                     "agent_token_ref": "a" * 64,
                     "delegation_token_ref": "d" * 64}}
        key = _det.identity_key_of(entry)
        self.assertTrue(key.startswith("u:" + "u" * 64))

    def test_prov_v2_leaf_tokens(self):
        entry = {"prov": {"delegation": {"hops": [
            {"kind": "principal", "ref": "user:x", "tokens": {
                "tokens_schema": "south-3token/v1",
                "user_token_ref": "u" * 64, "agent_token_ref": "a" * 64,
                "delegation_token_ref": "d1" * 32}},
            {"kind": "agent", "ref": "agent:y", "tokens": {
                "tokens_schema": "south-3token/v1",
                "user_token_ref": "u" * 64, "agent_token_ref": "a" * 64,
                "delegation_token_ref": "d2" * 32}},
        ]}}}
        key = _det.identity_key_of(entry)
        self.assertIn("d2" * 32, key)  # leaf hop's delegation ref


class TestSignalExtraction(unittest.TestCase):
    def test_tool_call_signals(self):
        e = {"event": "tool_call", "tool": "send_email",
             "decision": "allowed_executed"}
        sigs = _det.extract_signals(e)
        self.assertEqual(sigs["tool_call_rate"], 1)
        self.assertEqual(sigs["egress_attempts"], 1)
        self.assertNotIn("denial_rate", sigs)

    def test_denial_and_priv_esc(self):
        e = {"event": "tool_call", "tool": "read_file",
             "decision": "denied", "flag": "delegation_refused"}
        sigs = _det.extract_signals(e)
        self.assertEqual(sigs["denial_rate"], 1)
        self.assertEqual(sigs["priv_escalation_attempts"], 1)

    def test_approval_denial(self):
        e = {"event": "approval_decision", "approved": False}
        self.assertEqual(_det.extract_signals(e)["approval_denials"], 1)
        e2 = {"event": "approval_decision", "approved": True}
        self.assertEqual(_det.extract_signals(e2), {})

    def test_never_trains_on_own_trips(self):
        e = {"event": "detector_trip",
             "prov": {"record_type": "detector_trip"}}
        self.assertEqual(_det.extract_signals(e), {})


class TestEwmaSpike(unittest.TestCase):
    def _trained(self, role="scout", signal="tool_call_rate", level=4,
                 buckets=30):
        mon = _det.BehavioralMonitor()
        key = _ident(role=role)
        for _ in range(buckets):
            mon.observe_bucket(key, {signal: level})
        return mon, key

    def test_spike_trips(self):
        mon, key = self._trained()
        trips = mon.observe_bucket(key, {"tool_call_rate": 40})
        self.assertTrue(any(t["trip_kind"] == "ewma_spike"
                            for t in trips))
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "open")

    def test_improvement_does_not_trip(self):
        # Direction-of-badness: a sudden DROP is not a trip.
        mon, key = self._trained()
        trips = mon.observe_bucket(key, {"tool_call_rate": 0})
        self.assertEqual(trips, [])
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "closed")

    def test_quiet_does_not_trip(self):
        mon, key = self._trained()
        for _ in range(20):
            trips = mon.observe_bucket(key, {"tool_call_rate": 4})
        self.assertEqual(trips, [])
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "closed")


class TestCusumDrift(unittest.TestCase):
    def test_measured_lag(self):
        # The battery shape: scout, 12 cold-start buckets, then a
        # sustained +1.0-sigma shift. Measured lag is 11 buckets.
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        mean, sigma = _det.PURPOSE_GROUP_DEFAULTS["scout"][
            "egress_attempts"]
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        lag = None
        for i in range(1, 100):
            trips = mon.observe_bucket(
                key, {"egress_attempts": mean + sigma})
            if any(t["trip_kind"] == "cusum_drift" for t in trips):
                lag = i
                break
        self.assertEqual(lag, _det.MEASURED_CUSUM_LAG_BUCKETS)
        self.assertEqual(lag, 11)

    def test_ewma_does_not_fire_on_gradual_shape(self):
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        mean, sigma = _det.PURPOSE_GROUP_DEFAULTS["scout"][
            "egress_attempts"]
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        kinds = set()
        for _ in range(8):
            for t in mon.observe_bucket(
                    key, {"egress_attempts": mean + sigma}):
                kinds.add(t["trip_kind"])
        self.assertNotIn("ewma_spike", kinds)

    def test_patient_adversary_never_trips(self):
        # THE STATED BOUNDARY: a 0.4-sigma sustained shift (under the
        # k=0.5-sigma reference) never trips. Pinned, not filed.
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        mean, sigma = _det.PURPOSE_GROUP_DEFAULTS["scout"][
            "egress_attempts"]
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        for _ in range(300):
            trips = mon.observe_bucket(
                key, {"egress_attempts": mean + 0.4 * sigma})
            self.assertEqual(trips, [])
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "closed")

    def test_baseline_does_not_absorb_drift(self):
        # Training freezes while CUSUM suspicion is active: the drift
        # must not become the new normal.
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        for _ in range(12):
            mon.observe_bucket(key, {"egress_attempts": 0})
        for _ in range(10):
            mon.observe_bucket(key, {"egress_attempts": 0.7})
        ik = _det.identity_key_of(key)
        st = mon._signals[ik]["egress_attempts"]
        self.assertAlmostEqual(st.stats.mean, 0.2, places=6)


class TestColdStart(unittest.TestCase):
    def test_cold_start_uses_group_default(self):
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        trips = mon.observe_bucket(key, {"egress_attempts": 30})
        self.assertTrue(trips)
        self.assertIn("purpose-group-default", trips[0]["basis"])
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "open")

    def test_cold_start_never_trains(self):
        # Attack-rate traffic during the default window must not become
        # the baseline: stats stay at the seeded default.
        mon = _det.BehavioralMonitor()
        key = _ident(role="coder")
        for _ in range(11):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        ik = _det.identity_key_of(key)
        st = mon._signals[ik]["tool_call_rate"]
        self.assertEqual(st.stats.n, 0)  # not trained during cold start
        # After the window the baseline seeds FROM THE DEFAULT.
        mon.observe_bucket(key, {"tool_call_rate": 4})
        self.assertEqual(st.stats.n, _det.MIN_TRAINING_BUCKETS)
        self.assertAlmostEqual(
            st.stats.mean,
            _det.PURPOSE_GROUP_DEFAULTS["coder"]["tool_call_rate"][0])


class TestWinsorization(unittest.TestCase):
    def test_flood_is_clipped(self):
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        ik = _det.identity_key_of(key)
        st = mon._signals[ik]["tool_call_rate"]
        before = st.stats.mean
        # A flood inside the suspicion-free window is winsorized: one
        # bucket at 10x moves the mean only to the clip bound.
        mon.observe_bucket(key, {"tool_call_rate": 40})
        # breaker tripped on the spike -> frozen; unfreeze path:
        mon2 = _det.BehavioralMonitor()
        for _ in range(30):
            mon2.observe_bucket(key, {"tool_call_rate": 4})
        st2 = mon2._signals[_det.identity_key_of(key)]["tool_call_rate"]
        st2.train_after(40, frozen=False)
        mean, sigma, _ = st2.reference()
        self.assertLessEqual(st2.stats.mean,
                             before + _det.WINSOR_SIGMAS * sigma + 1)


class TestBreaker(unittest.TestCase):
    def _tripped(self):
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        mon.observe_bucket(key, {"tool_call_rate": 40})
        return mon, key

    def test_open_routes_high_risk_to_queue(self):
        mon, key = self._tripped()
        self.assertEqual(mon.route_action(key, "write_file"), "queue")
        self.assertEqual(mon.route_action(key, "send_email"), "queue")

    def test_open_still_executes_low_risk(self):
        mon, key = self._tripped()
        # Low-risk actions stay observed (the probing channel).
        self.assertEqual(mon.route_action(key, "read_file"), "execute")

    def test_one_trip_record_per_open_transition(self):
        mon, key = self._tripped()
        self.assertEqual(len(mon.pending_trips()), 1)
        # More attack buckets while OPEN: no new trip records.
        for _ in range(5):
            mon.observe_bucket(key, {"tool_call_rate": 40})
        self.assertEqual(mon.pending_trips(), [])

    def test_human_reset_half_open_and_close(self):
        mon, key = self._tripped()
        payload = mon.reset(key, reset_by="op-1")
        self.assertIsNotNone(payload)
        self.assertEqual(payload["reset_by"], "op-1")
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "half_open")
        # Half-open probe quota for high-risk actions.
        self.assertEqual(mon.route_action(key, "write_file"),
                         "half_open_probe")
        # Clean buckets close the breaker; CUSUM was carried forward
        # but the spike is over so quiet buckets accumulate.
        for _ in range(_det.HALF_OPEN_QUIET_BUCKETS):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        self.assertEqual(mon.breaker_state(ik), "closed")

    def test_half_open_retrip_reopens(self):
        mon, key = self._tripped()
        mon.reset(key, reset_by="op-1")
        mon.observe_bucket(key, {"tool_call_rate": 40})
        ik = _det.identity_key_of(key)
        self.assertEqual(mon.breaker_state(ik), "open")
        br = mon._breaker(ik)
        self.assertGreaterEqual(br.consecutive_opens, 1)

    def test_reset_when_closed_is_noop(self):
        mon = _det.BehavioralMonitor()
        key = _ident()
        self.assertIsNone(mon.reset(key, reset_by="op-1"))

    def test_rebaseline_adopts_new_level(self):
        mon, key = self._tripped()
        payload = mon.rebaseline(key, reset_by="op-1",
                                 signal="tool_call_rate")
        self.assertIn("tool_call_rate", payload["signals"])
        moved = payload["signals"]["tool_call_rate"]
        self.assertNotEqual(moved["old_mean"], moved["new_mean"])
        ik = _det.identity_key_of(key)
        st = mon._signals[ik]["tool_call_rate"]
        self.assertEqual(st.cusum.sh, 0.0)


class TestAnchorTripwire(unittest.TestCase):
    def test_downgrade_raises_monitor_latch(self):
        mon = _det.BehavioralMonitor()
        trip = mon.ingest_anchor_audit([{
            "epoch_id": "e1",
            "checks": {"chain_ok": True, "head_match": False}}])
        self.assertIsNotNone(trip)
        self.assertEqual(trip["trip_kind"], "boolean_tripwire")
        self.assertEqual(trip["identity_key"], "*")
        # The latch opens EVERY breaker's state: the log the baselines
        # were built on is suspect. High-risk actions queue; low-risk
        # actions still execute under observation (OPEN semantics).
        self.assertEqual(mon.breaker_state("anyone"), "open")
        self.assertEqual(mon.route_action(_ident(), "write_file"),
                         "queue")
        self.assertEqual(mon.route_action(_ident(), "read_file"),
                         "execute")

    def test_clean_audit_does_not_trip(self):
        mon = _det.BehavioralMonitor()
        trip = mon.ingest_anchor_audit([{
            "epoch_id": "e1",
            "checks": {"chain_ok": True, "head_match": True}}])
        self.assertIsNone(trip)
        self.assertEqual(mon.breaker_state("anyone"), "closed")

    def test_broken_chain_is_not_a_downgrade(self):
        # chain_ok False = tampering the chain answers itself; the
        # downgrade tripwire is specifically verified-in-chain BUT
        # anchor-mismatched (the key-holder shape).
        mon = _det.BehavioralMonitor()
        trip = mon.ingest_anchor_audit([{
            "epoch_id": "e1",
            "checks": {"chain_ok": False, "head_match": False}}])
        self.assertIsNone(trip)

    def test_operator_clears_latch(self):
        mon = _det.BehavioralMonitor()
        mon.ingest_anchor_audit([{
            "epoch_id": "e1",
            "checks": {"chain_ok": True, "head_match": False}}])
        self.assertTrue(mon.clear_anchor_alarm(reset_by="op-1"))
        self.assertEqual(mon.breaker_state("anyone"), "closed")
        self.assertFalse(mon.clear_anchor_alarm(reset_by="op-1"))


class TestTripRecord(unittest.TestCase):
    def test_build_and_validate(self):
        trip = {"identity_key": "u:x/a:y/d:z", "signal": "egress_attempts",
                "trip_kind": "cusum_drift", "observed": "0.7",
                "threshold": "2.5", "baseline_mean": "0.2",
                "baseline_sigma": "0.5", "basis": "per-identity",
                "buckets_seen": 30, "window_buckets": 30}
        rec = _det.build_detector_trip(
            trip, session_id="sess-1",
            session_open="2026-09-22T00:00:00+00:00")
        verdict = _prov.validate_provenance(rec)
        self.assertTrue(verdict["ok"], verdict["errors"])

    def test_append_through_operator_path(self):
        run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
        log = ActionLog(run_dir / "actions.jsonl")
        trip = {"identity_key": "u:x/a:y/d:z", "signal": "tool_call_rate",
                "trip_kind": "ewma_spike", "observed": "40",
                "threshold": "9.0", "baseline_mean": "4.0",
                "baseline_sigma": "2.0", "basis": "per-identity",
                "buckets_seen": 30, "window_buckets": 30}
        rec = _det.build_detector_trip(
            trip, session_id="sess-1",
            session_open="2026-09-22T00:00:00+00:00")
        _prov.append_provenance(log, rec)
        entries = _log.read_entries(run_dir / "actions.jsonl")
        self.assertEqual(
            entries[-1]["prov"]["record_type"], "detector_trip")

    def test_export_boundary_states_slow_boil(self):
        mon = _det.BehavioralMonitor()
        b = mon.export_boundary()
        self.assertIn("never trips", b["slow_boil"])
        self.assertEqual(
            b["signals"]["egress_attempts"]["ewma_alpha"], 0.3)
        self.assertEqual(b["measured_cusum_lag_buckets"], 11)


class TestPersistence(unittest.TestCase):
    def test_save_load_roundtrip(self):
        run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
        mon = _det.BehavioralMonitor(run_dir=run_dir)
        key = _ident(role="scout")
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        mon.observe_bucket(key, {"tool_call_rate": 40})
        path = mon.save_baselines()
        self.assertTrue(Path(path).exists())
        # Baselines live in the OPERATOR run dir, never agent space.
        self.assertIn("detection", path)

        mon2 = _det.BehavioralMonitor(run_dir=run_dir)
        self.assertTrue(mon2.load_baselines())
        ik = _det.identity_key_of(key)
        # A persisted OPEN restores as OPEN: restarts never silently
        # close a tripped breaker.
        self.assertEqual(mon2.breaker_state(ik), "open")
        st = mon2._signals[ik]["tool_call_rate"]
        self.assertGreater(st.stats.n, 0)

    def test_no_run_dir_is_memory_only(self):
        mon = _det.BehavioralMonitor()
        self.assertIsNone(mon.save_baselines())
        self.assertFalse(mon.load_baselines())


class TestRetentionWindow(unittest.TestCase):
    def test_window_evicts_oldest_values(self):
        st = _det.StreamingStats()
        st.seed_prior(12, 0.0, 1.0)
        for i in range(_det.WINDOW_BUCKETS + 10):
            st.update(float(i))
        self.assertEqual(st.retained, _det.WINDOW_BUCKETS)
        # The 10 oldest trained values (0..9) evicted: the window's
        # own mean is over 10..(WINDOW+9).
        vals = list(st.values)
        self.assertEqual(vals[0], 10.0)
        self.assertEqual(len(vals), _det.WINDOW_BUCKETS)

    def test_eviction_recompute_matches_exact(self):
        # Recompute-on-eviction must equal a from-scratch Welford over
        # prior + retained values (no numerical drift from removal).
        st = _det.StreamingStats()
        st.seed_prior(12, 4.0, 0.5)
        xs = [4.0 + (i % 7) * 0.1 for i in
              range(_det.WINDOW_BUCKETS + 50)]
        for x in xs:
            st.update(x)
        ref = _det.StreamingStats()
        ref.seed_prior(12, 4.0, 0.5)
        for x in xs[-_det.WINDOW_BUCKETS:]:
            ref.values.append(x)
        ref._recompute()
        self.assertAlmostEqual(st.mean, ref.mean, places=9)
        self.assertAlmostEqual(st.m2, ref.m2, places=6)
        self.assertEqual(st.n, ref.n)

    def test_virtual_prior_survives_eviction(self):
        st = _det.StreamingStats()
        st.seed_prior(12, 4.0, 0.5)
        for _ in range(_det.WINDOW_BUCKETS + 5):
            st.update(4.0)
        # The conservative default never washes out entirely: n still
        # counts the 12 virtual observations on top of the window.
        self.assertEqual(st.n, 12 + _det.WINDOW_BUCKETS)

    def test_window_persists_across_save_load(self):
        run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
        mon = _det.BehavioralMonitor(run_dir=run_dir)
        key = _ident(role="scout")
        for i in range(40):
            mon.observe_bucket(key, {"tool_call_rate": 4 + (i % 3)})
        mon.save_baselines()
        mon2 = _det.BehavioralMonitor(run_dir=run_dir)
        self.assertTrue(mon2.load_baselines())
        ik = _det.identity_key_of(key)
        a = mon._signals[ik]["tool_call_rate"].stats
        b = mon2._signals[ik]["tool_call_rate"].stats
        self.assertEqual(b.retained, a.retained)
        self.assertAlmostEqual(b.mean, a.mean, places=9)
        # The restored monitor keeps detecting on the restored window.
        trips = mon2.observe_bucket(key, {"tool_call_rate": 400})
        self.assertTrue(trips)

    def test_rebaseline_drops_old_window(self):
        mon = _det.BehavioralMonitor()
        key = _ident(role="scout")
        for _ in range(30):
            mon.observe_bucket(key, {"tool_call_rate": 4})
        mon.observe_bucket(key, {"tool_call_rate": 40})
        ik = _det.identity_key_of(key)
        st = mon._signals[ik]["tool_call_rate"]
        retained_before = st.stats.retained
        self.assertGreater(retained_before, 0)
        payload = mon.rebaseline(key, reset_by="op-1",
                                 signal="tool_call_rate")
        self.assertEqual(st.stats.retained, 0)
        # The new level is the anchor; the old traffic is gone.
        self.assertAlmostEqual(
            st.stats.mean,
            payload["signals"]["tool_call_rate"]["new_mean"], places=9)


class TestExecutorWiring(unittest.TestCase):
    def _executor(self, monitor):
        run_dir = Path(tempfile.mkdtemp(prefix="govred-"))
        policy = PolicyEngine(str(Path(
            _REPO_MAIN, "policies", "default.yaml")))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, approvals,
                          ledger_path=run_dir / "egress_ledger.jsonl",
                          detection_monitor=monitor,
                          # Wave-85: the detection monitor is the subject
                          # here; the governed core is not installed, so
                          # the bypass is declared, not silent.
                          ungoverned_ack=(
                              "detection test: the monitor is the "
                              "subject; governed core not installed"))
        return run_dir, ex

    def test_open_breaker_queues_high_risk(self):
        monitor = _det.BehavioralMonitor()
        run_dir, ex = self._executor(monitor)
        ident = ex.mint_identity("a1", "coder", "u1")
        # Trip the breaker for this identity via the monitor.
        key = {"agent_id": "a1", "principal": "u1",
               "run_id": run_dir.name, "role": "coder"}
        for _ in range(30):
            monitor.observe_bucket(key, {"tool_call_rate": 10})
        monitor.observe_bucket(key, {"tool_call_rate": 100})
        self.assertEqual(monitor.breaker_state(
            _det.identity_key_of(ident)), "open")
        # A high-risk call that policy would allow (inside the sandbox)
        # now queues with the breaker flag.
        res = ex.call(ident, "write_file",
                      path=str(run_dir / "sandbox" / "x.txt"),
                      content="hello")
        self.assertEqual(res["status"], "queued")
        rec = ex.approvals.get(res["approval_id"])
        self.assertEqual(rec["policy_flag"], "behavioral_breaker_open")
        self.assertEqual(rec["policy_id"], "detection-breaker")

    def test_low_risk_still_executes_while_open(self):
        monitor = _det.BehavioralMonitor()
        run_dir, ex = self._executor(monitor)
        ident = ex.mint_identity("a1", "coder", "u1")
        key = {"agent_id": "a1", "principal": "u1",
               "run_id": run_dir.name, "role": "coder"}
        for _ in range(30):
            monitor.observe_bucket(key, {"tool_call_rate": 10})
        monitor.observe_bucket(key, {"tool_call_rate": 100})
        # Wave-120 (F-RA3): the read must target the sandbox -- an
        # outside-sandbox path is now quarantined, not executed.
        probe = run_dir / "sandbox" / "x.txt"
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_text("x", encoding="utf-8")
        res = ex.call(ident, "read_file", path=str(probe))
        self.assertEqual(res["status"], "executed")

    def test_no_monitor_zero_behavior_change(self):
        run_dir, ex = self._executor(None)
        ident = ex.mint_identity("a1", "coder", "u1")
        res = ex.call(ident, "write_file", path="/tmp/x.txt",
                      content="hello")
        # Default policy requires approval for write_file anyway; the
        # point is the flag is NOT the breaker flag.
        rec = ex.approvals.get(res["approval_id"])
        self.assertNotEqual(rec["policy_flag"],
                            "behavioral_breaker_open")

    def test_monitor_error_fails_closed(self):
        class _Boom:
            def route_action(self, identity, tool):
                raise RuntimeError("monitor down")
        run_dir, ex = self._executor(_Boom())
        ident = ex.mint_identity("a1", "coder", "u1")
        res = ex.call(ident, "write_file",
                      path=str(run_dir / "sandbox" / "x.txt"),
                      content="hello")
        self.assertEqual(res["status"], "queued")
        rec = ex.approvals.get(res["approval_id"])
        self.assertEqual(rec["policy_flag"], "behavioral_breaker_open")


if __name__ == "__main__":
    unittest.main()
