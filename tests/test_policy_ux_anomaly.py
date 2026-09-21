"""POLICY UX tests: queue-anomaly detection (F4 — approval fatigue).

An attacker floods the approval queue with low-risk requests to hide one
malicious request (OWASP ASI09). These tests pin the advisory detection
layer in gov/approvals.py:

* fatigue bursts: >= 5 pending items from one agent inside 10 minutes,
  across tools (the shape a per-(agent,tool) flood threshold misses);
* rate spikes: arrivals in the trailing window vs the run's baseline;
* unusual tool mix: a tool dominating pending but rare in run history;
* the signal is ADVISORY: it escalates risk scores (+15, never down),
  shows a fatigue warning on the queue listing, and forces per-item
  confirmation in batch approve — it never auto-approves.

Timestamps are crafted explicitly and ``now`` is passed in, so every
test is deterministic.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from harness import make_run  # shared sibling harness (tests/harness.py)
from gov.approvals import main as approve_main


def _queue_item(queue, agent_id, tool, ts=None, decided=False):
    """Queue one pending item directly; optionally backdate its ts."""
    action = {
        "tool": tool,
        "args": {"path": "notes.txt"},
        "identity": {"agent_id": agent_id, "role": "support",
                     "run_id": queue.run_dir.name,
                     "principal": "customer-org"},
        "redactions": [],
        "agent_justification": None,
    }
    decision = SimpleNamespace(policy_id="test-policy", reason="test")
    aid = queue.queue(
        action, decision, provenance="agent_direct",
        policy_context={"path_outside_sandbox": False,
                        "domain_allowlisted": True,
                        "carries_read_content": False,
                        "source_untrusted": False,
                        "counters": {}})
    if ts is not None:
        queue._rewrite(lambda rs: [
            dict(r, ts=ts) if r["id"] == aid else r for r in rs])
    if decided:
        queue.decide(aid, True, "test decision",
                     decided_by="human-operator")
    return aid


class AnomalyTestBase(unittest.TestCase):
    def setUp(self):
        self.run = make_run()
        self.queue = self.run["approvals"]
        self.now = datetime.now(timezone.utc)

    def ts(self, minutes_ago):
        return (self.now - timedelta(minutes=minutes_ago)).isoformat()

    def anomalies(self, now=None):
        return self.queue.queue_anomalies(now=now or self.now)

    def types(self, now=None):
        return {a["type"] for a in self.anomalies(now)}


class TestFatigueBurst(AnomalyTestBase):
    def _burst(self, agent="burst-agent", n=6):
        # Spread across tools so the per-(agent,tool) flood detector does
        # NOT fire: this is the anomaly layer's own shape.
        tools = ["read_file", "log_note", "sleep"]
        return [_queue_item(self.queue, agent, tools[i % 3],
                            ts=self.ts(i))
                for i in range(n)]

    def test_burst_detected(self):
        ids = set(self._burst())
        anoms = [a for a in self.anomalies()
                 if a["type"] == "fatigue_burst"]
        self.assertEqual(len(anoms), 1)
        self.assertEqual(set(anoms[0]["items"]), ids)
        self.assertIn("burst-agent", anoms[0]["summary"])
        self.assertEqual(anoms[0]["detail"]["count"], 6)

    def test_no_burst_below_threshold(self):
        self._burst(n=4)
        self.assertNotIn("fatigue_burst", self.types())

    def test_burst_counts_pending_only(self):
        ids = self._burst(n=6)
        # Decide two: 4 pending remain, below the burst threshold.
        self.queue.decide(ids[0], True, "ok", decided_by="human-operator")
        self.queue.decide(ids[1], True, "ok", decided_by="human-operator")
        self.assertNotIn("fatigue_burst", self.types())

    def test_burst_spread_across_agents_is_not_a_burst(self):
        for i in range(3):
            _queue_item(self.queue, "agent-a", "read_file", ts=self.ts(i))
            _queue_item(self.queue, "agent-b", "read_file", ts=self.ts(i))
        self.assertNotIn("fatigue_burst", self.types())


class TestRateSpike(AnomalyTestBase):
    def test_rate_spike_detected(self):
        # Quiet history: one arrival in each of three prior windows.
        for m in (35, 48, 55):
            _queue_item(self.queue, "hist-agent", "read_file",
                        ts=self.ts(m), decided=True)
        # Sudden burst: five arrivals in the trailing window.
        for i in range(5):
            _queue_item(self.queue, "spike-agent", "read_file",
                        ts=self.ts(i))
        anoms = [a for a in self.anomalies()
                 if a["type"] == "rate_spike"]
        self.assertEqual(len(anoms), 1)
        self.assertEqual(anoms[0]["detail"]["current"], 5)
        self.assertIn("spiked", anoms[0]["summary"])

    def test_no_spike_without_history(self):
        # Arrivals only in the current window: no baseline, no spike.
        for i in range(5):
            _queue_item(self.queue, "new-agent", "read_file",
                        ts=self.ts(i))
        self.assertNotIn("rate_spike", self.types())

    def test_steady_rate_is_not_a_spike(self):
        for m in (5, 15, 25, 35, 45, 55):
            _queue_item(self.queue, "steady-agent", "read_file",
                        ts=self.ts(m))
        self.assertNotIn("rate_spike", self.types())


class TestToolMix(AnomalyTestBase):
    def test_unusual_tool_mix_detected(self):
        # History is all read_file; the pending queue is dominated by
        # api_call — the odd tool out (e.g. the hidden malicious send).
        for i in range(16):
            _queue_item(self.queue, "hist-agent", "read_file",
                        ts=self.ts(60 + i), decided=True)
        api_ids = [_queue_item(self.queue, "mix-agent", "api_call",
                               ts=self.ts(i)) for i in range(4)]
        _queue_item(self.queue, "mix-agent", "read_file", ts=self.ts(0))
        anoms = [a for a in self.anomalies()
                 if a["type"] == "unusual_tool_mix"]
        self.assertEqual(len(anoms), 1)
        self.assertEqual(set(anoms[0]["items"]), set(api_ids))
        self.assertIn("api_call", anoms[0]["summary"])

    def test_no_history_means_no_mix_signal(self):
        # Nothing to compare against: a uniform pending queue is not
        # "unusual".
        for i in range(4):
            _queue_item(self.queue, "mix-agent", "api_call",
                        ts=self.ts(i))
        self.assertNotIn("unusual_tool_mix", self.types())

    def test_common_tool_is_not_unusual(self):
        for i in range(6):
            _queue_item(self.queue, "hist-agent", "read_file",
                        ts=self.ts(60 + i), decided=True)
        for i in range(4):
            _queue_item(self.queue, "mix-agent", "read_file",
                        ts=self.ts(i))
        self.assertNotIn("unusual_tool_mix", self.types())


class TestAdvisoryEscalation(AnomalyTestBase):
    def _burst_and_loner(self):
        tools = ["read_file", "log_note", "sleep"]
        burst_ids = [_queue_item(self.queue, "burst-agent", tools[i % 3],
                                 ts=self.ts(i)) for i in range(6)]
        loner_id = _queue_item(self.queue, "loner-agent", "read_file",
                               ts=self.ts(0))
        return burst_ids, loner_id

    def test_anomaly_escalates_risk_scores(self):
        from gov.approvals import _score_factors
        burst_ids, _ = self._burst_and_loner()
        records = self.queue.all()
        for i in burst_ids:
            r = self.queue.get(i)
            plain, _ = _score_factors(r, records)  # no anomaly bump
            self.assertEqual(self.queue.risk(r), plain + 15)
        detail = self.queue.risk_detail(self.queue.get(burst_ids[0]))
        self.assertTrue(any("queue-anomaly cluster" in f
                            for f in detail["factors"]))

    def test_anomaly_never_auto_approves(self):
        burst_ids, loner_id = self._burst_and_loner()
        cfg = {"enabled": True, "max_risk_score": 20}
        # Without the anomaly bump these items (scores 10-15) would clear
        # the cap; the advisory escalation must hold every one of them
        # back.
        for i in burst_ids:
            self.assertIsNone(self.queue.maybe_auto_approve(i, cfg),
                              "anomalous item %s was auto-approved" % i)
            self.assertEqual(self.queue.get(i)["status"], "pending")
        # Positive control: the identical non-anomalous item (score 15)
        # still auto-approves under the same policy.
        decided = self.queue.maybe_auto_approve(loner_id, cfg)
        self.assertIsNotNone(decided)
        self.assertEqual(decided["status"], "approved")

    def test_detection_is_read_only(self):
        burst_ids, _ = self._burst_and_loner()
        before_bytes = self.queue.path.read_bytes()
        before_records = self.queue.all()
        self.queue.queue_anomalies(now=self.now)
        self.queue.anomaly_item_ids()
        self.assertEqual(self.queue.path.read_bytes(), before_bytes)
        self.assertEqual(self.queue.all(), before_records)
        # No anomaly flag is persisted onto the records themselves.
        for r in self.queue.all():
            self.assertNotIn("anomaly", r)

    def test_batch_approve_requires_confirmation_for_anomaly(self):
        burst_ids, _ = self._burst_and_loner()
        with self.assertRaises(ValueError) as cm:
            self.queue.batch_decide(burst_ids, True, "rubber stamp",
                                    decided_by="human-operator")
        self.assertIn("anomaly", str(cm.exception).lower())
        # Every item individually confirmed: the batch proceeds.
        decided, _entry = self.queue.batch_decide(
            burst_ids, True, "reviewed each one",
            decided_by="human-operator",
            confirm_risky=tuple(burst_ids))
        self.assertEqual(len(decided), 6)
        self.assertTrue(all(r["status"] == "approved" for r in decided))


class TestAnomalyCLI(AnomalyTestBase):
    def _run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = approve_main(["--rundir", str(self.run["run_dir"])]
                              + list(argv))
        return rc, buf.getvalue()

    def test_list_shows_fatigue_warning(self):
        tools = ["read_file", "log_note", "sleep"]
        for i in range(6):
            _queue_item(self.queue, "burst-agent", tools[i % 3],
                        ts=self.ts(i))
        rc, out = self._run_cli("list")
        self.assertEqual(rc, 0)
        self.assertIn("FATIGUE WARNING", out)
        self.assertIn("fatigue_burst", out)
        self.assertIn("| ANOMALY", out)

    def test_list_without_anomalies_shows_no_warning(self):
        _queue_item(self.queue, "calm-agent", "read_file", ts=self.ts(0))
        rc, out = self._run_cli("list")
        self.assertEqual(rc, 0)
        self.assertNotIn("FATIGUE WARNING", out)
        self.assertNotIn("| ANOMALY", out)

    def test_anomalies_command(self):
        tools = ["read_file", "log_note", "sleep"]
        for i in range(6):
            _queue_item(self.queue, "burst-agent", tools[i % 3],
                        ts=self.ts(i))
        rc, out = self._run_cli("anomalies")
        self.assertEqual(rc, 0)
        self.assertIn("fatigue_burst", out)
        self.assertIn("advisory only", out)

    def test_anomalies_command_quiet(self):
        _queue_item(self.queue, "calm-agent", "read_file", ts=self.ts(0))
        rc, out = self._run_cli("anomalies")
        self.assertEqual(rc, 0)
        self.assertIn("no queue-anomaly signals", out)


if __name__ == "__main__":
    unittest.main()
