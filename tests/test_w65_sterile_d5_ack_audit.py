"""Wave-65 D5 unit tests: acknowledgment audit trail.

Pins workstreams/evals/STERILE_D5_ACK_AUDIT.md (design + break-first):
AckAuditSink (flood budget, consecutive-duplicate coalescing with exact
counts, count-preserving overflow, peek-confirm drain), ack_context
correlation (executor-stamped window/run through the JSON envelope),
the enriched acknowledge() record (never payload contents), the
record-then-unwrap ordering, and ToolExecutor.drain_ack_sink (reserved
run keys win over forged record claims; failed appends keep the record).

Deterministic, hermetic (make_run temp dirs), $0.
"""
import json
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
os.environ.setdefault("GOV_DEV_KEYS", "1")

from gov.log import enable_dev_keys  # noqa: E402
enable_dev_keys()

from gov.sterile import (  # noqa: E402
    AckAuditSink, Unvetted)


def _ack(consumer="c", origin="reissue_reads", ctx=None, sink=None):
    u = Unvetted([{"result_summary": "s"}], origin=origin,
                 ack_context=ctx)
    return u.acknowledge(consumer, sink)


class AckRecordTest(unittest.TestCase):
    """The acknowledge() record: enriched, correlated, payload-free."""

    def test_record_fields_and_correlation(self):
        sink = AckAuditSink(now=lambda: 1234.5)
        ctx = {"window": "w-pay", "run_id": "run-9"}
        _ack("dashboard", sink=sink, ctx=ctx)
        rec = sink.peek_oldest()
        self.assertEqual(rec["event"], "unvetted_acknowledged")
        self.assertEqual(rec["consumer"], "dashboard")
        self.assertEqual(rec["origin"], "reissue_reads")
        self.assertEqual(rec["ack_context"], ctx)
        self.assertEqual(rec["ts"], 1234.5)
        self.assertEqual(rec["count"], 1)

    def test_record_never_carries_payload(self):
        sink = AckAuditSink(now=lambda: 1.0)
        secret = "sk-live-unvetted-payload-contents"
        u = Unvetted([{"result_summary": secret}])
        u.acknowledge("c", sink)
        blob = json.dumps(sink.peek_oldest())
        self.assertNotIn(secret, blob)
        self.assertNotIn("result_summary", blob)

    def test_plain_list_sink_still_works_with_ts(self):
        sink = []
        _ack("c", sink=sink)
        self.assertEqual(len(sink), 1)
        self.assertEqual(sink[0]["event"], "unvetted_acknowledged")
        self.assertIn("ts", sink[0])
        self.assertEqual(sink[0]["ack_context"], {})

    def test_ack_context_validated_at_construction(self):
        with self.assertRaises(TypeError):
            Unvetted([1], ack_context="not-a-dict")
        with self.assertRaises(TypeError):
            Unvetted([1], ack_context={1: "bad-key"})
        with self.assertRaises(TypeError):
            Unvetted([1], ack_context={"k": object()})
        # JSON scalars are fine.
        Unvetted([1], ack_context={"w": "w1", "n": 3, "f": 1.5,
                                   "b": True, "z": None})

    def test_envelope_carries_ack_context(self):
        ctx = {"window": "w1", "run_id": "r1"}
        env = Unvetted([1], ack_context=ctx).to_envelope()
        u2 = Unvetted.from_envelope(json.loads(json.dumps(env)))
        sink = []
        u2.acknowledge("c", sink)
        self.assertEqual(sink[0]["ack_context"], ctx)

    def test_envelope_malformed_context_under_informs(self):
        env = {"__gov_unvetted__": True, "origin": "reissue_reads",
               "payload": [1], "ack_context": ["x"]}
        u = Unvetted.from_envelope(env)
        sink = []
        u.acknowledge("c", sink)
        self.assertEqual(sink[0]["ack_context"], {})

    def test_ack_context_not_confused_by_nested_marker_keys(self):
        # A __gov_vetted__-looking key nested in ack_context stays inert
        # data; from_envelope never interprets nested keys.
        env = {"__gov_unvetted__": True, "origin": "reissue_reads",
               "payload": [1],
               "ack_context": {"note": "__gov_vetted__"}}
        u = Unvetted.from_envelope(env)
        self.assertIsInstance(u, Unvetted)


class AckSinkFloodTest(unittest.TestCase):
    """Flood resistance: budget, exact counts, no silent drops."""

    def test_consecutive_duplicates_coalesce_exactly(self):
        sink = AckAuditSink(now=lambda: 7.0)
        for _ in range(500):
            _ack("loop", sink=sink)
        self.assertEqual(sink.pending(), 1)
        rec = sink.peek_oldest()
        self.assertEqual(rec["count"], 500)
        self.assertEqual(rec["consumer"], "loop")

    def test_distinct_acks_bounded_with_exact_overflow(self):
        sink = AckAuditSink(max_records=10, now=lambda: 1.0)
        for i in range(25):
            _ack("c%d" % i, sink=sink)
        # 10 individual + 1 overflow summary; 15 counted, none lost.
        self.assertEqual(sink.pending(), 11)
        summary = sink._records[-1]
        self.assertEqual(summary["event"], "unvetted_ack_overflow")
        self.assertEqual(summary["dropped"], 15)
        self.assertEqual(sum(summary["by_consumer"].values()), 15)
        for i in range(10, 25):
            self.assertEqual(summary["by_consumer"]["c%d" % i], 1)

    def test_nothing_silently_dropped(self):
        sink = AckAuditSink(max_records=8, now=lambda: 1.0)
        n = 100
        for i in range(n):
            _ack("c%d" % (i % 20), sink=sink)
        individual = sum(r.get("count", 1)
                         for r in sink._records
                         if r["event"] == "unvetted_acknowledged")
        summaries = [r for r in sink._records
                     if r["event"] == "unvetted_ack_overflow"]
        self.assertEqual(len(summaries), 1)
        self.assertEqual(individual + summaries[0]["dropped"], n)

    def test_sink_never_raises_for_volume(self):
        sink = AckAuditSink(max_records=4, now=lambda: 1.0)
        for i in range(1000):
            _ack("spam-%d" % i, sink=sink)  # must not raise
        self.assertLessEqual(sink.pending(), 5)  # 4 + summary

    def test_coalescing_respects_context_boundaries(self):
        sink = AckAuditSink(now=lambda: 1.0)
        _ack("c", sink=sink, ctx={"window": "w1"})
        _ack("c", sink=sink, ctx={"window": "w2"})  # different window
        _ack("c", sink=sink, ctx={"window": "w2"})  # dup of w2
        self.assertEqual(sink.pending(), 2)
        recs = [sink.pop_oldest(), sink.pop_oldest()]
        self.assertEqual(recs[0]["count"], 1)
        self.assertEqual(recs[1]["count"], 2)

    def test_expected_consumer_mismatch_is_loud(self):
        sink = AckAuditSink(expected_consumer="dashboard",
                            now=lambda: 1.0)
        _ack("dashboard", sink=sink)  # fine
        with self.assertRaises(ValueError):
            _ack("someone-else", sink=sink)
        # ... and the failed ack left no partial record.
        self.assertEqual(sink.pending(), 1)

    def test_bad_sink_args_rejected(self):
        with self.assertRaises(ValueError):
            AckAuditSink(max_records=0)
        with self.assertRaises(ValueError):
            AckAuditSink(max_records=-3)
        with self.assertRaises(TypeError):
            AckAuditSink(expected_consumer="")


class AckOrderingTest(unittest.TestCase):
    """Record-then-unwrap: a record implies the unwrap; a raising sink
    never yields the payload."""

    def test_record_precedes_payload_return(self):
        events = []

        class OrderSink(list):
            def append(self, rec):
                events.append("record")
                super().append(rec)

        u = Unvetted(["payload"])
        events.append("before")
        out = u.acknowledge("c", OrderSink())
        events.append("after")
        self.assertEqual(out, ["payload"])
        self.assertEqual(events, ["before", "record", "after"])

    def test_raising_sink_never_returns_payload(self):
        class BrokenSink:
            def append(self, rec):
                raise IOError("disk gone")

        u = Unvetted(["payload"])
        with self.assertRaises(IOError):
            u.acknowledge("c", BrokenSink())
        # No silent loss: the failure is loud, the payload withheld.

    def test_no_sink_no_record(self):
        u = Unvetted(["payload"])
        self.assertEqual(u.acknowledge("c"), ["payload"])  # caller choice


_DRAIN_POLICY = """\
critical_windows:
  - id: w-pay
    on_tools: ["http_post"]
    suspend: [web_fetch]
    close_policy: agent_declared
    max_duration_s: 300
    rationale: "test"
policies: []
"""


def _drain_run():
    from harness import make_run  # noqa: E402
    d = tempfile.mkdtemp(prefix="w65ack-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_DRAIN_POLICY)
    run = make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


class DrainAckSinkTest(unittest.TestCase):
    """ToolExecutor.drain_ack_sink: reserved keys win; failed appends
    keep the record; the drained trail verifies in the hash chain."""

    def test_drain_into_hash_chained_log(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        sink = AckAuditSink(now=lambda: 2000.0)
        u = Unvetted([{"result_summary": "delta"}],
                     ack_context={"window": "w-pay",
                                  "run_id": ex.run_id})
        u.acknowledge("review-dashboard", sink)
        n = ex.drain_ack_sink(sink)
        self.assertEqual(n, 1)
        self.assertEqual(sink.pending(), 0)
        from gov import log as log_mod
        v = log_mod._verify(run["log"].path)
        self.assertTrue(v["ok"], v.get("error"))
        entries = [e for e in log_mod.read_entries(run["log"].path)
                   if e.get("event") == "unvetted_acknowledged"]
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e["consumer"], "review-dashboard")
        self.assertEqual(e["ack_context"]["window"], "w-pay")
        self.assertEqual(e["run_id"], ex.run_id)
        self.assertNotIn("result_summary", json.dumps(e))

    def test_forged_run_context_neutralized_at_drain(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        evil = {"event": "unvetted_acknowledged",
                "consumer": "mallory",
                "run_id": "forged-run",      # must not survive
                "agent_id": "forged-agent",  # must not survive
                "role": "forged-role",       # must not survive
                "origin": "reissue_reads",
                "ack_context": {}, "count": 1, "ts": 1.0}
        n = ex.drain_ack_sink([evil])
        self.assertEqual(n, 1)
        from gov import log as log_mod
        entries = [e for e in log_mod.read_entries(run["log"].path)
                   if e.get("event") == "unvetted_acknowledged"]
        self.assertEqual(entries[0]["run_id"], ex.run_id)
        self.assertNotEqual(entries[0]["agent_id"], "forged-agent")
        self.assertNotEqual(entries[0]["role"], "forged-role")
        # The self-attested consumer stays as claimed (documented
        # boundary — consumer identity is not authenticated).
        self.assertEqual(entries[0]["consumer"], "mallory")

    def test_failed_log_append_keeps_record_in_sink(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        sink = AckAuditSink(now=lambda: 1.0)
        _ack("c", sink=sink)
        ex.log.configure_guard(1)  # absurdly small: next append fails
        from gov import log as log_mod
        with self.assertRaises(log_mod.LogFullError):
            ex.drain_ack_sink(sink)
        # Peek-confirm: the record is still in the sink, nothing
        # silently dropped.
        self.assertEqual(sink.pending(), 1)
        ex.log.configure_guard(None)
        self.assertEqual(ex.drain_ack_sink(sink), 1)
        self.assertEqual(sink.pending(), 0)

    def test_drain_non_record_refused(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        with self.assertRaises(TypeError):
            ex.drain_ack_sink(["not-a-dict"])

    def test_executor_wrap_sites_stamp_ack_context(self):
        # Both reissue sites (close + expiry) stamp window/run into the
        # envelope so downstream acks correlate.
        from gov import sterile as st_mod
        run, ident = _drain_run()
        ex = run["executor"]

        class Loop(st_mod.LoopContract):
            def reissue_reads(self, reads):
                return [{"tool": t, "channel": c,
                         "result_summary": "s"}
                        for t, c in reads]

            def freeze_context(self, r):
                pass

            def withhold(self, c):
                pass

            def release(self, c):
                pass

        ex.attach_loop_contract(Loop())
        ex.call(ident, "http_post", url="https://synthetic.local/x",
                data="d")
        ex.call(ident, "api_call",
                endpoint="https://synthetic.local/v1", params={"q": 1})
        for rec in ex.approvals.pending():
            ex.approvals.decide(rec["id"], True, "test")
        out = ex.request_window_close(ident)
        self.assertTrue(out["closed"])
        from gov import log as log_mod
        exits = [e for e in log_mod.read_entries(run["log"].path)
                 if e.get("event") == "sterile_window_exit"]
        deltas = [e for e in exits if e.get("post_window_delta")]
        self.assertEqual(len(deltas), 1)
        u = st_mod.Unvetted.from_envelope(
            deltas[0]["post_window_delta"])
        self.assertEqual(u._ack_context["window"], "w-pay")
        self.assertEqual(u._ack_context["run_id"], ex.run_id)


if __name__ == "__main__":
    unittest.main()
