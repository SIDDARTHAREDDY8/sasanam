"""Unit tests for gov.decision_shipping (wave-206 lane E).

Deterministic. Stdlib unittest. Covers the config freeze, the compiled
mask gate, ingest/drop accounting, chunking, backoff, freshness cadence,
the unbuffered tier, and disk-tier write-through/recovery.
"""

import copy
import dataclasses
import json
import os
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import decision_shipping as ship
from gov import decision_log_v2 as dlv2

_REPLAY = "ship_unit_replay"


def _replay_fn(inputs):
    return {"verdict": "allow"}


try:
    dlv2.register_replay_fn(_REPLAY, _replay_fn)
except dlv2.EventBuildError:
    pass


def make_event(body_extra=None, erased=("/secret",), masked=("/token",),
               replay_inputs=None):
    body = {"action": "read", "secret": "hunter2",
            "token": "tok-abc", "nested": {"x": 1}}
    if body_extra:
        body.update(body_extra)
    if replay_inputs is None:
        replay_inputs = {"n": 1}
    return dlv2.build_event(
        decision={"kind": "tool_call", "effect": "allow",
                  "policy_id": "p1", "reason": "unit"},
        raw_body=body, erased=list(erased), masked=list(masked),
        replay_fn=_REPLAY, replay_inputs=replay_inputs,
        replay_verdict=_replay_fn(replay_inputs))


def make_config(**kw):
    base = dict(chunk_limit_bytes=10_000, buffer_limit_bytes=100_000,
                buffer_limit_events=100, max_delay_s=600.0, min_delay_s=0.0,
                backoff_base_s=0.0, backoff_max_s=0.0, max_retries=3)
    base.update(kw)
    return ship.ShippingConfig(**base)


def make_mask():
    return ship.CompiledMask(erased=("/secret",), masked=("/token",))


class Sink:
    def __init__(self, statuses):
        self.statuses = list(statuses)
        self.chunks = []

    def __call__(self, chunk_bytes):
        self.chunks.append(chunk_bytes)
        return self.statuses.pop(0) if len(self.statuses) > 1 \
            else self.statuses[0]


class ConfigTests(unittest.TestCase):
    def test_frozen(self):
        cfg = make_config()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.chunk_limit_bytes = 1

    def test_bad_values_refused(self):
        with self.assertRaises(ship.ConfigError):
            make_config(chunk_limit_bytes=0)
        with self.assertRaises(ship.ConfigError):
            make_config(chunk_limit_bytes=-5)
        with self.assertRaises(ship.ConfigError):
            make_config(chunk_limit_bytes=True)
        with self.assertRaises(ship.ConfigError):
            make_config(durability="carrier-pigeon")
        with self.assertRaises(ship.ConfigError):
            make_config(min_delay_s=700.0, max_delay_s=600.0)
        with self.assertRaises(ship.ConfigError):
            make_config(max_retries=-1)

    def test_disk_requires_journal_path(self):
        with self.assertRaises(ship.ConfigError):
            make_config(durability="disk")


class MaskTests(unittest.TestCase):
    def test_bad_pointers_refused(self):
        with self.assertRaises(ship.ConfigError):
            ship.CompiledMask(erased=("no-slash",))
        with self.assertRaises(ship.ConfigError):
            ship.CompiledMask(erased=("/a", "/a"))
        with self.assertRaises(ship.ConfigError):
            ship.CompiledMask(erased=("/a",), masked=("/a",))

    def test_gate_accepts_matching_plan(self):
        mask = make_mask()
        ev = make_event()
        self.assertEqual(mask.apply(ev), ev)

    def test_gate_refuses_plan_mismatch(self):
        mask = make_mask()
        other = make_event(erased=("/secret", "/nested/x"))
        with self.assertRaises(ship.IngestError):
            mask.apply(other)

    def test_gate_refuses_non_v2(self):
        with self.assertRaises(ship.IngestError):
            make_mask().apply({"not": "an event"})


class IngestTests(unittest.TestCase):
    def test_ingest_buffers(self):
        sh = ship.DecisionShipper(make_config(), make_mask(), Sink([200]))
        r = sh.ingest(make_event())
        self.assertEqual(r["status"], "buffered")
        self.assertEqual(sh.buffered_events, 1)

    def test_buffer_full_drops_loudly(self):
        audit = []
        sh = ship.DecisionShipper(make_config(buffer_limit_events=2),
                                  make_mask(), Sink([200]), audit=audit)
        sh.ingest(make_event())
        sh.ingest(make_event())
        r = sh.ingest(make_event())
        self.assertEqual(r["status"], "dropped")
        self.assertEqual(r["reason"], "buffer-full")
        self.assertEqual(sh.dropped_events, 1)
        self.assertEqual(sh.drop_records[0]["kind"], "drop-record")
        self.assertEqual(len(audit), 1)

    def test_oversize_evicts_replay_loudly(self):
        # The replay capture is the unbounded-growth key (the OPA
        # nd_builtin_cache analog): size the chunk limit so the raw event
        # exceeds it but the replay-evicted form fits (eviction must be
        # load-bearing).
        ev = make_event(replay_inputs={"trace": "x" * 900})
        raw = len(json.dumps(ev, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, default=str).encode())
        sh = ship.DecisionShipper(make_config(chunk_limit_bytes=raw - 500),
                                  make_mask(), Sink([200]))
        r = sh.ingest(ev)
        self.assertEqual(r["status"], "buffered", r)
        buffered = sh._buffer[0][2]  # (occurrence_id, decision_id, event, size)
        self.assertEqual(buffered["shipping_evictions"], ["replay"])
        self.assertTrue(buffered["replay"]["evicted"])
        # the capture digest commits to the dropped capture
        self.assertEqual(
            buffered["replay"]["capture_digest"],
            __import__("hashlib").sha256(
                json.dumps(ev["replay"], sort_keys=True,
                           separators=(",", ":"),
                           ensure_ascii=True).encode()).hexdigest())
        # the decision_id binding re-derives (tamper-evident) ...
        preimage = {k: v for k, v in buffered.items()
                    if k not in ("decision_id", "audit")}
        self.assertEqual(
            buffered["decision_id"],
            __import__("hashlib").sha256(
                json.dumps(preimage, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode()).hexdigest())
        # ... while verify_event refuses the evicted capture loudly
        # (never silently papered over)
        with self.assertRaises(dlv2.EventVerifyError):
            dlv2.verify_event(buffered)

    def test_hopelessly_oversize_drops_loudly(self):
        sh = ship.DecisionShipper(make_config(chunk_limit_bytes=600),
                                  make_mask(), Sink([200]))
        big = make_event(body_extra={"blob": "x" * 4000})
        r = sh.ingest(big)
        self.assertEqual(r["status"], "dropped")
        self.assertEqual(r["reason"], "oversize")
        self.assertEqual(sh.dropped_events, 1)

    def test_mask_never_breaches_buffer(self):
        sh = ship.DecisionShipper(make_config(), make_mask(), Sink([200]))
        with self.assertRaises(ship.IngestError):
            sh.ingest({"secret": "hunter2"})
        self.assertEqual(sh.buffered_events, 0)


class FlushTests(unittest.TestCase):
    def test_success_clears_buffer(self):
        sink = Sink([200])
        sh = ship.DecisionShipper(make_config(), make_mask(), sink)
        sh.ingest(make_event())
        s = sh.flush()
        self.assertEqual(s["shipped"], 1)
        self.assertEqual(sh.shipped_events, 1)
        self.assertEqual(sh.chunks_sent, 1)
        self.assertEqual(sh.buffered_events, 0)

    def test_non2xx_requeues_with_backoff(self):
        sink = Sink([500, 200])
        sh = ship.DecisionShipper(make_config(backoff_base_s=100.0,
                                              backoff_max_s=100.0),
                                  make_mask(), sink)
        sh.ingest(make_event())
        s1 = sh.flush()
        self.assertEqual(s1["requeued"], 1)
        self.assertEqual(sh.buffered_events, 1)
        s2 = sh.flush()
        self.assertEqual(s2["status"], "backoff")
        self.assertGreater(s2["retry_in_s"], 0)

    def test_retry_budget_exhaustion_drops_loudly(self):
        sink = Sink([500])
        sh = ship.DecisionShipper(make_config(max_retries=1,
                                              backoff_base_s=0.0),
                                  make_mask(), sink)
        sh.ingest(make_event())
        sh.flush()   # 1st failure: requeue
        s = sh.flush()  # 2nd failure: budget exhausted -> loud drop
        self.assertEqual(s["dropped"], 1)
        self.assertEqual(sh.dropped_events, 1)
        self.assertEqual(sh.buffered_events, 0)
        self.assertIn("sink-unavailable",
                      sh.drop_records[0]["reason"])

    def test_sink_raise_is_sink_error(self):
        def boom(chunk):
            raise RuntimeError("net down")

        sh = ship.DecisionShipper(make_config(), make_mask(), boom)
        sh.ingest(make_event())
        with self.assertRaises(ship.SinkError):
            sh.flush()

    def test_maybe_flush_freshness(self):
        sink = Sink([200])
        sh = ship.DecisionShipper(make_config(max_delay_s=100.0,
                                              min_delay_s=50.0),
                                  make_mask(), sink)
        sh.ingest(make_event())
        s = sh.maybe_flush(now=0.0)
        self.assertEqual(s["shipped"], 1)  # first flush always goes
        sh.ingest(make_event())
        s = sh.maybe_flush(now=10.0)
        self.assertEqual(s["status"], "fresh")  # min_delay respected
        s = sh.maybe_flush(now=200.0)
        self.assertEqual(s["shipped"], 1)  # max_delay forces it


class UnbufferedTests(unittest.TestCase):
    def test_no_ack_no_action(self):
        ran = []
        sh = ship.DecisionShipper(
            make_config(durability="unbuffered", max_retries=0,
                        backoff_base_s=0.0), make_mask(), Sink([503]))
        with self.assertRaises(ship.SinkError):
            sh.run_unbuffered(make_event(), lambda: ran.append(1))
        self.assertEqual(ran, [])
        self.assertEqual(sh.dropped_events, 1)

    def test_ack_then_action(self):
        order = []
        sink = Sink([200])

        def acking(chunk):
            order.append("ack")
            return sink(chunk)

        sh = ship.DecisionShipper(make_config(durability="unbuffered"),
                                  make_mask(), acking)
        self.assertEqual(
            sh.run_unbuffered(make_event(),
                              lambda: order.append("action") or "ok"), "ok")
        self.assertEqual(order, ["ack", "action"])

    def test_wrong_tier_refused(self):
        sh = ship.DecisionShipper(make_config(), make_mask(), Sink([200]))
        with self.assertRaises(ship.ConfigError):
            sh.run_unbuffered(make_event(), lambda: None)


class DiskTierTests(unittest.TestCase):
    def test_write_through_and_recovery(self):
        tmp = tempfile.mkdtemp(prefix="ship-unit-")
        jpath = os.path.join(tmp, "j.jsonl")
        sh = ship.DecisionShipper(
            make_config(durability="disk", journal_path=jpath),
            make_mask(), Sink([200]))
        ev = make_event()
        sh.ingest(ev)
        self.assertTrue(os.path.exists(jpath))
        # restart before flush: the event must come back
        sh2 = ship.DecisionShipper(
            make_config(durability="disk", journal_path=jpath),
            make_mask(), Sink([200]))
        self.assertEqual(sh2.buffered_events, 1)
        # restart after flush: nothing re-sent
        sh2.flush()
        sh3 = ship.DecisionShipper(
            make_config(durability="disk", journal_path=jpath),
            make_mask(), Sink([200]))
        self.assertEqual(sh3.buffered_events, 0)

    def test_journal_holds_drop_records(self):
        tmp = tempfile.mkdtemp(prefix="ship-unit-")
        jpath = os.path.join(tmp, "j.jsonl")
        sh = ship.DecisionShipper(
            make_config(durability="disk", journal_path=jpath,
                        buffer_limit_events=1),
            make_mask(), Sink([200]))
        sh.ingest(make_event())
        sh.ingest(make_event())  # buffer-full -> loud drop
        from gov import durable_journal as dj
        kinds = [r["type"] for r in dj.Journal(jpath).records]
        self.assertIn("drop_record", kinds)


class RegressionTests(unittest.TestCase):
    """Reviewer-found regressions (wave-206 two-axis review)."""

    def test_b1_unbuffered_needs_this_events_ack(self):
        # Split-ack: E1's chunk is acked, E2's chunk is not. The action
        # must NOT run on another event's ack.
        cfg = make_config(durability="unbuffered", chunk_limit_bytes=1000)
        sink = Sink([200, 500])
        sh = ship.DecisionShipper(cfg, make_mask(), sink)
        e1 = make_event(body_extra={"tag": "leftover-e1"})
        sh.ingest(e1)  # leftover from an earlier failed run
        e2 = make_event(body_extra={"tag": "e2"})
        ran = []
        with self.assertRaises(ship.SinkError):
            sh.run_unbuffered(e2, lambda: ran.append(True) or "ran")
        self.assertEqual(ran, [])
        # E2 is still buffered (requeued); E1 was shipped.
        self.assertEqual(sh.buffered_events, 1)
        self.assertEqual(sh.shipped_events, 1)

    def test_b1_unbuffered_runs_when_this_event_acked(self):
        cfg = make_config(durability="unbuffered", chunk_limit_bytes=1000)
        sink = Sink([500, 200])
        sh = ship.DecisionShipper(cfg, make_mask(), sink)
        sh.ingest(make_event(body_extra={"tag": "leftover-e1"}))
        out = sh.run_unbuffered(make_event(body_extra={"tag": "e2"}),
                                lambda: "ran")
        self.assertEqual(out, "ran")
        # E2's chunk acked (action released); E1's chunk got the 500 and
        # stays requeued -- per-occurrence accounting, not a global count.
        self.assertEqual(sh.shipped_events, 1)
        self.assertEqual(sh.buffered_events, 1)

    def test_b2_restart_does_not_resurrect_dropped(self):
        tmp = tempfile.mkdtemp(prefix="ship-unit-")
        jpath = os.path.join(tmp, "j.jsonl")
        cfg = make_config(durability="disk", journal_path=jpath,
                          max_retries=0)
        sh = ship.DecisionShipper(cfg, make_mask(), Sink([500]))
        ev = make_event()
        sh.ingest(ev)
        s = sh.flush()
        self.assertEqual(s["dropped"], 1)
        self.assertEqual(sh.dropped_events, 1)
        # Restart: the deliberately-dropped event must NOT come back.
        sh2 = ship.DecisionShipper(cfg, make_mask(), Sink([200]))
        self.assertEqual(sh2.buffered_events, 0)
        s2 = sh2.flush()
        self.assertEqual(s2["status"], "empty")
        self.assertEqual(sh2.shipped_events, 0)
        self.assertEqual(len(sh2.drop_records), 0)

    def test_s1_duplicate_ingest_ships_exactly(self):
        # Same decision_id twice, separate chunks: both occurrences must
        # ship (occurrence-exact removal, never a decision-id set).
        cfg = make_config(chunk_limit_bytes=1000)
        sink = Sink([200, 200])
        sh = ship.DecisionShipper(cfg, make_mask(), sink)
        ev = make_event()
        sh.ingest(ev)
        sh.ingest(ev)
        s = sh.flush()
        self.assertEqual(s["shipped"], 2)
        self.assertEqual(sh.shipped_events, 2)
        self.assertEqual(sh.buffered_events, 0)
        self.assertEqual(sh.dropped_events, 0)

    def test_s1_duplicate_ingest_drops_exactly(self):
        cfg = make_config(chunk_limit_bytes=1000, max_retries=0)
        sink = Sink([500, 500])
        sh = ship.DecisionShipper(cfg, make_mask(), sink)
        ev = make_event()
        sh.ingest(ev)
        sh.ingest(ev)
        s = sh.flush()
        self.assertEqual(s["dropped"], 2)
        self.assertEqual(sh.dropped_events, 2)
        self.assertEqual(len(sh.drop_records), 2)
        self.assertEqual(sh.buffered_events, 0)

    def test_s2_backoff_uses_injected_clock(self):
        cfg = make_config(backoff_base_s=100.0, backoff_max_s=1000.0)
        sink = Sink([500, 200])
        sh = ship.DecisionShipper(cfg, make_mask(), sink)
        sh.ingest(make_event())
        s1 = sh.flush(now=1000.0)
        self.assertEqual(s1["requeued"], 1)
        s2 = sh.flush(now=1050.0)
        self.assertEqual(s2["status"], "backoff")
        self.assertEqual(len(sink.chunks), 1)
        s3 = sh.flush(now=1150.0)
        self.assertEqual(s3["shipped"], 1)
        self.assertEqual(len(sink.chunks), 2)

    def test_s3_min_delay_floors_auto_flush(self):
        cfg = make_config(min_delay_s=50.0, max_delay_s=100.0)
        sh = ship.DecisionShipper(cfg, make_mask(), Sink([200]))
        sh.ingest(make_event())
        self.assertEqual(sh.maybe_flush(now=0.0)["status"], "flushed")
        sh.ingest(make_event())
        # Only 10s since the last flush: min_delay floors it.
        r = sh.maybe_flush(now=10.0)
        self.assertEqual(r["status"], "fresh")
        self.assertEqual(sh.buffered_events, 1)
        # Past max_delay: flush fires.
        r = sh.maybe_flush(now=200.0)
        self.assertEqual(r["status"], "flushed")
        self.assertEqual(sh.buffered_events, 0)


class StatsTests(unittest.TestCase):
    def test_stats_shape(self):
        sh = ship.DecisionShipper(make_config(), make_mask(), Sink([200]))
        s = sh.stats()
        for key in ("buffered_events", "buffered_bytes", "shipped_events",
                    "dropped_events", "upload_failures", "chunks_sent"):
            self.assertIn(key, s)


if __name__ == "__main__":
    unittest.main()
