"""Unit tests for gov.evidence_fanout and its Anchorer wiring (wave-273).

Loss-accounted evidence fan-out: the anchor job queue is BOUNDED and
every refused item is counted, never silently lost. These tests are
deterministic: the FanoutQueue tests are pure single-threaded logic,
and the Anchorer wiring tests close the worker first so the queue is
inert (no thread races).
"""

import os
import queue as std_queue
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import evidence_fanout as ef  # noqa: E402
from gov import anchorer as am  # noqa: E402
from gov import anchor_backend as ab_mod  # noqa: E402


def _tmpdir():
    base = os.environ.get("TMPDIR") or "/tmp"
    return tempfile.mkdtemp(prefix="t273-fanout-", dir="/var/tmp"
                            if os.path.isdir("/var/tmp") else base)


class FanoutQueueBasics(unittest.TestCase):
    def test_accept_up_to_maxsize_then_counted_drop(self):
        drops = []
        q = ef.FanoutQueue(maxsize=3, on_drop=lambda i, r: drops.append(
            (i, r)))
        self.assertEqual(q.submit("a"), "accepted")
        self.assertEqual(q.submit("b"), "accepted")
        self.assertEqual(q.submit("c"), "accepted")
        self.assertEqual(q.submit("d", reason="flood"), "dropped")
        self.assertEqual(q.submit("e", reason="flood"), "dropped")
        self.assertEqual(q.qsize(), 3)
        st = q.stats()
        self.assertEqual(st["accepted"], 3)
        self.assertEqual(st["dropped"], 2)
        self.assertEqual(st["dropped_by_reason"], {"flood": 2})
        self.assertEqual(st["high_water"], 3)
        self.assertIsNotNone(st["last_drop_wall"])
        # Drop-tail: the oldest items are preserved, the NEW items refused.
        self.assertEqual([q.get(), q.get(), q.get()], ["a", "b", "c"])
        # on_drop hook saw (item, reason).
        self.assertEqual(drops, [("d", "flood"), ("e", "flood")])

    def test_fail_closed_raises_and_counts_nothing(self):
        q = ef.FanoutQueue(maxsize=1, policy="fail-closed")
        q.submit("a")
        with self.assertRaises(ef.FanoutFullError):
            q.submit("b")
        st = q.stats()
        self.assertEqual(st["dropped"], 0)
        self.assertEqual(st["dropped_by_reason"], {})

    def test_invalid_construction(self):
        with self.assertRaises(ValueError):
            ef.FanoutQueue(maxsize=0)
        with self.assertRaises(ValueError):
            ef.FanoutQueue(policy="nope")
        with self.assertRaises(ValueError):
            ef.FanoutQueue(on_drop=42)

    def test_on_drop_exception_is_swallowed(self):
        def bad(item, reason):
            raise RuntimeError("hook bug")
        q = ef.FanoutQueue(maxsize=1, on_drop=bad)
        q.submit("a")
        # Must not propagate: a hook must never break the producer.
        self.assertEqual(q.submit("b"), "dropped")
        self.assertEqual(q.stats()["dropped"], 1)

    def test_submit_control_bypasses_bound(self):
        q = ef.FanoutQueue(maxsize=1)
        q.submit("a")
        q.submit_control(None)  # the stop sentinel: never refused
        self.assertEqual(q.qsize(), 2)
        st = q.stats()
        self.assertEqual(st["accepted"], 1)  # control items not counted
        self.assertEqual(st["dropped"], 0)

    def test_submit_priority_never_drops(self):
        q = ef.FanoutQueue(maxsize=2, policy="fail-closed")
        q.submit("a")
        q.submit("b")
        # Even fail-closed never refuses the priority channel: healing
        # must be reliable.
        self.assertEqual(q.submit_priority("c"), "accepted")
        self.assertEqual(q.qsize(), 3)
        st = q.stats()
        self.assertEqual(st["accepted"], 3)
        self.assertEqual(st["dropped"], 0)

    def test_get_task_done_join_roundtrip(self):
        q = ef.FanoutQueue(maxsize=4)
        q.submit("a")
        q.submit("b")
        self.assertEqual(q.get(), "a")
        q.task_done()
        self.assertEqual(q.get(), "b")
        q.task_done()
        q.join()  # returns: nothing unfinished
        with self.assertRaises(std_queue.Empty):
            q.get(block=False)
        with self.assertRaises(ValueError):
            q.task_done()  # too many

    def test_producer_consumer_threads(self):
        q = ef.FanoutQueue(maxsize=64)
        seen = []
        stop = threading.Event()

        def consumer():
            while not stop.is_set() or q.qsize():
                try:
                    seen.append(q.get(timeout=0.1))
                except std_queue.Empty:
                    continue
                q.task_done()

        t = threading.Thread(target=consumer, daemon=True)
        t.start()
        for i in range(50):
            self.assertEqual(q.submit(i), "accepted")
        q.join()
        stop.set()
        t.join(timeout=10)
        self.assertEqual(seen, list(range(50)))
        st = q.stats()
        self.assertEqual(st["accepted"], 50)
        self.assertEqual(st["dropped"], 0)

    def test_threaded_drop_tail_accounting(self):
        # Slow consumer + counted-drop: the tail is refused and every
        # refusal is counted; FIFO order of the accepted prefix holds.
        q = ef.FanoutQueue(maxsize=4)
        for i in range(20):
            q.submit(i)
        st = q.stats()
        self.assertEqual(st["accepted"] + st["dropped"], 20)
        self.assertEqual(st["dropped"], 16)
        got = [q.get() for _ in range(4)]
        self.assertEqual(got, [0, 1, 2, 3])

    def test_stats_shape(self):
        q = ef.FanoutQueue(maxsize=16)
        st = q.stats()
        for key in ("maxsize", "policy", "depth", "accepted", "dropped",
                    "dropped_by_reason", "high_water", "last_drop_wall",
                    "recent_drop_events"):
            self.assertIn(key, st)
        self.assertEqual(st["policy"], "counted-drop")
        self.assertEqual(st["recent_drop_events"], [])


class _NullBackend(ab_mod.AnchorBackend):
    def submit(self, anchor_hash):
        return {"backend": "null-test", "uuid": "u"}

    def verify_receipt(self, receipt, *, anchor_hash):
        return (True, "")


def _make_anchorer(fanout_maxsize=2, fanout_policy="counted-drop"):
    import secrets
    from gov.log import ActionLog
    d = _tmpdir()
    os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    lg = ActionLog(os.path.join(d, "actions.jsonl"))
    lg.append({"event": "tool_call", "principal": "p", "agent_id": "a"})
    seed = bytes([9]) * 32
    pub = ab_mod.anchor_pubkey(seed)
    key = {"seed": seed, "key_id": ab_mod.anchor_key_id(pub),
           "pubkey_hex": pub.hex(), "dev": True}
    a = am.Anchorer(
        lg, _NullBackend(),
        policy=am.AnchorPolicy(records_per_epoch=10 ** 9,
                               seconds_per_epoch=None,
                               anchor_on_close=False),
        anchor_key=key, warn=lambda m: None,
        fanout_maxsize=fanout_maxsize, fanout_policy=fanout_policy)
    return a, lg, d


class AnchorerWiring(unittest.TestCase):
    """Wiring tests with the worker closed: the queue is inert, so the
    fill/drop/recover assertions are deterministic."""

    def _closed(self, **kw):
        a, lg, d = _make_anchorer(**kw)
        a.close(timeout=15)
        self.assertFalse(a._thread.is_alive())
        return a, lg, d

    def test_enqueue_returns_queued_then_dropped(self):
        a, lg, d = self._closed(fanout_maxsize=2)
        self.assertEqual(
            a._enqueue_job("e00000001", 1, 1, "w"), "queued")
        self.assertEqual(
            a._enqueue_job("e00000001", 1, 1, "w"), "queued")
        self.assertEqual(
            a._enqueue_job("e00000001", 1, 1, "w"), "dropped")
        st = a.fanout_stats()
        self.assertEqual(st["accepted"], 2)
        self.assertEqual(st["dropped"], 1)
        self.assertEqual(st["dropped_by_reason"], {"anchor-job": 1})

    def test_drop_chains_recoverable_unanchored_record(self):
        a, lg, d = self._closed(fanout_maxsize=1)
        a._enqueue_job("e00000001", 1, 1, "w")
        self.assertEqual(
            a._enqueue_job("e00000001", 1, 1, "w"), "dropped")
        import json
        recs = [json.loads(l) for l in
                open(os.path.join(d, "actions.jsonl"),
                     encoding="utf-8").read().splitlines() if l.strip()]
        una = [e for e in recs
               if e.get("event") == am.ANCHOR_UNANCHORED_EVENT]
        self.assertEqual(len(una), 1)
        self.assertEqual(una[0]["reason"], "fanout-full")
        self.assertEqual(una[0]["anchored_epoch_id"], "e00000001")

    def test_fail_closed_policy_raises_from_enqueue(self):
        a, lg, d = self._closed(fanout_maxsize=1,
                                fanout_policy="fail-closed")
        a._enqueue_job("e00000001", 1, 1, "w")
        with self.assertRaises(ef.FanoutFullError):
            a._enqueue_job("e00000001", 1, 1, "w")
        self.assertEqual(a.fanout_stats()["dropped"], 0)

    def test_recover_requeues_through_priority_channel(self):
        # Fill the queue, drop one (chains an unanchored record), then
        # recover: the requeue must bypass the bound, not drop again.
        a, lg, d = self._closed(fanout_maxsize=1)
        a._enqueue_job("e00000001", 1, 1, "w")   # fills the queue
        self.assertEqual(
            a._enqueue_job("e00000002", 2, 2, "w"), "dropped")
        self.assertEqual(a.recover(), 1)
        # Priority requeue bypassed the full queue: nothing dropped twice.
        st = a.fanout_stats()
        self.assertEqual(st["dropped"], 1)
        self.assertEqual(a._queue.qsize(), 2)

    def test_fanout_stats_worker_counters(self):
        a, lg, d = self._closed()
        st = a.fanout_stats()
        for key in ("completed", "failed", "retried", "abandoned"):
            self.assertIn(key, st)
            self.assertEqual(st[key], 0)

    def test_default_policy_is_counted_drop(self):
        a, lg, d = self._closed(fanout_maxsize=1024)
        self.assertEqual(a._queue.policy, "counted-drop")
        self.assertEqual(a._queue.maxsize, 1024)

    def test_close_on_full_queue_exits(self):
        # The stop sentinel bypasses the bound: close() cannot deadlock.
        a, lg, d = _make_anchorer(fanout_maxsize=1)
        a._queue.submit({"job": 1}, reason="t")
        a._queue.submit({"job": 2}, reason="t")  # one drops; fine
        a.close(timeout=15)
        self.assertFalse(a._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
