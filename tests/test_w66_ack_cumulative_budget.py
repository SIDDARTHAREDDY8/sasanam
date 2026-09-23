"""Wave-66 D5 unit tests: per-run cumulative ack flood budget.

Pins workstreams/evals/ACK_CUMULATIVE_BUDGET.md (design + break-first):
the wave-65 per-sink budget bounds one batch before one drain; wave-66
adds a per-RUN cumulative cap enforced at ToolExecutor.drain_ack_sink
(the choke point into the hash chain). The counter lives on the run
(executor + .ack_cumulative run-dir marker), never the sink, so sink
replacement cannot reset it; exhaustion refuses LOUD
(AckCumulativeBudgetExceeded, evidence retained in the sink, one
audited control event per run); the counter increments only after a
successful chain-append + pop, so a failed drain re-drains with exact
accounting (no double-count).

Deterministic, hermetic (make_run temp dirs), $0.
"""
import json
import os
import secrets
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TMPDIR", "/tmp/gov-run")
# Wave-81: gov/ has no dev key or dev-key opt-in. Provision an EXPLICIT
# random key via the production env path (GOV_LOG_KEY/GOV_LOG_KEY_EPOCH);
# tests/__init__.py does the same for the canonical suite -- this keeps
# direct `python tests/test_x.py` runs self-sufficient.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "test")

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.sterile import (  # noqa: E402
    AckAuditSink, AckCumulativeBudgetExceeded, Unvetted,
    _ACK_CUMULATIVE_BATCHES_DEFAULT, _ACK_BUDGET_DEFAULT)

_DRAIN_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
policies: []
"""


def _drain_run():
    import tempfile
    d = tempfile.mkdtemp(prefix="w66-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_DRAIN_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _fill_sink(n, sink, tag="c"):
    for i in range(n):
        Unvetted([i]).acknowledge("%s%d" % (tag, i), sink)


def _ack_events(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_acknowledged"]


def _hit_events(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_ack_cumulative_budget_hit"]


class CumulativeCapTest(unittest.TestCase):
    """Drain/refill cycling cannot launder unbounded evidence."""

    def test_cap_scales_from_sink_batch_budget(self):
        sink = AckAuditSink(max_records=8, now=lambda: 1.0)
        self.assertEqual(sink.max_records, 8)
        run, _ident = _drain_run()
        ex = run["executor"]
        # 8 batches of 8 = 64 = the cumulative cap for this sink.
        for cycle in range(_ACK_CUMULATIVE_BATCHES_DEFAULT):
            s = AckAuditSink(max_records=8, now=lambda: 1.0)
            _fill_sink(8, s, tag="c%d-" % cycle)
            self.assertEqual(ex.drain_ack_sink(s), 8)
        self.assertEqual(ex._ack_cumulative_used, 64)
        # The 9th batch refuses LOUD.
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, s, tag="evil-")
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s)
        # Exact accounting: exactly 64 ack records chained, evidence
        # retained in the sink (peek-confirm), chain verifies.
        self.assertEqual(len(_ack_events(run)), 64)
        self.assertEqual(s.pending(), 8)
        v = log_mod._verify(run["log"].path)
        self.assertTrue(v["ok"], v.get("error"))

    def test_default_cap_is_eight_full_batches(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        s = AckAuditSink(now=lambda: 1.0)
        _fill_sink(3, s)
        ex.drain_ack_sink(s)
        # White-box fast-forward to just under the default cap.
        ex._ack_cumulative_used = \
            _ACK_CUMULATIVE_BATCHES_DEFAULT * _ACK_BUDGET_DEFAULT - 1
        s2 = AckAuditSink(now=lambda: 1.0)
        _fill_sink(2, s2, tag="t-")
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s2)
        # One drained (cap reached), one retained.
        self.assertEqual(ex._ack_cumulative_used,
                         _ACK_CUMULATIVE_BATCHES_DEFAULT
                         * _ACK_BUDGET_DEFAULT)
        self.assertEqual(s2.pending(), 1)


class SinkReplacementTest(unittest.TestCase):
    """Replacing the sink mid-run does not reset the counter."""

    def test_fresh_sink_does_not_reset_cumulative(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        for cycle in range(4):
            s = AckAuditSink(max_records=8, now=lambda: 1.0)
            _fill_sink(8, s, tag="a%d-" % cycle)
            ex.drain_ack_sink(s)
        self.assertEqual(ex._ack_cumulative_used, 32)
        # Adversary swaps in a brand-new sink: the run counter stands.
        fresh = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, fresh, tag="fresh-")
        ex.drain_ack_sink(fresh)
        self.assertEqual(ex._ack_cumulative_used, 40)
        for cycle in range(3):
            s = AckAuditSink(max_records=8, now=lambda: 1.0)
            _fill_sink(8, s, tag="b%d-" % cycle)
            ex.drain_ack_sink(s)
        self.assertEqual(ex._ack_cumulative_used, 64)
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, s, tag="over-")
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s)
        self.assertEqual(len(_ack_events(run)), 64)


class ExhaustionBehaviorTest(unittest.TestCase):
    """Exhaustion refuses LOUD: raise + evidence retained + one
    audited control event. No silent drops, no silent withhold."""

    def test_refusal_is_loud_and_exact(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        ex._ack_cumulative_used = 64 - 2  # near cap, max_records=8
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(5, s)
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s)
        # 2 drained (cap reached exactly), 3 retained in the sink.
        self.assertEqual(ex._ack_cumulative_used, 64)
        self.assertEqual(s.pending(), 3)
        # Loud in the chain: exactly one control event, with the
        # budget facts; the chain verifies.
        hits = _hit_events(run)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["decision"], "refused")
        self.assertEqual(hits[0]["budget"], 64)
        self.assertEqual(hits[0]["drained"], 64)
        self.assertEqual(hits[0]["run_id"], ex.run_id)
        v = log_mod._verify(run["log"].path)
        self.assertTrue(v["ok"], v.get("error"))

    def test_second_refusal_adds_no_second_control_event(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        ex._ack_cumulative_used = 64
        ex._ack_budget_hit_audited = False
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(2, s)
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s)
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(s)
        self.assertEqual(len(_hit_events(run)), 1)
        self.assertEqual(s.pending(), 2)

    def test_empty_sink_drain_while_exhausted_is_noop(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        ex._ack_cumulative_used = 64
        # Legitimate no-op drains keep working at exhaustion.
        self.assertEqual(ex.drain_ack_sink([]), 0)
        self.assertEqual(
            ex.drain_ack_sink(AckAuditSink(max_records=8,
                                           now=lambda: 1.0)), 0)
        self.assertEqual(len(_hit_events(run)), 0)

    def test_plain_list_sink_bounded_by_cumulative_cap(self):
        # A plain list has no per-sink budget; the cumulative cap is
        # its ONLY bound (keyed to the default batch baseline).
        run, _ident = _drain_run()
        ex = run["executor"]
        ex._ack_cumulative_used = (
            _ACK_CUMULATIVE_BATCHES_DEFAULT * _ACK_BUDGET_DEFAULT - 1)
        sink = []
        _fill_sink(5, sink, tag="pl-")
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex.drain_ack_sink(sink)
        self.assertEqual(ex._ack_cumulative_used,
                         _ACK_CUMULATIVE_BATCHES_DEFAULT
                         * _ACK_BUDGET_DEFAULT)
        self.assertEqual(len(sink), 4)  # one drained, four retained


class ExactAccountingTest(unittest.TestCase):
    """A failed drain re-drains with exact accounting: the counter
    moves only after a successful chain-append + pop (no double
    count), and the run-dir marker is rewritten only then."""

    def test_failed_mid_drain_redrains_exactly_once(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(4, s)
        calls = []
        orig_append = ex.log.append

        def flaky(entry):
            calls.append(entry)
            if len(calls) == 2:
                raise log_mod.LogFullError("synthetic wave-66 probe")
            return orig_append(entry)

        ex.log.append = flaky
        try:
            with self.assertRaises(log_mod.LogFullError):
                ex.drain_ack_sink(s)
        finally:
            ex.log.append = orig_append
        # First record chained (used=1); the failed record stayed in
        # the sink and was NOT counted.
        self.assertEqual(ex._ack_cumulative_used, 1)
        self.assertEqual(s.pending(), 3)
        # Re-drain: exact — no double count.
        self.assertEqual(ex.drain_ack_sink(s), 3)
        self.assertEqual(ex._ack_cumulative_used, 4)
        self.assertEqual(len(_ack_events(run)), 4)
        v = log_mod._verify(run["log"].path)
        self.assertTrue(v["ok"], v.get("error"))

    def test_marker_rewritten_only_on_success(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        marker = ex._ack_cumulative_marker
        self.assertFalse(marker.exists())
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(2, s)
        ex.drain_ack_sink(s)
        data = json.loads(marker.read_text())
        self.assertEqual(data, {"drained": 2, "budget_hit": False})
        # A failed drain does not touch the marker.
        before = marker.read_text()
        ex.log.configure_guard(1)
        s2 = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(1, s2)
        with self.assertRaises(log_mod.LogFullError):
            ex.drain_ack_sink(s2)
        ex.log.configure_guard(None)
        self.assertEqual(marker.read_text(), before)
        self.assertEqual(ex._ack_cumulative_used, 2)


class RunScopeTest(unittest.TestCase):
    """The counter survives executor re-creation over the same run
    dir and is keyed to the run, not the window."""

    def test_executor_recreation_reads_marker(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, s)
        ex.drain_ack_sink(s)
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, s)
        ex.drain_ack_sink(s)
        self.assertEqual(ex._ack_cumulative_used, 16)
        # A fresh executor over the same run dir picks up the count.
        ex2 = ToolExecutor(run["run_dir"], run["policy"], run["log"],
                           run["approvals"],
                           # Wave-85: ack-budget tests reconstruct over
                           # the same run dir; raw pipeline declared, not
                           # silent.
                           ungoverned_ack=(
                               "ack-budget test: re-construction over the "
                               "same run dir; raw pipeline by design"))
        self.assertEqual(ex2._ack_cumulative_used, 16)
        self.assertEqual(ex2.run_id, ex.run_id)
        # And it enforces from there: 48 more reach the 64 cap, then
        # refusal.
        for cycle in range(6):
            s = AckAuditSink(max_records=8, now=lambda: 1.0)
            _fill_sink(8, s, tag="r%d-" % cycle)
            ex2.drain_ack_sink(s)
        s = AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill_sink(8, s, tag="over-")
        with self.assertRaises(AckCumulativeBudgetExceeded):
            ex2.drain_ack_sink(s)
        self.assertEqual(len(_ack_events(run)), 64)

    def test_corrupt_marker_degrades_to_zero(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        ex._ack_cumulative_marker.write_text("not-json{{{")
        ex2 = ToolExecutor(run["run_dir"], run["policy"], run["log"],
                           run["approvals"],
                           # Wave-85: ack-budget tests reconstruct over
                           # the same run dir; raw pipeline declared, not
                           # silent.
                           ungoverned_ack=(
                               "ack-budget test: re-construction over the "
                               "same run dir; raw pipeline by design"))
        # Documented boundary: corrupt marker -> 0 (server-side
        # run-dir state, same trust class as the run dir itself).
        self.assertEqual(ex2._ack_cumulative_used, 0)
        self.assertFalse(ex2._ack_budget_hit_audited)


class LegitimateLoopTest(unittest.TestCase):
    """The cap does not break legitimate ack volumes: per-window
    drains of realistic size keep working end to end."""

    def test_legitimate_per_window_drains_unaffected(self):
        run, _ident = _drain_run()
        ex = run["executor"]
        # Three realistic windows: a handful of distinct acks plus a
        # coalesced per-row loop (500 identical acks -> one record).
        for w in range(3):
            sink = AckAuditSink(now=lambda: 1.0)
            ctx = {"window": "w%d" % w, "run_id": ex.run_id}
            for i in range(5):
                Unvetted([i], ack_context=ctx).acknowledge(
                    "consumer-%d" % i, sink)
            for _ in range(500):
                Unvetted([{"row": 1}], origin="loop-merge",
                         ack_context=ctx).acknowledge("loop-merge",
                                                      sink)
            n = ex.drain_ack_sink(sink)
            self.assertEqual(n, 6)  # 5 distinct + 1 coalesced
        self.assertEqual(ex._ack_cumulative_used, 18)
        self.assertEqual(len(_ack_events(run)), 18)
        v = log_mod._verify(run["log"].path)
        self.assertTrue(v["ok"], v.get("error"))


if __name__ == "__main__":
    unittest.main()
