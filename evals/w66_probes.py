"""Wave-66 D5 probes (2026-09-22): per-run cumulative ack flood budget.

Wave-65 shipped AckAuditSink with a per-sink budget (256 records +
coalescing + one overflow summary) but left the gap this wave closes:
the budget bounds one batch before one drain, so repeated drain/refill
cycles could grow the hash chain without bound per run. Wave-66 adds
the per-RUN cumulative cap (8 full sink batches, default 2048)
enforced at ToolExecutor.drain_ack_sink — the choke point into the
chain. The counter lives on the run (executor + .ack_cumulative
run-dir marker), never the sink.

Pins registered here (registry.yaml, ``redteam.sterile_d5_ack_cum.*``),
all closure: green (the control holds; probes assert it keeps
holding):
  cycle_cap_holds               — 12 drain/refill cycles x 8 records:
      exactly 64 chained (cap for max_records=8), further drains
      refuse LOUD; chain growth measured and bounded; chain verifies
  sink_replacement_no_reset     — a fresh AckAuditSink mid-run does
      not reset the cumulative counter (the anti-theater probe)
  exhaustion_refuses_loud       — AckCumulativeBudgetExceeded: raise +
      evidence retained in the sink + exactly one audited
      unvetted_ack_cumulative_budget_hit control event; empty-sink
      drains stay no-ops
  redrain_exact_accounting      — a failed mid-drain re-drains with
      exact accounting: the failed record is counted once, never
      twice (wave-65's no-silent-drops property survives)
  executor_recreation_survives  — a new ToolExecutor over the same
      run dir re-reads the marker and enforces from the carried count
  legit_loop_regression         — realistic per-window drains (distinct
      acks + a coalesced 500-ack loop) keep working end to end

All runs synthetic/local, $0. Deterministic per probe run_id. Env
hygiene restores every mutated variable in finally.
"""

import contextlib
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
# Import the test harness WITHOUT running tests/__init__.py (which flips
# on the dev-key opt-in process-wide); dev keys are enabled per-probe
# with _env()+_dev_keys() instead, and restored afterwards.
sys.path.insert(0, str(REPO_ROOT / "tests"))

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import sterile as st_mod  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
    """
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)
def _govrun():
    d = tempfile.mkdtemp(prefix="steriled5reg66-")
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = d
    tempfile.tempdir = d
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached


_govrun = contextlib.contextmanager(_govrun)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _dev_keys(True):
                        detail = fn()
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_POLICY = """\
version: 2
roles:
  researcher: [read_file, write_file, api_call, http_post, send_email]
approvals:
  ttl_hours: 24
policies: []
"""


def _fresh_run():
    d = tempfile.mkdtemp(prefix="w66probe-")
    path = os.path.join(d, "policy.yaml")
    with open(path, "w") as f:
        f.write(_POLICY)
    run = harness.make_run(policy_path=path)
    ident = run["mint_identity"]("agent-1", "researcher", "op-1")
    return run, ident


def _fill(sink, n, tag):
    for i in range(n):
        st_mod.Unvetted([i]).acknowledge("%s%d" % (tag, i), sink)


def _ack_entries(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_acknowledged"]


def _hit_entries(run):
    return [e for e in log_mod.read_entries(run["log"].path)
            if e.get("event") == "unvetted_ack_cumulative_budget_hit"]


@_sit("redteam.sterile_d5_ack_cum.cycle_cap_holds")
def sit_cycle_cap_holds():
    """D5-ack-cum pin: 12 drain/refill cycles x 8 records -> exactly 64
    chained (the cap for max_records=8); cycle 9+ refuse LOUD; chain
    growth measured and bounded; the chain verifies."""
    run, _ = _fresh_run()
    ex = run["executor"]
    refused = 0
    for cycle in range(12):
        sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill(sink, 8, "c%d-" % cycle)
        try:
            ex.drain_ack_sink(sink)
        except st_mod.AckCumulativeBudgetExceeded:
            refused += 1
            if sink.pending() != 8:
                return {"verdict": "break",
                        "note": "refused drain lost evidence: pending=%d"
                                % sink.pending()}
    if refused != 4:
        return {"verdict": "break",
                "note": "expected 4 refused cycles, got %d" % refused}
    acks = _ack_entries(run)
    if len(acks) != 64:
        return {"verdict": "break",
                "note": "chained ack records != cap: %d" % len(acks)}
    size = os.path.getsize(run["log"].path)
    if size > 200 * 1024:
        return {"verdict": "break",
                "note": "chain growth unbounded: %d bytes" % size}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "12 cycles -> 64 chained (cap), 4 refused loud; "
                    "chain %d bytes, verifies" % size}


@_sit("redteam.sterile_d5_ack_cum.sink_replacement_no_reset")
def sit_sink_replacement_no_reset():
    """D5-ack-cum pin (anti-theater): swapping in a fresh AckAuditSink
    mid-run does NOT reset the cumulative counter — the budget is
    bound to the run, not the sink."""
    run, _ = _fresh_run()
    ex = run["executor"]
    for cycle in range(4):
        sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill(sink, 8, "a%d-" % cycle)
        ex.drain_ack_sink(sink)
    if ex._ack_cumulative_used != 32:
        return {"verdict": "break", "note": "counter wrong pre-swap"}
    fresh = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
    _fill(fresh, 8, "fresh-")
    ex.drain_ack_sink(fresh)
    if ex._ack_cumulative_used != 40:
        return {"verdict": "break",
                "note": "fresh sink reset the counter: used=%d"
                        % ex._ack_cumulative_used}
    for cycle in range(3):
        sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill(sink, 8, "b%d-" % cycle)
        ex.drain_ack_sink(sink)
    over = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
    _fill(over, 8, "over-")
    try:
        ex.drain_ack_sink(over)
        return {"verdict": "break",
                "note": "no refusal at 64+8 across replaced sinks"}
    except st_mod.AckCumulativeBudgetExceeded:
        pass
    if len(_ack_entries(run)) != 64:
        return {"verdict": "break", "note": "chained != 64"}
    return {"verdict": "stopped",
            "note": "counter survived sink replacement; cap held at 64"}


@_sit("redteam.sterile_d5_ack_cum.exhaustion_refuses_loud")
def sit_exhaustion_refuses_loud():
    """D5-ack-cum pin: exhaustion raises AckCumulativeBudgetExceeded
    (not silent), the undrained records stay in the sink, exactly one
    unvetted_ack_cumulative_budget_hit control event is chained, and
    empty-sink drains stay no-ops."""
    run, _ = _fresh_run()
    ex = run["executor"]
    ex._ack_cumulative_used = 62  # near cap (max_records=8 -> 64)
    sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
    _fill(sink, 5, "x-")
    try:
        ex.drain_ack_sink(sink)
        return {"verdict": "break", "note": "exhaustion did not raise"}
    except st_mod.AckCumulativeBudgetExceeded:
        pass
    if ex._ack_cumulative_used != 64 or sink.pending() != 3:
        return {"verdict": "break",
                "note": "inexact: used=%d pending=%d"
                        % (ex._ack_cumulative_used, sink.pending())}
    hits = _hit_entries(run)
    if len(hits) != 1 or hits[0]["decision"] != "refused" \
            or hits[0]["budget"] != 64 or hits[0]["drained"] != 64:
        return {"verdict": "break",
                "note": "control event wrong: %r" % (hits,)}
    # Second refusal: still loud, but no second control event.
    try:
        ex.drain_ack_sink(sink)
    except st_mod.AckCumulativeBudgetExceeded:
        pass
    if len(_hit_entries(run)) != 1:
        return {"verdict": "break", "note": "control event not once"}
    # Empty sinks drain to 0 without raising.
    if ex.drain_ack_sink([]) != 0:
        return {"verdict": "break", "note": "empty drain misbehaved"}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "refusal loud + exact + once-audited; chain verifies"}


@_sit("redteam.sterile_d5_ack_cum.redrain_exact_accounting")
def sit_redrain_exact_accounting():
    """D5-ack-cum pin: a failed mid-drain re-drains with exact
    accounting — the failed record is counted exactly once, never
    twice (wave-65's no-silent-drops property survives the wave-66
    counter)."""
    run, _ = _fresh_run()
    ex = run["executor"]
    sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
    _fill(sink, 4, "r-")
    calls = []
    orig_append = ex.log.append

    def flaky(entry):
        calls.append(entry)
        if len(calls) == 2:
            raise log_mod.LogFullError("synthetic wave-66 probe")
        return orig_append(entry)

    ex.log.append = flaky
    try:
        ex.drain_ack_sink(sink)
        return {"verdict": "break", "note": "flaky drain did not fail"}
    except log_mod.LogFullError:
        pass
    finally:
        ex.log.append = orig_append
    if ex._ack_cumulative_used != 1 or sink.pending() != 3:
        return {"verdict": "break",
                "note": "failed record counted wrong: used=%d pending=%d"
                        % (ex._ack_cumulative_used, sink.pending())}
    if ex.drain_ack_sink(sink) != 3 or ex._ack_cumulative_used != 4:
        return {"verdict": "break", "note": "re-drain inexact"}
    if len(_ack_entries(run)) != 4:
        return {"verdict": "break", "note": "chained != 4"}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "failed drain re-drained exactly once; chain verifies"}


@_sit("redteam.sterile_d5_ack_cum.executor_recreation_survives")
def sit_executor_recreation_survives():
    """D5-ack-cum pin: a fresh ToolExecutor over the same run dir
    re-reads the .ack_cumulative marker and enforces from the carried
    count — re-creation cannot reset the run budget."""
    run, _ = _fresh_run()
    ex = run["executor"]
    for cycle in range(2):
        sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill(sink, 8, "e%d-" % cycle)
        ex.drain_ack_sink(sink)
    ex2 = ToolExecutor(run["run_dir"], run["policy"], run["log"],
                       run["approvals"])
    if ex2._ack_cumulative_used != 16:
        return {"verdict": "break",
                "note": "marker not re-read: used=%d"
                        % ex2._ack_cumulative_used}
    for cycle in range(6):
        sink = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
        _fill(sink, 8, "f%d-" % cycle)
        ex2.drain_ack_sink(sink)
    over = st_mod.AckAuditSink(max_records=8, now=lambda: 1.0)
    _fill(over, 8, "over-")
    try:
        ex2.drain_ack_sink(over)
        return {"verdict": "break",
                "note": "re-created executor did not enforce the cap"}
    except st_mod.AckCumulativeBudgetExceeded:
        pass
    if len(_ack_entries(run)) != 64:
        return {"verdict": "break", "note": "chained != 64"}
    return {"verdict": "stopped",
            "note": "marker re-read; re-created executor held the cap"}


@_sit("redteam.sterile_d5_ack_cum.legit_loop_regression")
def sit_legit_loop_regression():
    """D5-ack-cum no-regression pin: realistic per-window drains —
    distinct acks plus a coalesced 500-ack loop — keep working end to
    end, far below the cumulative cap."""
    run, _ = _fresh_run()
    ex = run["executor"]
    for w in range(3):
        sink = st_mod.AckAuditSink(now=lambda: 1.0)
        ctx = {"window": "w%d" % w, "run_id": ex.run_id}
        for i in range(5):
            st_mod.Unvetted([i], ack_context=ctx).acknowledge(
                "consumer-%d" % i, sink)
        for _ in range(500):
            st_mod.Unvetted([{"row": 1}], origin="loop-merge",
                            ack_context=ctx).acknowledge("loop-merge",
                                                         sink)
        if ex.drain_ack_sink(sink) != 6:
            return {"verdict": "break",
                    "note": "legitimate drain short in window %d" % w}
    if ex._ack_cumulative_used != 18 or len(_ack_entries(run)) != 18:
        return {"verdict": "break", "note": "legitimate count wrong"}
    v = log_mod._verify(run["log"].path)
    if not v["ok"]:
        return {"verdict": "break", "note": "chain failed to verify"}
    return {"verdict": "stopped",
            "note": "3 realistic windows drain cleanly; 18 chained"}


def _main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    stopped = [r for r in RESULTS if r["verdict"] == "stopped"]
    broken = [r for r in RESULTS if r["verdict"] not in ("stopped",)]
    print("wave-66 probes: %d stopped / %d total"
          % (len(stopped), len(RESULTS)))
    for r in RESULTS:
        print("  %-55s %s" % (r["id"], r["verdict"]))
        if r["verdict"] != "stopped":
            print("    %r" % (r["detail"],))
    return 0 if not broken else 1


if __name__ == "__main__":
    raise SystemExit(_main())
