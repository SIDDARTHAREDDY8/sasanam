"""Concurrent-load benchmark for the governance hot path.

NOT a unittest: the filename does not match ``test_*.py`` so the suite
(``tests/run_tests.py``) ignores it. Run directly::

    TMPDIR=/tmp/gov-run /path/to/.venv/bin/python3 tests/bench_concurrent.py

Measures, under N concurrent agent threads (default 1/4/16/64), with
``time.perf_counter_ns`` per-iteration deltas and p50/p95/p99/max
reporting:

* S1 policy-decision throughput: ``PolicyEngine.evaluate()`` on one
  shared engine (read-only stage — expect GIL-bound scaling).
* S2 approval-queue throughput: ``ApprovalQueue.queue()`` on one shared
  queue (unlocked O_APPEND writes + keyed digest HMAC per record).
* S3 audit-log append throughput: ``ActionLog.append()`` on ONE shared
  log (F25 exclusive flock serializes writers — the bench then runs
  ``verify_chain()`` to prove the chain stayed intact under contention,
  the property the R16 corruption finding broke).
* S4 end-to-end ``ToolExecutor.call("read_file")`` with one run dir +
  executor PER thread (realistic multi-agent shape, no logical
  contention — exposes per-call fixed costs).
* S5 end-to-end ``ToolExecutor.call("api_call")`` on ONE shared run dir
  + executor (adversarial contention shape: ledger append + per-call
  ledger re-verify, flock-serialized log appends). Uses a synthetic
  policy variant of the default policy with ``min_external_calls``
  raised so the burst stays on the allow path (documented below).
* S6 approval-sweep contention: N threads racing
  ``execute_approved()`` over K pre-approved records (the queue flock
  serializes sweeps; exactly-once execution is asserted).

Also includes ``bench_refused_sweeps()``: a faithful re-run of the
Round-16 F69 refused-sweep measurement (2k/10k/20k action-log entries,
F51 disturbance shape, 1 cold + 5 warm sweeps) to check reproducibility.

Design doc: workstreams/performance/DESIGN.md.
Results are appended to BENCHMARKS.md by this script's main().

Env knobs: BENCH_THREADS (default "1,4,16,64"), BENCH_M1..M5
(iterations per thread per scenario), BENCH_WARMUP (default 100).
"""

import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.approvals import ApprovalQueue
# F73 double opt-in: dev-key posture for local benchmark harnesses only.
# Matches the suite's tests/__init__.py (in-code enable_dev_keys() +
# GOV_DEV_KEYS=1). Ledger numbers stay worst-case for the ledger path
# (no real GOV_LOG_KEY -> sig cache disabled).
os.environ.setdefault("GOV_DEV_KEYS", "1")
from gov.log import enable_dev_keys as _bench_enable_dev_keys
_bench_enable_dev_keys()
from gov.egress_ledger import EgressLedger
from gov.executor import ToolExecutor
from gov.log import ActionLog, verify_chain
from gov.policy import PolicyDecision, PolicyEngine

DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"

THREADS = [int(x) for x in
           os.environ.get("BENCH_THREADS", "1,4,16,64").split(",") if x]
WARMUP = int(os.environ.get("BENCH_WARMUP", "100"))
M = {
    "S1": int(os.environ.get("BENCH_M1", "2000")),
    "S2": int(os.environ.get("BENCH_M2", "400")),
    "S3": int(os.environ.get("BENCH_M3", "200")),
    "S4": int(os.environ.get("BENCH_M4", "200")),
    "S5": int(os.environ.get("BENCH_M5", "40")),
}


def pct(samples, q):
    s = sorted(samples)
    if not s:
        return 0.0
    idx = min(len(s) - 1, int(q * len(s)))
    return s[idx]


def summarize_ms(name, samples):
    ms = [x * 1e3 for x in samples]
    if not ms:
        return {"name": name, "n": 0, "mean_ms": float("nan"),
                "p50_ms": float("nan"), "p95_ms": float("nan"),
                "p99_ms": float("nan"), "max_ms": float("nan")}
    return {
        "name": name,
        "n": len(ms),
        "mean_ms": statistics.mean(ms),
        "p50_ms": pct(ms, 0.50),
        "p95_ms": pct(ms, 0.95),
        "p99_ms": pct(ms, 0.99),
        "max_ms": max(ms),
    }


def _run_threads(n_threads, setup_fn, work_fn, warmup=WARMUP):
    """setup_fn(tid) -> state; work_fn(tid, state, i) timed per iteration.

    Returns (all_samples, per_thread_max_ms, wall_s, errors). A start
    barrier aligns the threads so the wall clock measures contention,
    not stagger.

    Exception safety: a worker that raises (e.g. the S5 egress-ledger
    fork raising LedgerUnverifiableError) records its error and STILL
    reaches both barrier rendezvous, so a failing worker can never
    deadlock the main thread. Errors are returned, never hidden.
    """
    states = [setup_fn(t) for t in range(n_threads)]
    barrier = threading.Barrier(n_threads + 1)
    results = [None] * n_threads
    errors = [None] * n_threads

    def _arrive():
        try:
            barrier.wait()
        except threading.BrokenBarrierError:
            pass

    def runner(t):
        state = states[t]
        ok = True
        try:
            # Warmup iterations use distinct negative indices so
            # per-iteration-varying workloads (S4/S5 unique paths/params)
            # do not trip the executor's identical-call loop guard
            # during warmup (100 identical warmup calls would).
            for w in range(warmup):
                work_fn(t, state, -1 - w)
        except Exception as e:  # noqa: BLE001 - recorded in errors
            errors[t] = ("warmup", repr(e))
            ok = False
        _arrive()  # (A) start together even if warmup failed
        samples = []
        if ok:
            try:
                for i in range(work_fn.m):
                    t0 = time.perf_counter_ns()
                    try:
                        work_fn(t, state, i)
                    except Exception as e:  # noqa: BLE001
                        # Per-iteration failure (S5 ledger fork): count
                        # it, keep the thread alive for the barrier.
                        if errors[t] is None:
                            errors[t] = ("timed", repr(e))
                        samples.append(None)
                        continue
                    samples.append((time.perf_counter_ns() - t0) * 1e-9)
            except Exception as e:  # noqa: BLE001 - unexpected harness bug
                if errors[t] is None:
                    errors[t] = ("harness", repr(e))
        results[t] = samples
        _arrive()  # (B) always rendezvous

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        futs = [pool.submit(runner, t) for t in range(n_threads)]
        try:
            barrier.wait(timeout=600)  # (C) release all workers at once
        except threading.BrokenBarrierError:
            raise RuntimeError("benchmark barrier broken at start")
        t0 = time.perf_counter_ns()
        try:
            barrier.wait(timeout=600)  # (D) all workers done
        except threading.BrokenBarrierError:
            raise RuntimeError("benchmark barrier broken at finish")
        wall_s = (time.perf_counter_ns() - t0) * 1e-9
        for f in futs:
            f.result()
    timed = [s for rs in results for s in rs if s is not None]
    n_err_iters = sum(1 for rs in results for s in rs if s is None)
    per_thread_max = [max([s for s in rs if s is not None] or [0.0]) * 1e3
                      for rs in results]
    err_notes = [(t, e) for t, e in enumerate(errors) if e is not None]
    return timed, per_thread_max, wall_s, n_err_iters, err_notes


def _mkwork(m):
    def deco(fn):
        fn.m = m
        return fn
    return deco


# ---------------------------------------------------------------- S1: policy
def bench_s1_policy(n_threads):
    policy = PolicyEngine(str(DEFAULT_POLICY))
    action = {"tool": "read_file", "agent_id": "a", "role": "coder",
              "args": {"path": "bench.txt"}}
    ctx = {"path_outside_sandbox": False}

    @_mkwork(M["S1"])
    def work(t, _state, i):
        policy.evaluate(action, ctx)

    samples, tmax, wall, n_err, err_notes = _run_threads(
        n_threads, lambda t: None, work)
    row = summarize_ms("S1 policy.evaluate, %d threads" % n_threads,
                       samples)
    row["throughput_ops"] = len(samples) / wall
    row["wall_s"] = wall
    row["slowest_thread_max_ms"] = max(tmax)
    row["err_iters"] = n_err
    row["err_notes"] = err_notes
    return row


# ------------------------------------------------------- S2: approval queue
def bench_s2_queue(n_threads):
    run_dir = Path(tempfile.mkdtemp(prefix="govbench-cq-"))
    try:
        log = ActionLog(run_dir / "actions.jsonl")
        q = ApprovalQueue(run_dir, log)
        # One executor installs the F42 identity verifier (write-once);
        # identities are pre-minted BEFORE timing (mint budget = 64/run).
        ex = ToolExecutor(run_dir, policy_stub(), log, q,
                          ledger_path=run_dir / "egress_ledger.jsonl")
        idents = [ex.mint_identity("agent-%d" % t, "coder",
                                   "bench-principal")
                  for t in range(n_threads)]
        decision = PolicyDecision("require_approval", "bench",
                                  policy_id="bench-q")

        def setup(t):
            return idents[t]

        @_mkwork(M["S2"])
        def work(t, ident, i):
            q.queue(
                {"tool": "read_file",
                 "args": {"path": "q-%d-%d.txt" % (t, i)}},
                decision, "agent_direct", "bench preview",
                policy_hash=ex.policy.policy_hash,
                caller_identity=ident)

        samples, tmax, wall, n_err, err_notes = _run_threads(n_threads, setup, work)
        expect = n_threads * (WARMUP + M["S2"])  # warmup also queues
        assert len(q.all()) == expect, (len(q.all()), expect)
        row = summarize_ms("S2 approvals.queue, %d threads" % n_threads,
                           samples)
        row["throughput_ops"] = len(samples) / wall
        row["wall_s"] = wall
        row["slowest_thread_max_ms"] = max(tmax)
        row["err_iters"] = n_err
        row["err_notes"] = err_notes
        return row
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


def policy_stub():
    """A PolicyEngine is required by ToolExecutor only for pins/policy
    hash; the default policy is the honest choice here."""
    return PolicyEngine(str(DEFAULT_POLICY))


# ------------------------------------------------------------ S3: log append
def bench_s3_log_append(n_threads):
    run_dir = Path(tempfile.mkdtemp(prefix="govbench-cl-"))
    try:
        log = ActionLog(run_dir / "actions.jsonl")

        @_mkwork(M["S3"])
        def work(t, _state, i):
            log.append({"event": "conc-bench", "w": t, "i": i})

        samples, tmax, wall, n_err, err_notes = _run_threads(
            n_threads, lambda t: None, work)
        ok, broken, count = verify_chain(str(run_dir / "actions.jsonl"))
        assert ok, "chain broke under concurrent appends: %r" % (broken,)
        expect = n_threads * (WARMUP + M["S3"])  # warmup also appends
        assert count == expect, (count, expect)
        row = summarize_ms("S3 log.append (shared log), %d threads"
                           % n_threads, samples)
        row["throughput_ops"] = len(samples) / wall
        row["wall_s"] = wall
        row["slowest_thread_max_ms"] = max(tmax)
        row["err_iters"] = n_err
        row["err_notes"] = err_notes
        row["verify_ok"] = ok
        return row
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


# ------------------------------------------- S4: e2e, isolated runs/threads
def bench_s4_e2e_isolated(n_threads):
    base = Path(tempfile.mkdtemp(prefix="govbench-ce4-"))
    try:
        policy = PolicyEngine(str(DEFAULT_POLICY))

        def setup(t):
            run_dir = base / ("t%d" % t)
            run_dir.mkdir()
            log = ActionLog(run_dir / "actions.jsonl")
            q = ApprovalQueue(run_dir, log)
            ex = ToolExecutor(run_dir, policy, log, q,
                              ledger_path=run_dir / "egress_ledger.jsonl")
            ident = ex.mint_identity("agent-%d" % t, "coder",
                                     "bench-principal")
            # warmup calls happen inside _run_threads; the executor is
            # constructed (2 setup log appends) before timing starts.
            return ex, ident

        @_mkwork(M["S4"])
        def work(t, state, i):
            ex, ident = state
            rec = ex.call(ident, "read_file", path="iso-%d-%d.txt" % (t, i))
            assert rec["status"] == "executed", rec

        samples, tmax, wall, n_err, err_notes = _run_threads(n_threads, setup, work)
        row = summarize_ms("S4 e2e call, isolated runs, %d threads"
                           % n_threads, samples)
        row["throughput_ops"] = len(samples) / wall
        row["wall_s"] = wall
        row["slowest_thread_max_ms"] = max(tmax)
        row["err_iters"] = n_err
        row["err_notes"] = err_notes
        return row
    finally:
        shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------- S5: e2e, ONE shared run dir
def _api_policy_path(tmp):
    """Default policy with the external-call volume rule raised so a
    benchmark burst of api_call stays on the allow path (the campaign
    heuristics need >= 2-3 DISTINCT runs to fire, so one fresh run dir
    never trips them). The change is documented, not hidden."""
    text = DEFAULT_POLICY.read_text(encoding="utf-8")
    assert "min_external_calls: 5" in text
    p = Path(tmp) / "bench-api-policy.yaml"
    p.write_text(text.replace("min_external_calls: 5",
                             "min_external_calls: 1000000"),
                 encoding="utf-8")
    return str(p)


def bench_s5_e2e_shared(n_threads):
    # S5 warmup is small on purpose: every S5 call (warmup or timed)
    # appends to the ledger and the dev-key posture re-verifies the whole
    # ledger per call (O(n) per call -> O(n^2) per burst), so a 100/call
    # warmup would dominate wall time at high thread counts. 5 warmup
    # calls still exercise the warm code paths. See BENCH_S5_WARMUP.
    s5_warmup = int(os.environ.get("BENCH_S5_WARMUP", "5"))
    run_dir = Path(tempfile.mkdtemp(prefix="govbench-ce5-"))
    try:
        policy = PolicyEngine(_api_policy_path(run_dir))
        log = ActionLog(run_dir / "actions.jsonl")
        q = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, q,
                          ledger_path=run_dir / "egress_ledger.jsonl")
        idents = [ex.mint_identity("agent-%d" % t, "coder",
                                   "bench-principal")
                  for t in range(n_threads)]

        def setup(t):
            return idents[t]

        @_mkwork(M["S5"])
        def work(t, ident, i):
            rec = ex.call(ident, "api_call",
                          endpoint="https://api.example.com/v1",
                          params={"q": "shared-%d-%d" % (t, i)})
            assert rec["status"] == "executed", rec

        samples, tmax, wall, n_err, err_notes = _run_threads(
            n_threads, setup, work, warmup=s5_warmup)
        # F74 fix verification under load: the ledger chain must be
        # unbroken and entry count exact (pre-fix this forked: duplicate
        # seqs, verify() false, every call LedgerUnverifiableError).
        ledger = EgressLedger(run_dir / "egress_ledger.jsonl")
        ledger_ok = ledger.verify()
        entries = sum(1 for _ in
                      (run_dir / "egress_ledger.jsonl").open(
                          encoding="utf-8"))
        expect = n_threads * (s5_warmup + M["S5"])  # warmup also appends
        assert ledger_ok, "ledger chain broke under concurrent load"
        assert entries == expect, (entries, expect)
        row = summarize_ms("S5 e2e api_call, shared run, %d threads"
                           % n_threads, samples)
        row["throughput_ops"] = len(samples) / wall
        row["wall_s"] = wall
        row["slowest_thread_max_ms"] = max(tmax)
        row["err_iters"] = n_err
        row["err_notes"] = err_notes
        row["verify_ok"] = ledger_ok
        row["entries"] = entries
        return row
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


# ------------------------------------------------- S6: racing approval sweeps
def bench_s6_sweep_race(n_threads, k_records=16):
    run_dir = Path(tempfile.mkdtemp(prefix="govbench-cs6-"))
    try:
        policy = PolicyEngine(str(DEFAULT_POLICY))
        log = ActionLog(run_dir / "actions.jsonl")
        q = ApprovalQueue(run_dir, log)
        ex = ToolExecutor(run_dir, policy, log, q,
                          ledger_path=run_dir / "egress_ledger.jsonl")
        ident = ex.mint_identity("sweeper", "coder", "bench-principal")
        decision = PolicyDecision("require_approval", "bench",
                                  policy_id="bench-s6")
        aids = []
        for i in range(k_records):
            aid = q.queue(
                {"tool": "read_file",
                 "args": {"path": "sweep-%d.txt" % i}},
                decision, "agent_direct", "bench",
                policy_hash=policy.policy_hash,
                caller_identity=ident)
            q.decide(aid, True, "bench approval")
            aids.append(aid)
        barrier = threading.Barrier(n_threads + 1)
        walls = [None] * n_threads
        errs = []

        def sweeper(t):
            barrier.wait()
            t0 = time.perf_counter_ns()
            try:
                ex.execute_approved()
            except Exception as e:  # noqa: BLE001 - recorded, not hidden
                errs.append(repr(e))
            walls[t] = (time.perf_counter_ns() - t0) * 1e-9
            barrier.wait()

        with ThreadPoolExecutor(max_workers=n_threads) as pool:
            futs = [pool.submit(sweeper, t) for t in range(n_threads)]
            barrier.wait()
            barrier.wait()
            for f in futs:
                f.result()
        assert not errs, errs
        # Exactly-once: each record's approved_executed appears once.
        executed = [e for e in
                    (run_dir / "actions.jsonl").read_text(
                        encoding="utf-8").splitlines()
                    if '"approved_executed"' in e]
        assert len(executed) == k_records, (len(executed), k_records)
        ms = [w * 1e3 for w in walls]
        return {
            "name": "S6 racing execute_approved sweeps, %d threads"
                    % n_threads,
            "n": n_threads,
            "mean_ms": statistics.mean(ms),
            "p50_ms": pct(ms, 0.50),
            "p95_ms": pct(ms, 0.95),
            "p99_ms": pct(ms, 0.99),
            "max_ms": max(ms),
            "wall_s": max(walls),
            "executed_once_each": True,
        }
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


# --------------------------------------------- sandbox spawn overhead
def bench_sandbox_spawn(n=60, warmup=5):
    """Re-run of the bench_latency.py sandbox measurement (``Sandbox.run(
    [\"/bin/true\"])``): the per-tool-call process cost if every file op
    goes through the sandbox backend. Sequential, n=60, same shape as the
    stale 2026-09-21 row so the numbers are comparable."""
    from gov.sandbox import Sandbox
    s = Sandbox(timeout=10)
    for _ in range(warmup):
        r = s.run(["/bin/true"])
        assert r.ok, r
    samples = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        r = s.run(["/bin/true"])
        samples.append((time.perf_counter_ns() - t0) * 1e-9)
        assert r.ok, r
    row = summarize_ms("sandbox spawn (/bin/true)", samples)
    row["throughput_ops"] = len(samples) / sum(samples)
    row["wall_s"] = sum(samples)
    return row


# --------------------------------------- R16 refused-sweep reproducibility
def bench_refused_sweeps(sizes=(2000, 10000, 20000), warm=5):
    """Faithful re-run of the Round-16 F69 refused-sweep measurement.

    Shape (from tests/test_hardening_r16.py + evals/r16_probes.py): N
    action-log entries, a directory at approvals.lock (the F51
    disturbance shape), the coalesce sidecar re-corrupted before each
    sweep, and a FRESH executor per sweep. 1 cold sweep seeds the
    chain-tip cache; ``warm`` sweeps are timed. Recorded 2026-09-22:
    2k -> 2-13ms; 10k -> 15-56ms; 20k -> 30-73ms (5 warm sweeps each).
    """
    policy = PolicyEngine(str(DEFAULT_POLICY))
    rows = []
    for n in sizes:
        run_dir = Path(tempfile.mkdtemp(prefix="govbench-rs%d-" % n))
        try:
            (run_dir / "approvals.lock").mkdir()
            log = ActionLog(run_dir / "actions.jsonl")
            for i in range(n):
                log.append({"event": "r16_setup", "i": i})

            def one_sweep():
                (run_dir / "lock_refusal_coalesce.json").write_text(
                    '{"broken": true', encoding="utf-8")
                ex = ToolExecutor(
                    run_dir, policy,
                    ActionLog(run_dir / "actions.jsonl"),
                    ApprovalQueue(run_dir,
                                  ActionLog(run_dir / "actions.jsonl")),
                    ledger_path=run_dir / "egress_ledger.jsonl")
                t0 = time.perf_counter_ns()
                ret = ex.execute_approved()
                return ret, (time.perf_counter_ns() - t0) * 1e-9

            ret, cold = one_sweep()
            assert ret == [], ret
            warm_times = []
            for _ in range(warm):
                ret, dt = one_sweep()
                assert ret == [], ret
                warm_times.append(dt)
            wms = [t * 1e3 for t in warm_times]
            rows.append({
                "name": "refused sweep, %d entries (1 cold + %d warm)"
                        % (n, warm),
                "n": n,
                "cold_ms": cold * 1e3,
                "warm_p50_ms": pct(wms, 0.50),
                "warm_max_ms": max(wms),
                "warm_min_ms": min(wms),
            })
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
    return rows


def fmt_row(r):
    err = ""
    notes = r.get("err_notes") or []
    n_err = r.get("err_iters") or 0
    if n_err or notes:
        first = notes[0][1][1][:70] if notes else "?"
        kinds = ",".join(sorted(set(k for _, (k, _) in notes))) or "timed"
        err = " ERRORS iters=%d threads[%d]=%s (%s...)" % (
            n_err, len(notes), kinds, first)
    if r.get("verify_ok") is not None:
        err += " verify_ok=%s entries=%d" % (r["verify_ok"],
                                            r.get("entries", -1))
    return ("| %s | %d | %.1f | %.3f | %.3f | %.3f | %.3f | %.3f |%s"
            % (r["name"], r["n"], r.get("throughput_ops", 0.0) or 0.0,
               r["mean_ms"], r["p50_ms"], r["p95_ms"], r["p99_ms"],
               r["max_ms"], err))


def main():
    print("concurrent-load benchmarks: threads=%s warmup=%d M=%s"
          % (THREADS, WARMUP, M), flush=True)
    rows = []
    for label, fn, skey in (
            ("S1", bench_s1_policy, "S1"),
            ("S2", bench_s2_queue, "S2"),
            ("S3", bench_s3_log_append, "S3"),
            ("S4", bench_s4_e2e_isolated, "S4"),
            ("S5", bench_s5_e2e_shared, "S5")):
        for t in THREADS:
            print("  %s: %d threads x %d ..." % (label, t, M[skey]),
                  flush=True)
            rows.append(fn(t))
    print("  S6: racing sweeps ...", flush=True)
    for t in (2, 4, 8):
        rows.append(bench_s6_sweep_race(t))
    print("  sandbox spawn (sequential, n=60) ...", flush=True)
    rows.append(bench_sandbox_spawn())

    table = ("| scenario | n | throughput ops/s | mean ms | p50 ms | "
             "p95 ms | p99 ms | max ms |\n"
             "|---|---|---|---|---|---|---|---|\n"
             + "\n".join(fmt_row(r) for r in rows) + "\n")

    print("  refused-sweep reproducibility (2k/10k/20k) ...", flush=True)
    if os.environ.get("BENCH_SKIP_REFUSED"):
        rtable = "_skipped (BENCH_SKIP_REFUSED set)_\n"
    else:
        rs = bench_refused_sweeps()
        rtable = ("| shape | entries | cold ms | warm min ms | warm p50 ms | "
                  "warm max ms |\n"
                  "|---|---|---|---|---|---|\n"
                  + "\n".join(
                      "| %s | %d | %.1f | %.1f | %.1f | %.1f |"
                      % (r["name"], r["n"], r["cold_ms"], r["warm_min_ms"],
                         r["warm_p50_ms"], r["warm_max_ms"]) for r in rs)
                  + "\n")

    date = "2026-09-22"
    f74note = ("F74 status: the EgressLedger append race is CLOSED (fix "
               "landed + red-team verified 2026-09-22; F25-style reentrant "
               "per-path read/write lock in `gov/egress_ledger.py`). S5 now "
               "asserts the fix holds under load: all thread counts must "
               "complete with an unbroken chain and zero LedgerUnverifiableError.")

    section = """
## Concurrent-load benchmarks (%s)

`tests/bench_concurrent.py` (excluded from unittest discovery by
filename; run directly). N concurrent threads, %d-iteration warmup,
per-iteration `time.perf_counter_ns` deltas; p50/p95/p99/max in ms plus
aggregate throughput. Env: BENCH_THREADS="%s", iterations/thread
S1=%d S2=%d S3=%d S4=%d S5=%d. Dev-key posture (no GOV_LOG_KEY) — the
ledger's O(1) verify cache is disabled, so S5 is worst-case for the
ledger path (see notes). S5 warmup is %d, not the global %d (every S5
call appends to the ledger and re-verifies it O(n) under the dev key,
so a full warmup would dominate wall time at 64 threads).

%s
### F74 verification note

%s
### Refused-sweep reproducibility (Round-16 F69 shape)

1 cold sweep + 5 warm sweeps per entry count, fresh executor per sweep,
F51 disturbance shape (directory at `approvals.lock`), coalesce sidecar
re-corrupted before each sweep. Recorded 2026-09-22 (post-fix): 2k ->
2-13ms; 10k -> 15-56ms; 20k -> 30-73ms warm.

%s
### Reading the numbers
- S3/S6 assert correctness under contention: S3 `verify_chain()` passes
  after the shared-log run (F25 flock serialization holds); S6 executes
  each pre-approved record exactly once despite racing sweeps.
- Dev-key caveat: under a real GOV_LOG_KEY the ledger's sig cache makes
  `require_verified()` O(1) between writes; every number above is the
  worst case for the ledger path.
""" % (date, WARMUP, ",".join(str(t) for t in THREADS),
       M["S1"], M["S2"], M["S3"], M["S4"], M["S5"],
       int(os.environ.get("BENCH_S5_WARMUP", "5")), WARMUP,
       table, f74note, rtable)

    path = REPO_ROOT / "BENCHMARKS.md"
    with open(path, "a", encoding="utf-8") as f:
        f.write(section)
    print(section)
    print("appended concurrent-load results to BENCHMARKS.md")


if __name__ == "__main__":
    main()
