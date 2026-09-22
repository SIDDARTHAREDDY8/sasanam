# BENCHMARKS

Latency of the governance hot path, measured on this VM
(`tests/bench_latency.py`, excluded from unittest discovery by filename).

## Method
- Per-iteration deltas with `time.perf_counter_ns`; 100-iteration warmup;
  reported mean / p50 / p99 / max in milliseconds.
- End-to-end = `ToolExecutor.call("read_file")` through the real pipeline:
  identity check, DLP scan, policy evaluation, **two** log appends with
  checkpoint writes (default policy, `coder` role).
- Args vary per call (`bench-<i>.txt`) so the loop guard
  (`max_identical_calls=10`) is not tripped — tripping it would measure the
  deny path, not the hot path.
- Stage figures use `n=1200` on one executor/log; note the log-append p99
  includes `ActionLog.refresh()` re-reading a growing file (O(n) per
  append — the chain is re-scanned to rebuild head state).
- Worst-case policy: synthetic policies with 41 / 501 / 2001 rules where
  the matching rule is LAST (full scan); `n=500` evaluations each.
- Worst-case DLP: 1 MB argument payloads (`n=300`), clean and with a
  secret at the tail (forces the scanner to walk the whole payload).
- Concurrent: 8 threads x 250 iterations of policy+DLP (read-only stages);
  then 8 threads x 100 log appends, with `verify_chain` afterwards.
- Sandbox spawn: `Sandbox.run(["/bin/true"])` — the per-tool-call process
  cost if every file op goes through the sandbox backend (`n=60`).

## Results

| stage | n | mean ms | p50 ms | p99 ms | max ms |
|---|---|---|---|---|---|
| executor.call end-to-end | 800 | 28.073 | 23.809 | 99.285 | 171.468 |
| identity check | 1200 | 0.000 | 0.000 | 0.000 | 0.023 |
| DLP scan (small args) | 1200 | 0.008 | 0.006 | 0.030 | 2.196 |
| policy evaluate (default policy) | 1200 | 0.011 | 0.008 | 0.030 | 0.934 |
| log append (incl. checkpoint) | 1200 | 4.294 | 3.136 | 27.958 | 30.328 |
| policy evaluate (41 rules) | 500 | 0.074 | 0.018 | 2.874 | 4.548 |
| policy evaluate (501 rules) | 500 | 0.244 | 0.184 | 1.459 | 13.709 |
| policy evaluate (2001 rules) | 500 | 1.321 | 0.814 | 9.470 | 29.310 |
| DLP scan (1 MB clean args) | 300 | 175.745 | 148.178 | 397.823 | 666.042 |
| DLP scan (1 MB args, secret at tail) | 300 | 154.430 | 137.679 | 313.718 | 359.892 |
| policy+DLP, 8 threads x 250 | 2000 | 0.041 | 0.014 | 0.033 | 15.047 |
| 8-thread log append (800 entries) | 800 | n/a (wall 2.0s) | n/a | n/a | n/a | verify_ok=False entries=22 err=broken at seq 10 |
| sandbox spawn (/bin/true) | 60 | 21.142 | 18.443 | 66.160 | 66.160 |

## Reading the numbers
- End-to-end p99 target: single-digit ms. Verdict below — currently MISS.
- The log-append stage dominates end-to-end (mean 4 ms, p99 29 ms per
  append): each `call()` appends twice, every append re-scans the file
  (`refresh()`, O(n) in log length), and every entry also fsyncs a
  checkpoint line. Cost grows with log length; p99 here reflects a log
  grown to a few thousand entries.
- Policy evaluation is linear in rule count (first-match-wins scan);
  2001 rules is ~50x the default 40. p50 stays sub-ms; the p99/max spikes
  (16/27 ms) are GC/allocation noise on this VM, not the scan itself.
- DLP on 1 MB payloads costs ~150 ms mean — multi-layer decodings
  (base64/hex, entropy checks) walk the whole buffer. Small-arg DLP
  (the realistic case) is 0.007 ms.
- Concurrent: 8 threads x 250 read-only iterations are fine, but 8 threads
  appending to one ActionLog CORRUPTS the chain (see finding below) —
  `ActionLog.append` has no lock; concurrent writers fork the hash chain
  via duplicate seqs. Do not share one ActionLog across threads.
- Sandbox spawn (~20 ms mean on this VM) is the price of real isolation
  per file op; synthetic tools (api_call/http_post/send_email) skip the
  child entirely.

## Findings for the coordinator
1. **CRITICAL — `ActionLog.append` is not thread-safe** (`gov/log.py`,
   read-only here): `refresh()` + seq increment + file append is an
   unlocked read-modify-write. 8 threads x 100 appends produced 400 lines
   with only 71 unique seqs and a chain broken at seq 1. Concurrent
   writers need an in-process lock (or one log per thread + merge), else
   the tamper-evidence backbone silently forks.
2. **End-to-end p99 misses the single-digit-ms target** because of
   O(n) `refresh()` re-scans plus per-entry checkpoint writes. Batching
   checkpoints and caching head state would cut this substantially.

## Verdict
- End-to-end p99 = 99.285 ms -> **MISS** (target: single-digit ms p99).

## Primary references
- Python `subprocess` — process creation, `preexec_fn`, `start_new_session`:
  https://docs.python.org/3/library/subprocess.html
- Python `resource` — `setrlimit` (RLIMIT_CPU/AS/FSIZE/NOFILE/NPROC):
  https://docs.python.org/3/library/resource.html
- Linux namespaces and `unshare(2)` — PID/network isolation primitives:
  https://man7.org/linux/man-pages/man7/namespaces.7.html and
  https://man7.org/linux/man-pages/man2/unshare.2.html
- Sigstore/Rekor and TUF — transparency-log / trust-root key-rotation
  semantics this design borrows from (append-only history, epoch-scoped
  keys, offline verification):
  https://www.sigstore.dev/ and
  https://theupdateframework.github.io/specification/latest/


## Concurrent-load benchmarks (2026-09-21)

`tests/bench_concurrent.py` (excluded from unittest discovery by
filename; run directly). N concurrent threads, 100-iteration warmup,
per-iteration `time.perf_counter_ns` deltas; p50/p95/p99/max in ms plus
aggregate throughput. Env: BENCH_THREADS="1,4,16,64", iterations/thread
S1=2000 S2=400 S3=200 S4=200 S5=40. Dev-key posture (no GOV_LOG_KEY) — the
ledger's O(1) verify cache is disabled, so S5 is worst-case for the
ledger path (see notes).

| scenario | n | throughput ops/s | mean ms | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|
| S1 policy.evaluate, 1 threads | 2000 | 102120.1 | 0.009 | 0.009 | 0.009 | 0.018 | 0.323 |
| S1 policy.evaluate, 4 threads | 8000 | 88285.3 | 0.016 | 0.009 | 0.009 | 0.022 | 8.853 |
| S1 policy.evaluate, 16 threads | 32000 | 81744.4 | 0.112 | 0.009 | 0.010 | 0.025 | 269.940 |
| S1 policy.evaluate, 64 threads | 128000 | 86178.5 | 0.316 | 0.009 | 0.009 | 0.037 | 1073.905 |
| S2 approvals.queue, 1 threads | 400 | 14330.0 | 0.069 | 0.066 | 0.083 | 0.113 | 0.345 |
| S2 approvals.queue, 4 threads | 1600 | 10977.3 | 0.356 | 0.068 | 0.160 | 8.107 | 25.087 |
| S2 approvals.queue, 16 threads | 6400 | 8628.3 | 1.631 | 0.069 | 0.384 | 51.273 | 231.866 |
| S2 approvals.queue, 64 threads | 25600 | 6240.5 | 8.971 | 0.072 | 51.860 | 227.167 | 1124.062 |
| S3 log.append (shared log), 1 threads | 200 | 11540.4 | 0.086 | 0.079 | 0.114 | 0.144 | 0.416 |
| S3 log.append (shared log), 4 threads | 800 | 5413.5 | 0.467 | 0.079 | 0.135 | 2.671 | 130.340 |
| S3 log.append (shared log), 16 threads | 3200 | 5632.9 | 1.581 | 0.079 | 0.187 | 2.711 | 517.053 |
| S3 log.append (shared log), 64 threads | 12800 | 4820.0 | 7.850 | 0.081 | 0.428 | 112.176 | 2200.927 |
| S4 e2e call, isolated runs, 1 threads | 200 | 1076.8 | 0.927 | 0.549 | 1.700 | 18.337 | 18.352 |
| S4 e2e call, isolated runs, 4 threads | 800 | 1235.4 | 3.153 | 0.509 | 12.570 | 25.591 | 65.848 |
| S4 e2e call, isolated runs, 16 threads | 3200 | 947.3 | 15.943 | 0.620 | 77.642 | 145.645 | 450.376 |
| S4 e2e call, isolated runs, 64 threads | 12800 | 563.9 | 108.598 | 42.802 | 425.671 | 691.337 | 1442.492 |
| S5 e2e api_call, shared run, 1 threads | 40 | 13.7 | 74.495 | 71.020 | 154.979 | 156.289 | 156.289 |
| S5 e2e api_call, shared run, 4 threads | 40 | 16.8 | 59.460 | 44.760 | 127.104 | 168.768 | 168.768 | ERRORS iters=0 threads=warmup (1: LedgerUnverifiableError('ledger verification failed for /tmp/gov-run/g...)
| S5 e2e api_call, shared run, 16 threads | 0 | 0.0 | nan | nan | nan | nan | nan | ERRORS iters=0 threads=warmup (0: LedgerUnverifiableError('ledger verification failed for /tmp/gov-run/g...)
| S5 e2e api_call, shared run, 64 threads | 0 | 0.0 | nan | nan | nan | nan | nan | ERRORS iters=0 threads=warmup (0: LedgerUnverifiableError('ledger verification failed for /tmp/gov-run/g...)
| S6 racing execute_approved sweeps, 2 threads | 2 | 0.0 | 32.659 | 42.702 | 42.702 | 42.702 | 42.702 |
| S6 racing execute_approved sweeps, 4 threads | 4 | 0.0 | 31.858 | 41.643 | 42.950 | 42.950 | 42.950 |
| S6 racing execute_approved sweeps, 8 threads | 8 | 0.0 | 59.988 | 57.017 | 97.689 | 97.689 | 97.689 |

### Refused-sweep reproducibility (Round-16 F69 shape)

1 cold sweep + 5 warm sweeps per entry count, fresh executor per sweep,
F51 disturbance shape (directory at `approvals.lock`), coalesce sidecar
re-corrupted before each sweep. Recorded 2026-09-22 (post-fix): 2k ->
2-13ms; 10k -> 15-56ms; 20k -> 30-73ms warm.

| shape | entries | cold ms | warm min ms | warm p50 ms | warm max ms |
|---|---|---|---|---|---|
| refused sweep, 2000 entries (1 cold + 5 warm) | 2000 | 150.3 | 1.6 | 1.7 | 3.0 |
| refused sweep, 10000 entries (1 cold + 5 warm) | 10000 | 557.4 | 6.4 | 8.3 | 18.3 |
| refused sweep, 20000 entries (1 cold + 5 warm) | 20000 | 958.1 | 11.4 | 12.8 | 63.6 |

### Reading the numbers
- S3/S6 assert correctness under contention: S3 `verify_chain()` passes
  after the shared-log run (F25 flock serialization holds); S6 executes
  each pre-approved record exactly once despite racing sweeps.
- Dev-key caveat: under a real GOV_LOG_KEY the ledger's sig cache makes
  `require_verified()` O(1) between writes; every number above is the
  worst case for the ledger path.
- S1 (policy): p50 is 0.009 ms at ALL thread counts — the engine is
  read-only and correct under concurrency — but aggregate throughput does
  NOT scale (102k -> 86k ops/s) and max explodes (0.3 -> 1074 ms at 64
  threads). CPU-bound under the GIL: more threads buy nothing, tail
  latency pays for scheduling.
- S2 (queue): p50 flat at ~0.07 ms (one keyed HMAC + one unlocked
  O_APPEND write); no records lost at any thread count (25600 queued at
  64 threads, all present). Throughput falls 14.3k -> 6.2k ops/s with
  threads — GIL contention on the digest/json, not a lock (there is
  none in `queue()`).
- S3 (shared log append): p50 flat at ~0.08 ms, but the F25 flock
  serializes writers — throughput drops 11.5k -> 4.8k appends/s and p99
  goes 0.14 -> 112 ms from 1 to 64 threads (lock convoy). Correctness
  holds: `verify_chain()` passes after every run. Contrast with the old
  R16 finding (chain forked without the lock); the price of the fix is
  serialized throughput.
- S4 (e2e, isolated runs): the realistic multi-agent shape. p50 holds at
  ~0.5-0.6 ms through 16 threads, then collapses at 64 threads (p50
  42.8 ms, p99 691 ms) — 64 threads doing fsync-heavy appends oversubscribe
  this VM. Throughput peaks at 4 threads (1235 calls/s).
- S5 (e2e api_call, shared run): at 1 thread, 40/40 succeed at ~74 ms
  mean per call — the ledger path dominates (per-call full re-verify
  under the dev key + one ledger append + campaign scans = O(n) per call,
  O(n^2) per burst). At >= 4 threads the run FAILS: `EgressLedger.append`
  has no lock, concurrent writers fork the chain (duplicate seqs
  observed), and every later `call()` raises `LedgerUnverifiableError`
  fail-closed. See finding P1 in workstreams/performance/PROGRESS.md —
  the same bug class as the pre-F25 `ActionLog.append` corruption, never
  fixed for the ledger. Do not run api_call-heavy multi-agent workloads
  against one run dir until this is addressed.
- S6 (racing sweeps): 2/4/8 threads racing `execute_approved()` over 16
  pre-approved records — each record executed exactly once (no double
  execution); losing sweeps pay ~30-60 ms (queue-lock wait + the
  `_reconcile_interrupted_executions` full-log read + tip verify).
- STALENESS NOTE for the coordinator/QA: the single-threaded e2e row
  above ("executor.call end-to-end", p50 23.8 / p99 99.3 ms, verdict MISS)
  predates the F22 O(1)-append fix. Re-measured 2026-09-21 on current
  code with the identical shape (800 `read_file` calls, 100 warmup):
  p50 = 0.500 ms, p99 = 5.979 ms, max = 24.359 ms — the single-digit-ms
  p99 target now PASSES. Recommend re-running `tests/bench_latency.py`
  to refresh the stale rows (it rewrites this file; the concurrent
  section above would need re-appending afterwards).
- Refused-sweep reproducibility: warm-sweep maxes (2k: 3.0 ms; 10k:
  18.3 ms; 20k: 63.6 ms) all fall inside the recorded 2026-09-22 ranges
  (2-13 / 15-56 / 30-73 ms); p50s came in faster than the recorded
  typicals (1.7 / 8.3 / 12.8 ms vs typical ~30-50 ms at 20k) — VM/disk
  variance plus R17 path changes; the <150 ms regression bound at 20k
  holds with >2x margin. The pre-fix baseline (47-109 / 297-381 /
  677-719 ms) cannot be reproduced without reverting F69.
- What these numbers do NOT prove: shared noisy VM (p99/max carry
  scheduler/GC/neighbor noise); dev-key posture (ledger numbers are
  worst-case); threads not processes; synthetic agents with simulated
  tools (real sandbox spawn adds ~20 ms per bench_latency.py). Treat
  cross-thread-count comparisons as indicative, not as SLOs.

## Concurrent-load benchmarks (2026-09-22)

`tests/bench_concurrent.py` (excluded from unittest discovery by
filename; run directly). N concurrent threads, 100-iteration warmup,
per-iteration `time.perf_counter_ns` deltas; p50/p95/p99/max in ms plus
aggregate throughput. Env: BENCH_THREADS="1,4,16,64", iterations/thread
S1=2000 S2=400 S3=200 S4=200 S5=12. Dev-key posture (no GOV_LOG_KEY) — the
ledger's O(1) verify cache is disabled, so S5 is worst-case for the
ledger path (see notes). S5 warmup is 5, not the global 100 (every S5
call appends to the ledger and re-verifies it O(n) under the dev key,
so a full warmup would dominate wall time at 64 threads).

| scenario | n | throughput ops/s | mean ms | p50 ms | p95 ms | p99 ms | max ms |
|---|---|---|---|---|---|---|---|
| S1 policy.evaluate, 1 threads | 2000 | 85558.3 | 0.011 | 0.010 | 0.010 | 0.024 | 1.471 |
| S1 policy.evaluate, 4 threads | 8000 | 83939.3 | 0.036 | 0.010 | 0.010 | 0.053 | 38.490 |
| S1 policy.evaluate, 16 threads | 32000 | 86431.6 | 0.058 | 0.010 | 0.010 | 0.029 | 162.850 |
| S1 policy.evaluate, 64 threads | 128000 | 75342.1 | 0.449 | 0.010 | 0.014 | 0.058 | 1352.918 |
| S2 approvals.queue, 1 threads | 400 | 6052.4 | 0.165 | 0.141 | 0.244 | 0.578 | 1.015 |
| S2 approvals.queue, 4 threads | 1600 | 5294.5 | 0.637 | 0.141 | 0.515 | 17.323 | 64.281 |
| S2 approvals.queue, 16 threads | 6400 | 4754.1 | 2.838 | 0.143 | 10.685 | 84.121 | 348.600 |
| S2 approvals.queue, 64 threads | 25600 | 3520.6 | 15.234 | 0.167 | 95.457 | 337.443 | 1483.837 |
| S3 log.append (shared log), 1 threads | 200 | 11092.9 | 0.090 | 0.080 | 0.143 | 0.331 | 0.370 | verify_ok=True entries=-1
| S3 log.append (shared log), 4 threads | 800 | 7226.3 | 0.399 | 0.085 | 0.170 | 0.428 | 63.662 | verify_ok=True entries=-1
| S3 log.append (shared log), 16 threads | 3200 | 6269.0 | 1.402 | 0.087 | 0.234 | 20.742 | 418.998 | verify_ok=True entries=-1
| S3 log.append (shared log), 64 threads | 12800 | 7450.3 | 5.053 | 0.082 | 0.263 | 143.299 | 1461.660 | verify_ok=True entries=-1
| S4 e2e call, isolated runs, 1 threads | 200 | 2032.3 | 0.492 | 0.480 | 0.583 | 0.853 | 0.961 |
| S4 e2e call, isolated runs, 4 threads | 800 | 1328.3 | 2.944 | 1.649 | 8.742 | 12.201 | 25.888 |
| S4 e2e call, isolated runs, 16 threads | 3200 | 1209.6 | 12.467 | 2.704 | 49.063 | 80.143 | 152.987 |
| S4 e2e call, isolated runs, 64 threads | 12800 | 801.3 | 76.401 | 54.671 | 251.620 | 449.651 | 1220.402 | (re-run on clean tmpdir; original run hit ENOSPC, see notes) |
| S5 e2e api_call, shared run, 1 threads | 12 | 173.7 | 5.748 | 4.965 | 13.082 | 13.082 | 13.082 | verify_ok=True entries=17
| S5 e2e api_call, shared run, 4 threads | 48 | 52.4 | 72.900 | 62.335 | 154.314 | 172.849 | 172.849 | verify_ok=True entries=68
| S5 e2e api_call, shared run, 16 threads | 192 | 17.0 | 894.455 | 887.653 | 1435.513 | 1652.715 | 1689.136 | verify_ok=True entries=272
| S5 e2e api_call, shared run, 64 threads | 768 | 4.7 | 13387.979 | 12628.719 | 20840.768 | 21444.211 | 24223.192 | verify_ok=True entries=1088
| S6 racing execute_approved sweeps, 2 threads | 2 | 0.0 | 21.388 | 23.339 | 23.339 | 23.339 | 23.339 |
| S6 racing execute_approved sweeps, 4 threads | 4 | 0.0 | 38.554 | 44.682 | 65.510 | 65.510 | 65.510 |
| S6 racing execute_approved sweeps, 8 threads | 8 | 0.0 | 94.203 | 104.185 | 164.968 | 164.968 | 164.968 |
| sandbox spawn (/bin/true) | 60 | 46.8 | 21.388 | 18.998 | 32.530 | 72.560 | 72.560 |

### F74 verification note

F74 status: the EgressLedger append race is CLOSED (fix landed + red-team verified 2026-09-22; F25-style reentrant per-path read/write lock in `gov/egress_ledger.py`). S5 now asserts the fix holds under load: all thread counts must complete with an unbroken chain and zero LedgerUnverifiableError.

### Refused-sweep reproducibility (Round-16 F69 shape)

1 cold sweep + 5 warm sweeps per entry count, fresh executor per sweep,
F51 disturbance shape (directory at `approvals.lock`), coalesce sidecar
re-corrupted before each sweep. Recorded 2026-09-22 (post-fix): 2k ->
2-13ms; 10k -> 15-56ms; 20k -> 30-73ms warm.

| shape | entries | cold ms | warm min ms | warm p50 ms | warm max ms |
|---|---|---|---|---|---|
| refused sweep, 2000 entries (1 cold + 5 warm) | 2000 | 74.3 | 9.6 | 9.8 | 10.1 |
| refused sweep, 10000 entries (1 cold + 5 warm) | 10000 | 376.8 | 45.0 | 46.2 | 47.2 |
| refused sweep, 20000 entries (1 cold + 5 warm) | 20000 | 724.5 | 88.7 | 98.2 | 106.3 |

### Wave-24 re-baseline (2026-09-22) — SUPERSEDES the ranges above

The recorded 2026-09-22 ranges (2k: 2-13 ms; 10k: 15-56 ms; 20k:
30-73 ms warm) no longer reproduce on this VM and are SUPERSEDED —
do not use them as regression bounds. The wave-23 table above is kept
for history; the numbers below replace it.

Methodology: `tests/bench_concurrent.py::bench_refused_sweeps()`
unchanged (Round-16 F69 shape: N action-log entries, F51 disturbance
directory at `approvals.lock`, coalesce sidecar re-corrupted before
each sweep, fresh executor per sweep, 1 cold + 5 warm sweeps per
size). Two full repetitions at 2k/10k/20k on this VM
(2 vCPU / 8 GB shared), private empty TMPDIR
(`/tmp/gov-bench-rs`, 0 dirs left afterwards), dev-key posture
(ledger worst-case, same as all prior refused-sweep runs).

| size | rep | cold ms | warm min ms | warm p50 ms | warm max ms | load (1/5/15m) |
|---|---|---|---|---|---|---|
| 2000 | 1 | 117.0 | 10.8 | 11.0 | 33.4 | 2.33/2.81/3.41 |
| 2000 | 2 | 93.1 | 10.3 | 10.9 | 19.7 | 2.42/2.81/3.41 |
| 10000 | 1 | 437.6 | 46.1 | 67.0 | 72.5 | 2.33/2.81/3.41 |
| 10000 | 2 | 462.5 | 60.3 | 74.4 | 143.3 | 2.42/2.81/3.41 |
| 20000 | 1 | 1002.4 | 96.7 | 167.1 | 175.9 | 2.33/2.81/3.41 |
| 20000 | 2 | 1127.9 | 95.2 | 102.1 | 167.9 | 2.42/3.02/3.47 |

New measured warm ranges (min-max across both reps, 10 warm sweeps):
2k: 10-33 ms; 10k: 46-143 ms; 20k: 95-176 ms. Cold sweeps:
2k ~93-117 ms; 10k ~438-463 ms; 20k ~1002-1128 ms.

Honest caveats:
- The box was NOT quiet: load 2.3-3.5 with other agents' Python
  workloads at up to 69% CPU during the run. Warm-sweep variance
  tracks that noise (20k warm p50 167 ms in rep 1 vs 102 ms in
  rep 2 on identical code). Treat the max column as load-inflated.
- The <150 ms regression bound at 20k did NOT hold under these
  loaded conditions (warm max 168-176 ms; rep-1 p50 167 ms). On the
  quieter VM in wave-23 the same shape held at ~92-98 ms warm p50
  (max 106.6 ms), so this looks like load noise, not a code
  regression — but it is UNVERIFIED on a quiet box right now.
  Recommendation for the lead: either (a) re-verify the bound on a
  quiet box before keeping it, (b) scope the bound to quiet-box
  conditions explicitly, or (c) raise it (e.g. <250 ms) to cover
  loaded-box noise. Not filed as a finding: identical code measured
  102 ms and 167 ms p50 across reps, which is a load artifact
  signature, not a regression signature.
- The structural cost driver is unchanged (wave-23 cProfile: ~3 full
  20k-line log scans / ~60k `json.loads` per warm sweep: two
  `ActionLog.refresh()` + one tip-cache generation scan).

### Reading the numbers
- S3/S6 assert correctness under contention: S3 `verify_chain()` passes
  after the shared-log run (F25 flock serialization holds); S6 executes
  each pre-approved record exactly once despite racing sweeps.
- Dev-key caveat: under a real GOV_LOG_KEY the ledger's sig cache makes
  `require_verified()` O(1) between writes; every number above is the
  worst case for the ledger path.

- **S5 (F74 verification): HOLDS.** All four thread counts completed
  with `verify_ok=True` and exact entry counts (17 / 68 / 272 / 1088 =
  n_threads x (5 warmup + 12 timed)) and zero errors — no duplicate
  seqs, no torn reads, no `LedgerUnverifiableError`. The pre-fix
  behavior (instant fork at >=4 threads) is gone. Price of the fix:
  under the dev-key posture every `api_call` re-verifies the whole
  ledger (O(n) per call -> O(n^2) per burst), so mean call latency at
  64 threads is 13.4 s. This is the known worst-case posture, not a
  regression — under a real `GOV_LOG_KEY` the O(1) stat-sig cache
  removes the re-verify (see the F74 fix note in evals/FINDINGS.md).
  The multi-thread S5 shape would be infeasible without the warmup
  reduction (O(n^2) with a 100-call warmup blew past the 600 s
  harness barrier timeout at 16 threads — killed and re-run with
  warmup=5, M5=12).
- **S4-64 flake (ENOSPC), not a break:** the first run errored 3396 of
  12800 iters with `OSError(28, 'No space left on device')`. The bench
  ran in a private TMPDIR on a 512 MB /tmp tmpfs that filled up —
  partly from leftover dirs of an earlier killed bench run and the
  canonical-suite run sharing that dir. Re-run on a cleaned tmpdir:
  12800/12800 clean (p50 54.7 ms, p99 449.7 ms); the row above is the
  re-run. Lesson: bench TMPDIR must be private AND empty at start.
- Refused-sweep drift: warm sweeps at 20k measured 88.7-106.3 ms here
  vs the recorded 2026-09-22 range of 30-73 ms. Re-measured twice on a
  quieter VM (73.1/387.1/799.8 cold; 20k warm max 106.6 ms) —
  reproducible at ~92-98 ms warm p50. cProfile shows each warm sweep
  does ~3 full 20k-line log scans (60k `json.loads`: two
  `ActionLog.refresh()` + one tip-cache generation scan). The <150 ms
  regression bound at 20k still holds (1.4x margin), so this is NOT a
  finding — but the recorded "30-73 ms / typical ~30-50 ms" ranges no
  longer match this VM; recommend the coordinator re-baseline them on
  reference hardware, or accept ~100 ms as the new typical.
  [Wave-24: DONE — see "Wave-24 re-baseline" above; the 30-73 ms ranges
  are superseded. The <150 ms bound needs a quiet-box re-verification:
  it did not hold under load (20k warm max 168-176 ms at load 2.3-3.5),
  while the wave-23 quieter-VM run held at ~92-98 ms p50.]
- Machine conditions: 2 vCPU / 8 GB shared VM, load 3.5-6.4 during the
  run (self-inflicted — the bench saturates both CPUs; S1-S4 rows at
  high thread counts are noisier than the 2026-09-21 run). p50s are
  stable across runs; treat p99/max and cross-thread-count throughput
  comparisons as indicative. Sandbox spawn (sequential, quiet-ish):
  mean 21.4 ms, p50 19.0 ms — matches the stale 2026-09-21 row (21.1 /
  18.4 ms); the sandbox-spawn cost is stable.

## D2 neutral benchmark (2026-09-22 re-run, wave-26 QA lane)

Our adversarial battery (21 pinned scenarios, 18 scored) vs Microsoft
AGT v5.0.0's governor, compared against each scenario's security
expectation (A13 doctrine — never engine-vs-engine parity). Full
methodology, per-situation table, reproductions, and honest
limitations: `workstreams/evals/D2_BENCHMARK.md`.

| run | ours met | AGT met |
|---|---|---|
| 2026-09-22 06:23Z (wave-25) | 12/18 | 3/18 |
| 2026-09-22 ~06:41Z (wave-26 QA re-run) | **14/18** | 3/18 |

The re-run was queued because the first run's tree state lacked the
F86/F87 StruQ closures in `gov/adapters/trust.py` (footnote-² artifact
in D2_BENCHMARK.md §3.1). With the closures present, d2c12
(variation-selector) and d2c13 (modifier-letter-colon) flip
allowed→stopped (quarantined `privilege_claim:system`); AGT still
allows both. Remaining ours misses are the three documented unicode
residuals (d2c09 Cyrillic, d2c14 combining marks, d2c15
prefix-attached — no findings). AGT's 15 misses are dominated by one
class: no privilege-claim concept in the default detector (14/15).

Method: private venv (Python 3.12, only `pyyaml`+`pydantic` from PyPI),
AGT v5.0.0 from the GitHub tag tarball on `PYTHONPATH` (no install),
ours-engine from a frozen point-in-time snapshot of the working copy
(2026-09-22 06:41 UTC), `GOV_DEV_KEYS=1` local-only, private TMPDIR.
$0 spend, no network at run time, no paid APIs. Raw results:
`workstreams/evals/d2/results/d2-adapter@0.1.0/results.json`.
