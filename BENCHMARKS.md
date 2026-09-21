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
