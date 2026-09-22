# Flake Tracker — known timing-sensitive probes and tests

**Purpose:** this file is the permanent registry of *known* timing-sensitive
probe/test failures in this repo. It exists for two reasons:

1. **Stop re-investigating known flakes.** When a gate goes red, check here
   first; a failure matching a documented signature gets the documented
   disposition instead of a fresh root-cause expedition.
2. **Catch a real regression hiding behind the "known flake" label.** Every
   entry records a *signature* (the exact failing assertion and failure
   shape), not just a name. A failure that does not match the signature —
   a different assertion, a failure in isolation, a new failure mode — is
   **not** the known flake and must be investigated as a potential
   regression. The triage procedure below makes this mechanical.

**Rule:** "known flake" is never a dismissal. It is a *claim* with three
conjuncts — (a) the failure matches a documented signature, (b) the failing
situation passes in isolation on a quiet tree, (c) the wave's changes have
zero code-path intersection with the failing path. All three are required.
If any one fails, it is not the known flake: investigate.

## Triage procedure (mechanical, run on every red gate)

1. **Record the exact failure**, not just the situation name: which cell
   (adapter × privilege × harness), which assertion/line, which exception or
   bound, stdout/stderr around it. Names move between runs; signatures do
   not.
2. **Match against the registry below.** Compare the failing assertion and
   failure shape to the documented signature. A different assertion in the
   same probe (e.g. sit64 failing on `fresh_executor_refuses_on_policy_change`
   instead of `chain_verifies_after_concurrent_writes`) is **not** the
   known flake — it is a new failure mode.
3. **Isolation check.** Re-run the failing situation/probe in isolation on a
   quiet tree (no other lanes running, private TMPDIR). The documented
   signature requires 12/12 (or equivalent) in isolation. A failure in
   isolation is a regression signal, full stop.
4. **Code-path intersection check.** List the code paths the failing probe
   exercises (`gov/log.py` for chain verification, `gov/adapters/trust.py`
   for StruQ, etc.) and intersect with the wave's diff. The known flake
   requires zero intersection. If the wave touched the failing path, the
   failure is *guilty until proven innocent*: prove it with a
   differential old-vs-new run (the wave-25 F86 closure lane's 1140+20000
   input proof is the template), not with the label.
5. **Disposition.** Only when (2)+(3)+(4) all hold: record the flake in
   BUILD_LOG.md, re-run the gate on a quiet tree, and move on. Otherwise:
   suite red halts feature work — investigate and, if a genuine miss,
   file a finding.

## Known-flake registry

### FK-1 — sit64 concurrent-append chain verification
- **Probe:** `_w11_rundir_toctou` (sit64), sub-assertion
  `chain_verifies_after_concurrent_writes` (`evals/w11_probes.py`).
- **What it does:** 4 processes × 25 concurrent `ActionLog` appends, then
  `verify_chain()` immediately after `join(60)`.
- **Signature:** `concurrent_appends_all_ok` is True (all 100 bytes landed),
  but `chain_verifies_after_concurrent_writes` is False — the verification
  raced a still-flushing writer, or a child had not fully exited when
  `join(60)` returned. Deterministic assertions of the same probe
  (`queue_follows_symlink`, `fresh_executor_refuses_on_policy_change`,
  …) all pass. Passes 12/12 in isolation on a quiet tree.
- **NOT the flake:** a failure in `queue_follows_symlink`,
  `fresh_executor_refuses_on_policy_change`, or `approval_policy_stale`
  auditing; a failure that reproduces in isolation; a failure where
  `concurrent_appends_all_ok` is False (that means bytes were lost — a
  real integrity problem).
- **History:** wave-25 (BUILD_LOG: "moves between runs; passes in
  isolation"), wave-27 (12-cell move), wave-41 (matrix first run
  3192/3216; isolated 12/12; quiet-tree re-run 3216/3216 GREEN).

### FK-2 — F25 concurrent writer chain verification
- **Probe:** `_w7_concurrent` (`evals/run_evals.py`), key `chain_verifies`.
- **What it does:** 2 barrier-synchronized processes × 300 appends, then
  `verify_chain()`.
- **Signature:** `all_bytes_land`, `json_intact`, `seqs_unique` all True,
  but `chain_verifies` False. Same race shape as FK-1. Passes in
  isolation; failing bytes/seqs are NOT the flake (data-loss signal).
- **History:** same class as FK-1; recorded wave-42 to pin the
  distinction (verification-race vs write-loss).

### FK-3 — F69 warm-tip sweep absolute timing bound
- **Test:** `tests/test_hardening_r16.py::TestWarmTip::test_warm_tip_refused_sweep_bounded_at_20k`.
- **What it does:** asserts a refused sweep with a warm tip completes in
  < 0.150 s.
- **Signature:** measured time marginally over the bound (e.g. 153.2 ms
  vs 150 ms), with no functional assertion failing — the sweep still
  refuses correctly, the count is right, only the wall clock missed.
  Reproduces under CPU contention, not in isolation on a quiet tree.
- **NOT the flake:** a sweep that fails to refuse, a count mismatch, or a
  miss by a large factor (>2× suggests an algorithmic regression, not
  jitter).
- **History:** wave-27 (153.2 ms vs 150 ms, parent-confirmed
  environmental); wave-42 (166.2 ms vs 150 ms — canonical suite ran
  while box was under load from web searches; green in isolation,
  2026-09-22).

### FK-4 — concurrent-lane tmpdir pollution
- **Tests:** `test_retry_attempts_each_mediated`, `test_policy_export`
  refusal pins (wave-25); any probe showing `FileNotFoundError` inside a
  `_tmp`-style helper.
- **What it does:** tempfile path assumptions break when lanes share
  `/tmp/gov-run`.
- **Signature:** `FileNotFoundError` / `FileExistsError` on temp paths,
  or errors mentioning another lane's prefix (e.g. an unknown_grant /
  parent-grant-not-found in a probe that never creates grants). Vanishes
  with a private TMPDIR and sequential gates. **Prevention, not just
  recognition:** always `mkdir -p` the TMPDIR before launching
  (tempfile falls back to shared /tmp when TMPDIR does not exist), and
  never run suite + matrix concurrently.
- **NOT the flake:** the same error with a private TMPDIR and no other
  lanes running — that is a real path-handling bug.
- **History:** wave-25 (4 unrelated failures under concurrent-lane load,
  all green in isolation), wave-27 (accidental backgrounded
  `run_evals.py --help` polluted the shared TMPDIR).

## Maintenance

- Add a row when a new timing-sensitive failure is *demonstrated* (signature
  + isolation + intersection evidence), not when one is suspected.
- If a documented signature ever fires while a wave *did* touch the failing
  path, open a finding instead of re-running: the signature's third
  conjunct (zero intersection) is what keeps this file honest.
