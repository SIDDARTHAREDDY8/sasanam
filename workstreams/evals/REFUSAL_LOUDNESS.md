# Refusal Loudness — Wave-62 Lane 1

**Open question from wave-61:** the LOG-tier production guard's refusal
is `SandboxError`-to-caller. A deployment that swallows the exception
and proceeds anyway runs uncaged and misconfigures silently *at the
caller layer*. The guard's whole value is loud refusal; if the caller
swallows it, the guard is theater. This lane earns its conclusion
through break-first, not assumption.

## 1. Break-first: what survives a swallowing caller?

Harness: `workstreams/evals/refusal_loudness_harness.py` (each case in a
fresh subprocess for honest stderr capture). Baseline measured against
the pre-wave-62 code (`/tmp/swallow_baseline.py`):

| refusal channel | pre-fix | post-fix |
|---|---|---|
| the `SandboxError` exception itself | **dead on swallow** (the only channel; 0 stderr bytes emitted, no receipt, workload ran uncaged) | still the primary contract — raised with the identical message |
| stderr write | did not exist | **survives** — `GOV-SANDBOX REFUSAL [seccomp-log-tier-guard] pid=…` written before raising; deployments capture stderr and a swallower that catches the exception rarely also redirects it (harness: `swallow_stderr_captured`) |
| structured refusal receipt (`<dir>/refusals.jsonl`) | did not exist | **survives even stderr suppression** — one JSONL line per refusal, written before raising (harness: `swallow_stderr_devnull_receipt`); opt-in via `refusal_receipt_dir=` kwarg or `GOV_SANDBOX_REFUSAL_DIR` env, kwarg wins |
| process exit | unchanged — `run()` raises, never exits | unchanged by design (see §3) |

Harness result post-fix: **7/7 cases pass**, including
`broken_sink_still_refuses` (sink path is a file → makedirs fails →
refusal still raises), `kwarg_wins_over_env`, `no_sink_by_default`
(stderr fires, zero files written), `uncaught_still_kills_process`
(traceback + record), and `legitimate_recovery_unbroken` (catch, then
explicit `deployment_mode="staging"` retry proceeds — the refusal
poisons nothing).

## 2. Design: the loudest channel without new audit machinery

Shipped (`gov/sandbox.py`): `_refuse_loud(message, *, kind,
receipt_dir, extra=None)` — one choke point for every fail-closed
refusal from `Sandbox.run()`:

1. **stderr record, unconditional.** One line:
   `GOV-SANDBOX REFUSAL [<kind>] pid=<pid>: <message>`. Cheap, and it
   survives the common swallower (try/except + proceed), because
   deployments capture the launcher's stderr.
2. **Structured receipt, opt-in.** `<refusal_receipt_dir>/refusals.jsonl`,
   one JSON object per line: `ts` (UTC), `kind`, `pid`,
   `deployment_mode` / `missing` (kind-dependent), `message`. Plain
   JSONL — deliberately *not* a hash-chained audit sink (wave-61
   declined threading audit machinery into `Sandbox`; that decision
   stands — the receipt is observability, not evidence).
3. **Then raise `SandboxError(message)`** — the exception contract is
   unchanged; loudness is additive, never a replacement.

Both emission steps are best-effort and fail-safe: any failure is
swallowed and the refusal still raises. A broken sink is observability
loss, never enforcement loss (pinned by
`test_broken_receipt_sink_still_refuses` and
`test_broken_stderr_still_refuses`).

Wired into all three fail-closed refusal sites in `run()`: the
wave-61 LOG-tier guard (`kind=seccomp-log-tier-guard`), the canary-plant
failure (`kind=canary-plant-failure`), and the required-layer-missing
refusal (`kind=required-layer-missing`). The `_make_preexec` internal
misuse guard is intentionally *not* routed through it — an internal
programming invariant, not a deployment-facing refusal.

Configuration: `Sandbox(..., refusal_receipt_dir=None)`; explicit
kwarg wins, else `GOV_SANDBOX_REFUSAL_DIR` (blank → disabled).
Documented in `sandbox_config_from_env()`'s docstring; the constructor
resolves it so `install_from_env` inherits it with no dict change. The
env var is observability config, not a security decision — the wave-61
"env is not authoritative" principle governs the *tier decision*, not
where a log line lands. A hostile env value can only misplace a
receipt, never weaken enforcement (the refusal raises regardless).

## 3. Deliberately not built

- **Fail-deadly process poisoning** (`os._exit`, poisoning later runs
  in the process): hostile to legitimate recovery. The supported flow
  is catch-and-remediate — e.g. catch the refusal, re-run with an
  explicit `deployment_mode="staging"` declaration — and the harness
  proves it still works. Killing the process on a caught exception
  would punish the deployments that handle the refusal correctly.
- **A hash-chained audit-log sink in `Sandbox`**: wave-61 declined it;
  the break-first evidence does not overturn that — the two cheap
  channels cover the realistic swallower shapes (exception-swallower,
  stderr-dropper). If a future wave shows a deployment class that
  suppresses stderr *and* cannot configure a receipt dir *and* swallows
  the exception, that is the evidence that would justify the sink.
- **Config-file authority / build-time constants**: same reasoning as
  wave-61 §1 — no such machinery exists; inventing it is new surface.

## 4. Residual boundary (documented, not a finding)

A caller that **deliberately** suppresses stderr *and* disables the
receipt sink *and* swallows the exception is outside the trust model —
the same class as wave-61's documented malicious-environment-writer
boundary (anyone who controls the launcher's environment can already
unset `GOV_SANDBOX_BACKEND`). Nothing in-process can stop a caller from
abandoning `Sandbox` entirely and exec'ing the workload raw; the
guard's contract is loud refusal *to the caller*, made observable to
the *deployment* through these channels. This is the deployment-hygiene
half of the answer the wave brief asked for: the mechanism (stderr +
receipt) covers the negligent swallower; the deliberately negligent
caller is a trust-model boundary, stated plainly.

## 5. Tests and probes

`RefusalLoudnessTest` (10 tests) in
`tests/test_sandbox_seccomp_cage.py` — all green. Registry:
`redteam.f81.refusal_loudness_*` (3 probes, expected: denied),
517 scenarios, 41 delegated to `tests/`.

**No misses → no finding filed; next free remains F128.** F81 stays
LOW/OPEN (the loudness work hardens the F81 guard's refusal; wall
closure still needs the composed wall + privileged-CI lanes D1–D4).
