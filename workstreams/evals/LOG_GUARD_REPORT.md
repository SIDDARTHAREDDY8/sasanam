# LOG-Tier Production Guard — Wave-61 Report

**Question (from wave-60 §3, "Operator hazard"):** the only control
stopping `GOV_SANDBOX_SECCOMP_LOG=1` from dissolving KILL default-deny
into log-and-execute in production was an honest run-note stamp —
audit, not prevention. An env var that silently downgrades a KILL
filter to LOG-and-execute is a fail-open seam, exactly the class this
project exists to kill.

**Verdict:** the guard is designed, implemented, and break-first
clean. No finding filed — every attack shape below was stopped by the
guard or closed as a documented boundary; next free finding number
remains **F128**.

## 1. Design (Lane 1)

Full design in `workstreams/evals/SECCOMP_LOG_SHAKEDOWN.md` §6. The
four required answers, in brief:

- **(a) Authority.** Precedence: explicit `Sandbox(...,
  deployment_mode=)` constructor kwarg (operator code) >
  `GOV_SANDBOX_DEPLOYMENT_MODE` env (operator-explicit launcher
  signal, mapped by `sandbox_config_from_env()`) > default
  `"production"`. `GOV_SANDBOX_SECCOMP_LOG=1` is demoted from
  authority to *request*: honored only in staging mode.
- **(b) "Production".** No deployment-mode flag existed; the
  least-privilege definition is `deployment_mode ∈
  {"production","staging"}`, default **production** — ambiguity
  defaults to KILL. Unknown values refuse at construction.
- **(c) Fail-closed direction.** production + LOG request →
  **refuse to launch loudly** (`SandboxError` naming the var, before
  jail creation), not "force KILL and continue": the contradiction is
  misconfiguration, and launching in either mode assumes intent we
  cannot know. Force-KILL would normalize the misconfiguration (the
  stray var persists; the note is the only trace — the stamp's
  failure mode moved, not fixed). Guard-internal failure → no launch.
- **(d) Testing.** The config-guard analog of byte-pinning is the
  exhaustive decision table (`_resolve_seccomp_tier` pure, every
  `(mode, request)` pair pinned) plus structural pins: exactly-one
  env read per run, tier-as-value through `_make_preexec`, no
  downgrade laundering.

Deliberately not built: config-file authority (no such machinery
exists; inventing it is new surface), build-time constants (kills
legitimate staging), force-KILL-and-continue (argued above).

**Threat-model honesty:** the guard's adversary is *operator
misconfiguration* (stray staging env in a production launcher), not
a malicious environment writer — anyone who can write the launcher's
environment can already unset `GOV_SANDBOX_BACKEND` or bypass the
launcher. Documented as a boundary note, never a finding.

## 2. Implementation (Lane 2)

`gov/sandbox.py`:

- `_DEPLOYMENT_MODES = ("production", "staging")` +
  `_resolve_seccomp_tier(deployment_mode, log_requested)` — the
  guard; returns `"kill"`/`"log"`, raises `SandboxError` on
  production+LOG, `ValueError` on unknown mode.
- `Sandbox(..., deployment_mode="production")` — validated
  fail-fast at construction.
- `run()`: the guard is a **single chokepoint at the top**, before
  jail creation. The tier resolves exactly once and flows as a value
  into `_make_preexec(..., seccomp_tier)`; the run note uses the same
  resolved value. This deletes the old double-read (note re-read at
  old line 1695 vs preexec read at old line 1801): no second read to
  go stale, no decision/install TOCTOU, and the child-side preexec
  never touches the environment for the tier (parent-side, pre-fork).
- `sandbox_config_from_env()`: maps `GOV_SANDBOX_DEPLOYMENT_MODE`
  (garbage/empty → default production; the constructor validates).
- Staging behavior unchanged: LOG honored + stamped; staging
  without LOG → KILL (no downgrade by default).

## 3. Break-first results

`SeccompLogGuardTest` (13 tests, all green) in
`tests/test_sandbox_seccomp_cage.py`:

| attack shape | result |
|---|---|
| `GOV_SANDBOX_SECCOMP_LOG=1` in production (default) | **REFUSED** — `SandboxError` naming the var, before `Popen` (no child spawned; patched `Popen` would trip) |
| LOG=1 in production, seccomp not installed this run | **REFUSED** — invariant is unconditional, not install-conditional |
| LOG set to empty / `0` / `true` / `yes` / `on` / whitespace / fullwidth `１` / `" true"` | **KILL** — `_env_flag` strictness pinned; only exact `"1"` (post-strip) is a request |
| LOG=`" 1 "` (stripped → `"1"`) in production | **REFUSED** — strip semantics pinned, no whitespace smuggling |
| Env set after fork but before install (TOCTOU) | **CLOSED structurally** — exactly-one-read pin: tier var read once per `run()`; `_make_preexec` takes it as a value; child preexec never reads env |
| Inherited env from compromised parent | **boundary note** — out of scope (env-writer can already disable the backend); child never sees the var (`DEFAULT_ALLOWED_ENV` pin) and tier is parent-side pre-fork |
| `deployment_mode` kwarg vs env disagreeing | kwarg wins (staging honored over env's production); env garbage → constructor `ValueError` |
| unknown `deployment_mode` | `ValueError` at construction and in resolver |
| staging + LOG | **allowed, stamped** — legitimate staging use unbroken (file-recorded installer proves `default_action="log"` reached the child) |
| staging, no LOG | **KILL** — no downgrade by default |
| KILL-tier install raises `OSError` | **no LOG retry** — every recorded install attempt carries `"kill"`; honest layer-fallback note, `seccomp_active=False` (no downgrade laundering) |
| `_make_preexec` called with unresolved tier | `SandboxError` (internal misuse guard) |

Three registry probes added (`redteam.f81.seccomp_log_guard_*`,
expected: denied): prod-refusal, TOCTOU single-read,
no-downgrade-laundering. 511 → **514 scenarios**.

**No misses → no finding.** F81 stays LOW/OPEN (unchanged rationale:
the guard hardens the staging tier of the F81 cage profile; wall
closure still needs the composed wall + privileged-CI lanes D1–D4).
Next free: **F128**.

## 4. Honest limits

- The guard is config-level: it cannot stop a malicious environment
  writer (boundary noted in §1, not a finding).
- Kernel acceptance of the LOG program is still gated on privileged
  CI (unchanged from wave-60 §5); the guard's own tests are
  hermetic and run everywhere.
- The refusal is raised as `SandboxError` to the caller; there is no
  `Sandbox`-level audit-log sink to thread, so the exception *is*
  the loud record — consistent with the codebase's other refusals
  (unknown `cage_mode`, canary-plant failure).
