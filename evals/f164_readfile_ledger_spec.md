# F164 spec — wire the agent `read_file` tool path through the F163 exchange-access ledger (Wave-110)

## Problem Statement

The F163 exchange-access ledger guards only the harness/auditor read seam
(`gov.log.read_entries` / `read_entries_with_stats`). The agent's own
governed `read_file` tool — the path an agent actually uses to bulk-read
reasoning traces and tool exchanges (the Anthropic Sept-2026 "Illicit
distillation" field pattern) — never invokes the guard. Cross-run trace
harvest via `read_file` returns real bytes with zero ledger records and
zero tripwire engagement. The F163 module claim "every read of another
run's traces/exchanges is a logged, policy-checked event" is therefore
false on the agent tool path (F164, HIGH).

## Solution

Bind the ambient exchange reader to the calling identity/run around the
executor's file-returning tool path, and run the F163 two-phase
`check_exchange_read` gate there: before the read (policy + replay-tempo
check) and after the read (full-trace size check + extraction record).
A denial is fail-closed: the agent never receives the bytes, an
`exchange_read_denied` record exists on the ledger (mirrored onto the
reader's chained log when bound), and the call raises.

## User Stories

1. As an auditor, I want every cross-run trace/exchange read an agent
   performs through `read_file` to leave an `exchange_read` record on
   the deployment ledger, so that harvest activity is visible in the
   audit layer.
2. As an operator, I want an agent bulk-reading distinct run transcripts
   through `read_file` to be denied fail-closed at the tempo tripwire
   (before receiving the bytes), so that cross-session replay harvest
   cannot proceed silently.
3. As an operator, I want a single full-trace pull at scale through
   `read_file` to be denied fail-closed at the size tripwire, so that
   whole-transcript exfiltration is blocked, not just recorded.
4. As an agent, I want reads of my OWN run's exchanges to stay
   frictionless (no record, no check), so that working memory and
   legitimate debugging are unaffected.
5. As an operator, I want the allowlist (`GOV_EXCHANGE_READ_ALLOW`) and
   strict-posture (`GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL`) semantics to
   apply identically on the tool path as on the log seam, so that one
   policy governs every read path.
6. As an auditor, I want denied reads to leave an `exchange_read_denied`
   record mirrored onto the reader's chained log, so that the denial
   inherits hash-chain integrity and is attributable.
7. As a deployment, I want nested/spawned executions to bind the correct
   (innermost) reader context, so that a child agent's reads are
   attributed to the child, not the parent.
8. As a red-team tester, I want the A1 audit repro
   (`~/workspace/audits/wave109/f164_readfile_harvest_repro.py`) to flip
   from BREAK to recorded-on-ledger, so that the closure is demonstrated
   on the exact defeating playbook.
9. As a red-team tester, I want a bulk-harvest battery through the tool
   path (many distinct victim runs via `read_file`) to be denied at the
   tempo limit with a denial record, matching the log-seam battery
   behavior.
10. As an operator, I want non-exchange reads (source files, notes, any
    non-`.jsonl`-under-`runs/` path) to be completely unaffected — zero
    overhead, zero records — so that the guard never taxes ordinary
    file I/O.

## Implementation Decisions

- **Single choke point.** The only executor tool that returns real file
  bytes is `read_file` (the sandbox-read branch of the single internal
  tool-execution routine, which is also the only code that reads file
  bytes into an agent-facing result; all other tools return synthetic
  or metadata results). The guard lives at that branch, so it covers
  the direct-allow execution path, the approved-sweep execution path,
  and the pre-commit commit thunk path by construction — every one of
  them funnels through the same routine. No new seams; one site.
- **Two-phase pattern, exactly like the log seam.** Before the file is
  touched: `check_exchange_read(path)` with `n_entries=None` (policy +
  replay-tempo tripwire — a tempo denial happens before any bytes are
  read from disk). After the full file text is in memory: a second call
  with the parsed entry count (full-trace size tripwire + the
  `exchange_read` / `exchange_read_denied` extraction record). The
  entry count is the number of non-blank lines of the full file text
  (the `.jsonl` analog of the seam's parsed-entry count), computed from
  the complete file content — never from the 4000-char tool-result
  truncation.
- **Reader binding at the execution boundary.** The ambient reader is
  bound with `exchange_ledger.bind_reader(principal, run_id,
  action_log=<the run's chained log>)` around the internal tool-execution
  call at the two call sites that have identity context: the direct
  `call()` path (binds the calling identity's principal/run_id) and the
  approved-sweep path (binds the approval record's principal/run_id).
  `bind_reader` is a thread-local context manager that restores the
  previous binding on exit, so nested/spawned executions attribute
  correctly to the innermost reader.
- **Own-run reads stay frictionless.** The bound reader's `run_id`
  compared against the exchange target is the calling identity's run;
  reads of the reader's own run return immediately (no record, no
  check) — identical semantics to the log seam.
- **Denial semantics.** `ExchangeAccessDenied` propagates out of the
  tool-execution routine fail-closed: no result dict is built, the
  agent never receives the bytes, and the `exchange_read_denied`
  record (appended by the guard itself, mirrored onto the chained log
  when bound) exists before the exception surfaces. No extra wrapping:
  the exception type is already the public fail-closed signal of the
  ledger module.
- **No import cycle.** The executor imports the ledger module the same
  way the log seam does (`from . import exchange_ledger as ...`); the
  ledger module imports no `gov` modules — this invariant is kept, and
  a regression test asserts the ledger module has no `gov.` imports.
- **Simulated path needs no guard.** When the file is outside the
  sandbox or the target flipped, the tool returns synthetic content
  with no real bytes — there is nothing to harvest, so the guard is
  not invoked there. This is documented, not assumed: the branch is
  explicit.
- **Mirror failures stay fail-closed.** If the chained-log mirror of
  an extraction record fails, the guard raises (the ledger module's
  existing behavior) — the read is denied rather than silently
  unmirrored.
- **Residuals carried over.** Raw `open()`/read_text reads outside the
  governed seams (harness-internal readers, eval scripts) remain
  uncovered — the documented F163 residual, unchanged. Foreign-adapter
  result ingestion (`ingest_foreign_result`) carries no file reads and
  is out of scope (F168 covers its metering).

## Testing Decisions

- **Red-first at public seams.** New test module
  `tests/test_f164_readfile_ledger.py` written against the UNFIXED
  code first (demonstrated red via a scratch copy of `gov/`), then
  green post-fix. Tests assert only externally observable behavior:
  tool-call status, returned content presence/absence, ledger record
  counts and event names, chained-log mirror entries — never
  implementation internals.
- **Cases (minimum):** single cross-run `read_file` harvest is now
  recorded (`exchange_read` with the victim target, reader principal,
  entry count); bulk harvest via `read_file` across distinct victim
  runs trips the tempo denial (`ExchangeAccessDenied` raised, an
  `exchange_read_denied` record exists, no bytes returned);
  own-run `read_file` stays frictionless (executed, content returned,
  zero records); allowlisted cross-run read is allowed AND recorded;
  denied read returns no bytes to the agent; non-exchange reads are
  unaffected (zero ledger records).
- **Prior art:** `tests/test_f163_exchange_ledger.py` (the seam-level
  battery, 15 tests) for ledger-behavior assertions;
  `~/workspace/audits/wave109/f164_readfile_harvest_repro.py` as the
  defeating playbook the closure must break.
- **Both environments.** Every new test and the audit repro run under
  normal env and `env -u GOV_DEPLOYMENT_MODE` (new eval batteries set
  `GOV_DEPLOYMENT_MODE=staging` at module level).

## Out of Scope

- F165 (window fail-open on non-positive window), F166 (wall-clock
  tempo), F167 (pause volatility), F168 (foreign metering), F169
  (battery scoring), F170 (ledger growth) — sibling findings, separate
  lanes.
- Content redaction/DLP on reads (access control + accounting only).
- Per-principal default-deny ownership registry (strict-posture flag +
  allowlist is the v1 mechanism).
- Guarding harness-internal raw file reads (documented residual).

## Further Notes

- The guard path string passed to the ledger is the resolved absolute
  sandbox path the tool actually reads; target-run parsing and ledger
  placement therefore match the log-seam behavior for the same file.
- F163 re-closure depends on this lane: the re-verification runs both
  `evals/f163_harvest_break.py` (seam leg) and the F164 audit repro
  (agent-path leg); F163 is RE-CLOSED only if both hold.
