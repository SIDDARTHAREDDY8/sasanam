# Spec: exchange-ledger robustness closures (F165, F166, F170)

Wave-110 ledger-robustness lane. Closes three Wave-109 quality-audit findings
in `gov/exchange_ledger.py`, all fail-closed posture. Companion: the F163
ledger spec (`docs/f163-exchange-ledger-spec.md`) is unchanged in intent;
this spec only hardens the tempo window's config, clock, and scale behavior.

## Problem Statement

The exchange-access ledger (F163) guards bulk trace/exchange harvest with a
sliding-window distinct-run tripwire, but the window itself is fragile in
three ways:

1. **F165 (MED):** `GOV_EXCHANGE_WINDOW_SEC<=0` collapses `_read_window` so
   the tripwire can never fire — fail-open on misconfiguration, contradicting
   the repo's fail-closed convention (`gov/policy.py` raises `ValueError` on
   malformed config).
2. **F166 (MED):** the window is keyed on wall-clock `time.time()`; a forward
   clock jump (NTP step, VM restore) empties the window and hands the
   harvester a fresh budget. (`gov/velocity.py::TempoWire` already uses
   monotonic — but it is in-memory only; the ledger's cross-process,
   cross-restart persistence changes the calculus, so this is not a
   straight copy.)
3. **F170 (LOW):** the ledger grows unboundedly; every cross-run read does a
   full-file read + JSON parse (linear cost per read; attacker-appendable via
   allowed reads = availability defect).

## Solution

Harden the three window properties while keeping every existing seam and the
fail-closed currency (`ExchangeAccessDenied`, never warn-and-continue):

- **F165:** validate the window config at read time on the window-dependent
  path; a parsed non-positive window denies cross-run reads loudly
  (denied-record + `ExchangeAccessDenied`). Own-run reads stay frictionless;
  allowlisted/strict paths (which never consult the window) are untouched.
- **F166:** stamp records with `time.monotonic()` plus a boot-epoch id; the
  tripwire compares monotonic stamps within one boot epoch and treats
  cross-boot/legacy records as still counting (fail-closed: a restart does
  not launder the budget). Wall-clock `ts` stays for audit readability.
- **F170:** bound every read to a tail byte-budget sized for the window;
  truncation without a trip denies fail-closed (cannot prove the allow case).
  Append-time compaction (temp-file + atomic replace, stale-fd retry,
  fsync discipline) drops window-irrelevant records when the file exceeds a
  size cap; any compaction failure degrades to deny, never to unbounded.

## User Stories

1. As a deployer who typo'd `GOV_EXCHANGE_WINDOW_SEC=0`, I want every
   cross-run read denied with a clear reason naming my bad value, so that a
   misconfiguration can never silently disarm the harvest control.
2. As a deployer, I want my agents' own-run reads to keep working even when
   the window config is broken, so that a config mistake degrades to
   deny-cross-run rather than bricking the product.
3. As an operator allowlisting a legitimate cross-run debug read, I want the
   allowlist path unaffected by window misconfiguration, so explicit trust
   decisions keep their meaning.
4. As an auditor, I want the denied-on-misconfig event recorded in the ledger
   like any other denial, so the misconfiguration itself is auditable.
5. As a defender, I want a forward wall-clock jump (NTP step, VM restore) to
   leave the tempo window intact, so the harvester gains no fresh budget.
6. As a defender, I want a process restart to NOT reset harvest accounting,
   so the boot-id trick cannot launder a nearly-tripped budget.
7. As an auditor, I want records to keep a human-readable wall-clock `ts`
   even though the tripwire no longer trusts it, so the ledger stays
   interpretable.
8. As an operator on a long-lived deployment, I want per-read cost bounded
   regardless of ledger history, so a slow-drip harvester cannot degrade
   every subsequent read.
9. As an operator, I want the ledger file compacted automatically (old,
   window-irrelevant records dropped) with crash-safe, fsync'd writes, so
   disk use stays bounded without risking a truncated ledger on crash.
10. As a defender, I want any I/O or compaction failure to deny the read
    rather than skip accounting, preserving the module's fail-closed-on-
    ledger-failure contract.

## Implementation Decisions

- **Module:** `gov/exchange_ledger.py` only. No seam signature changes:
  `check_exchange_read(path, n_entries=None)`, `bind_reader`,
  `exchange_target_for_path`, `_read_window(ledger_path, reader_key,
  window_sec)` (still returns a list), `_append_record` keep their shapes.
  New internal helpers: `_window_sec()` (validated config),
  `_boot_epoch()` (cached boot id), `_record_in_window(...)` (relevance
  predicate), `_read_window_full(...)` (records + truncated flag),
  `_compact_ledger(...)` (append-time compaction).
- **F165 posture — deny, not clamp, not ValueError.** A non-positive parsed
  window denies window-dependent (default-posture) cross-run reads with an
  `exchange_read_denied` record and `ExchangeAccessDenied` naming the value.
  Rationale: clamping silently rewrites an explicit (broken) operator intent
  into different tripwire semantics; `ValueError` would be an unhandled new
  exception class at a seam whose callers speak `ExchangeAccessDenied`.
  Unparseable values keep the documented default 900 (status quo the audit
  confirmed safe — the fail-open is specifically non-positive windows).
  Threshold knobs (`GOV_EXCHANGE_MAX_RUNS`, `GOV_EXCHANGE_MAX_SINGLE_READ`)
  are already fail-closed under misconfiguration (non-positive over-denies;
  non-numeric falls back to defaults) — analyzed, no change.
- **F166 clock design.** Each record carries `mono` (`time.monotonic()` at
  record time) and `boot` (boot-epoch id). A record is window-relevant iff
  (same boot-epoch AND `mono >= now_mono - window`) OR (different/missing
  epoch AND wall `ts >= now_wall - window`). Same-epoch accounting is
  monotonic-only (immune to wall jumps either direction); cross-epoch and
  legacy (pre-fix, no `mono`/`boot`) records keep counting by wall-clock —
  the fail-closed direction, so neither a clock jump nor a restart grants a
  fresh budget. Boot-epoch source: `/proc/sys/kernel/random/boot_id`,
  read once per process and cached; non-Linux fallback is a per-process
  random id (degrades gracefully to wall-clock behavior for cross-process
  records — no worse than status quo ante). `ts` remains the audit-visible
  wall-clock timestamp.
- **F166 residuals (documented, not fixed):** (a) restart + forward wall jump
  *together* can evict pre-restart records (attacker needs both privileges;
  a current-epoch harvest stays monotonic-pinned); (b) legitimate
  post-restart over-counting — pre-restart records count until wall-expired
  (fail-closed direction); (c) deleting the ledger file still yields an
  empty window (pre-existing first-run path, out of scope).
- **F170 read bound.** `_read_window_full` seeks to `max(0, size -
  TAIL_BUDGET)` under the shared lock, drops a possible partial first line,
  parses the tail. `TAIL_BUDGET` defaults to `max(2MB, window_sec * 512)`,
  overridable via `GOV_EXCHANGE_LEDGER_TAIL_BYTES`; garbage/non-positive
  falls back to the default (size knobs can only move toward deny, never
  toward allow, so a loud deny on misconfig would be theater here).
  Truncation + no tripwire trip → deny fail-closed ("cannot verify tempo
  window within bounded read"); a trip from partial data still denies with
  the tripwire reason.
- **F170 compaction.** In `_append_record`, while holding the exclusive
  lock, if the file exceeds `COMPACT_THRESHOLD` (default `max(1MB,
  window_sec * 256)`, env `GOV_EXCHANGE_LEDGER_COMPACT_BYTES`, same
  fallback rule), rewrite keeping only window-relevant records: write
  temp file in the same directory, fsync temp, fsync directory,
  `os.replace`, with a stale-fd identity check (`fstat` vs `stat`,
  ≤3 retries) against the replace-vs-concurrent-appender race. Any failure
  → `ExchangeAccessDenied` (degrade to deny, never to unbounded growth).
  Crash-consistency: temp+replace never leaves a truncated ledger; fsync
  discipline preserved on both the record append and the compaction paths.
- **F170 residuals:** (a) a sustained same-window write flood keeps all-fresh
  records above the threshold → steady truncation-denies (fail-closed DoS
  shape: loud deny replaces slow degradation); (b) no per-reader write
  rate limit — a new control, out of scope.
- **Record schema:** additive only — new `mono` (float) and `boot` (str)
  fields; all existing fields unchanged. Old records without them take the
  legacy arm of the relevance predicate.

## Testing Decisions

- What makes a good test here: behavior through the public/internal seams
  (`check_exchange_read`, `_read_window`, `_append_record`) with env-var
  config, never implementation internals; expected values from independent
  reasoning (counts, denial reasons), not recomputed from the code.
- New file `tests/test_ledger_robustness_f165_166_170.py`, module-level
  `os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")`, env
  save/restore in setUp/tearDown following `tests/test_f163_exchange_ledger.py`.
- Red-first: the new tests must FAIL against a pristine copy of the
  unfixed module (scratch copy under `~/workspace/audits/wave110/`), then
  pass post-fix. The three audit repros (`vrfy_ledger_window_failopen.py`,
  `vrfy_ledger_wallclock.py`, `vrfy_ledger_growth.py`) are the Phase-1
  feedback loops: red pre-fix, break-gone post-fix.
- Prior art: `tests/test_f163_exchange_ledger.py` (15 tests, seam + env
  patterns), `tests/test_f164_readfile_ledger.py` (10 tests).
- Adjacent suites to re-run green: the two above plus log-seam tests
  (`read_entries`/`read_entries_with_stats` coverage).
- Both deployment modes: normal and `env -u GOV_DEPLOYMENT_MODE`.
- Anti-patterns to avoid: tautological window math, mocking the module's
  own helpers instead of driving `check_exchange_read`, time-dependent
  flakiness (control clocks via `mock.patch` on `time.time` /
  `time.monotonic`, never sleeps).

## Out of Scope

- F167 (executor-memory tempo pause), F168 (foreign metering), F169
  (adaptive-battery instrument) — separate lanes.
- Ledger-file deletion / tampering (pre-existing first-run path).
- Per-reader write rate limiting (new control; noted as F170 residual).
- Changing the `check_exchange_read` public signature or the
  `ExchangeAccessDenied` currency.
- `setup-matt-pocock-skills` repo scaffolding (prompt-driven; no user
  available to confirm — spec/review artifacts live in-tree per repo
  convention instead).

## Further Notes

- `mock.patch("time.time")`-style tests keep working: the module calls
  `time.monotonic()` via the `time` module attribute, so patching
  `time.monotonic` (or the module's `_boot_epoch` seam) controls the new
  path without touching wall-clock patches.
- The two-axis review artifact for this wave lives at
  `evals/ledger_robustness_two_axis_review.md` (Standards and Spec axes
  run as separate passes; subagent spawning is unavailable at this depth,
  so the axes are executed sequentially, not merged).
