# F163 Spec — Exchange-Access Ledger (bulk trace/exchange harvest control)

## Problem Statement

Field evidence (Anthropic Sept-2026 threat report, "Illicit
distillation"): Alibaba extracted chain-of-thought at 3M exchanges/day
via 3,500 fraudulent accounts (151M exchanges total); Moonshot/DeepSeek
silently relayed user traffic through Claude and harvested the
exchanges; cross-session replay attacks defeated reasoning-signature
protections. Our governance records agent *actions* on the chained log,
but bulk *reading* of reasoning traces / tool exchanges — the harvest
pattern — leaves no extraction record and trips no control. An agent
(or a compromised harness) replaying sessions to harvest traces is
invisible to the audit layer.

## Solution

An exchange-access ledger: every read of *another run's*
traces/exchanges through the public log seam is a logged,
policy-checked event. Bulk-extraction patterns (cross-session replay
tempo, full-trace reads at scale) trip a fail-closed control that
denies the read instead of warning and continuing. Legitimate
debugging reads (own run, small cross-run inspection) keep working.

## User Stories

1. As a security operator, I want every bulk read of agent traces to
   leave an extraction record, so that a harvest campaign is visible
   in audit.
2. As a security operator, I want cross-session replay tempo (many
   distinct run transcripts read in a short window) to be denied
   fail-closed, so that a harvester cannot keep pulling.
3. As a security operator, I want a single full-trace read at scale
   to trip the control, so that one giant pull is also stopped.
4. As a deployment owner, I want cross-principal trace reads to be
   default-deny under a strict posture flag, so that tenants cannot
   read each other's reasoning traces.
5. As a deployment owner, I want an allowlist for legitimate
   cross-run readers (evaluators, incident responders), so that
   approved access is not broken by the tripwire.
6. As an agent developer debugging my own run, I want reads of my
   run's own exchanges to stay frictionless (no record, no policy
   check), so that debugging workflows do not change.
7. As an agent developer, I want small reads of my own past runs'
   exchanges to keep working, so that I can compare behavior across
   runs.
8. As an evaluator, I want denied harvest attempts to be recorded
   (`exchange_read_denied`), so that the attempt itself is evidence.
9. As an auditor, I want each extraction record to carry reader
   identity, target run, entry count, and the window stats behind the
   decision, so that the record is self-explanatory.
10. As an auditor, I want the extraction record mirrored onto the
    reader's own chained log when the reader is governed, so that the
    record inherits chain integrity.
11. As a red-team operator, I want a deterministic break battery that
    replays harvest tempo vs legitimate debugging reads, so that the
    control can be verified without production data.

## Implementation Decisions

- **Seam (one seam):** `gov.log.read_entries` /
  `gov.log.read_entries_with_stats` — the actual in-tree read path
  for run exchange files (used by `gov.simulator` replay and
  `gov.approval_web`). No new seam is invented; the guard is called
  at the top (pre-read) and after parsing (post-read, entry count
  known). Raw `open()` reads outside this seam are a stated residual.
- **What counts as a trace/exchange read:** a call through the seam
  whose path is a run exchange file: under a `runs/` directory
  (`runs/<run-id>/actions.jsonl`, target = `<run-id>`), or a file
  named `actions.jsonl` / `transcript.jsonl` (target = parent dir
  name). All other paths skip the guard entirely.
- **Own working memory stays frictionless:** when the bound reader
  context's `run_id` equals the target run id, the guard returns
  immediately — no record, no policy check, no tempo accounting.
- **Ledger:** new module `gov/exchange_ledger.py` (stdlib only, no
  import cycle with `gov.log`). Deployment-level JSONL ledger,
  file-locked appends (`fcntl.flock`), location from
  `GOV_EXCHANGE_LEDGER_PATH`, else a sibling
  `exchange_access.jsonl` of the target `runs/` dir, else the OS
  temp dir.
- **Ledger event schema:** `{"event": "exchange_read" |
  "exchange_read_denied", "ts", "reader_principal", "reader_run_id",
  "target_run_id", "path_tail", "n_entries", "window_distinct_runs",
  "window_reads", "decision", "reason"}`. `path_tail` is the
  last two path components only (no absolute paths in the record).
- **Chained-log mirror:** when a reader context binds a governed
  `ActionLog`, every `exchange_read` / `exchange_read_denied` is
  also appended there (event names as above), so the extraction
  record inherits hash-chain integrity.
- **Policy check semantics (fail-closed):**
  1. Own run → ALLOW, silent.
  2. Allowlisted (`GOV_EXCHANGE_READ_ALLOW`, entries
     `principal:run`, `principal:*`, `*:run`) → ALLOW + record.
  3. Strict posture (`GOV_EXCHANGE_STRICT_CROSS_PRINCIPAL=1`):
     cross-run read with a known reader principal and no allowlist
     hit → DENY + denied-record. Unknown (unbound) readers are also
     denied here — the principal cannot be verified.
  4. Default posture: cross-run read → ALLOW + record, subject to
     the bulk tripwire.
- **Bulk-extraction tripwire (fail-closed, never warn-and-continue):**
  per reader key (principal, or `"unknown"` when unbound), sliding
  window `GOV_EXCHANGE_WINDOW_SEC` (default 900):
  - distinct target runs read in window >
    `GOV_EXCHANGE_MAX_RUNS` (default 50) → DENY;
  - a single read with `n_entries` >
    `GOV_EXCHANGE_MAX_SINGLE_READ` (default 250000) → DENY.
  Denial appends `exchange_read_denied` and raises
  `ExchangeAccessDenied`; the caller never receives the entries.
- **Ledger failure is fail-closed:** if the ledger cannot be read or
  appended, cross-run reads are denied (own-run reads unaffected).
- **Reader context:** thread-local, bound via
  `bind_reader(principal, run_id, action_log=None)` context
  manager. Unbound callers read as principal `"unknown"`.
- **No behavior change by deployment mode:** the guard behaves
  identically in staging and production (verified in both).

## Testing Decisions

- Good tests exercise the real harvest pattern at the real seam
  (`read_entries` over many `runs/<run>/actions.jsonl` files), not
  a mock of the guard.
- **Red battery** `evals/f163_harvest_break.py`: fixture runs with
  synthetic exchanges; harvest scenario (tight loop over 12 distinct
  runs) vs control scenarios (own-run reads, one past-run debug
  read). Pre-fix it must demonstrate the gap (harvest invisible:
  no record, no trip) and exit non-zero; post-fix it must show the
  harvest tripped fail-closed and the controls green, exit zero.
  Thresholds are driven by env vars inside the battery for
  determinism; no sleeps, no RNG.
- **Regression tests** `tests/test_f163_exchange_ledger.py`
  (unittest): own-run frictionless; cross-run recorded; tempo
  tripwire trips; single-huge-read trips; strict-mode default deny;
  allowlist bypass; unknown reader recorded; ledger failure
  fail-closed; both envs (module-level
  `os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")`,
  battery also verified under `env -u GOV_DEPLOYMENT_MODE`).
- Prior art: `evals/f142_break.py`, `evals/f139_closure.py`
  (break/closure battery shape); `tests/test_citation_provenance.py`
  (ledger-backed verdict tests).

## Out of Scope

- Content redaction / DLP on trace reads (v1 is access control +
  accounting, not data-loss prevention).
- Raw `open()`/read_text reads outside the public log seam (e.g.
  `evals/llm_redteam/toolshim.py` reads transcripts directly) —
  stated residual; closing it means routing all transcript access
  through the seam (follow-up).
- A run→principal ownership registry: true per-principal
  default-deny needs a binding between run ids and owning
  principals, which the run-dir naming does not carry. v1 offers
  the strict-posture flag plus the allowlist; the registry is
  follow-up work.
- Cross-process harvest accounting beyond the shared ledger file
  (the ledger file is the cross-process mechanism; in-memory
  shortcuts must not bypass it).

## Further Notes

- The field pattern this closes is *read-side*: Alibaba's 3M
  exchanges/day tempo is exactly what the distinct-runs-per-window
  tripwire targets, while Moonshot/DeepSeek-style silent relay is
  what the per-read extraction record targets.
- Thresholds are deployment-tunable via env; the defaults are
  chosen so normal debugging (tens of runs per 15 minutes) never
  trips, while harvest tempo (hundreds+) always does.
- Close-when: (1) every cross-run exchange read through the seam
  appends an `exchange_read` record; (2) harvest-tempo reads raise
  `ExchangeAccessDenied` fail-closed with an
  `exchange_read_denied` record; (3) own-run reads stay silent and
  frictionless; (4) red battery green post-fix in both envs;
  (5) no existing suite regressions.

## Close-when criteria (checklist)

- [ ] C1: cross-run read via `read_entries` appends `exchange_read`
- [ ] C2: harvest tempo (> max distinct runs/window) → fail-closed
        deny + `exchange_read_denied`
- [ ] C3: single full-trace read (> max single) → fail-closed deny
- [ ] C4: own-run reads → no record, no check
- [ ] C5: strict mode denies non-allowlisted cross-run reads
- [ ] C6: battery red pre-fix, green post-fix, both envs
- [ ] C7: canonical + registry + matrix suites stay green
