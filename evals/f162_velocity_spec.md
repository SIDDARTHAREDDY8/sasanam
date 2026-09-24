# F162 Closure Spec — Velocity / Economic Controls
## (amended finding, 2026-09-24; coverage map: `research/anthropic-sept2026-coverage-map.md`)

This spec synthesizes the amended F162 finding and its closure direction.
No interview was run (per the `to-spec` skill: synthesize what is known).
Seam: `ToolExecutor.call()` and the approved-execution sweep in
`gov/executor.py` (the same two execution boundaries F33 charges at).
No new seams.

## Problem Statement

Anthropic's "Detecting and countering misuse of AI: September 2026"
shows the attack class is unit economics, not novel technique: GTG-50014
(2,100+ Azure AD token sets, 40+ tenants, ~34h), GTG-20006 (bulk mailbox
exports, hundreds of GB), GTG-10007 (13-agent scheduled collection
fleet). The coverage map (2026-09-24) proved the tree HAS volume guards
— but the demonstrated residual is:

1. Every guard is opt-in or off-by-default: absent `budgets:` section =
   unenforced; absent `velocity:` section = disabled. Under default
   config, reads (`api_call` is read-classified per F1, `read_file` has
   no volume guard) and bulk tempo trip nothing.
2. All guards are per-run cumulative totals. There is NO time-window
   tempo control: nothing trips on per-minute / per-hour action *rate*,
   so trickle-across-the-window evades them.
3. The S5/K-052 velocity guard fails OPEN on ledger errors (`loud`
   `velocity_check_skipped`, call proceeds).
4. Token/spend accrual is unwired (S2-GAP-1): `_tokens_used`/`_spend_used`
   are initialized to 0 and never incremented; `max_tokens_per_run` /
   `max_spend_per_run` can never trip; the two accrual tests are
   `expectedFailure`. No metered accounting on the chained log.

A governed run executing 10,000 `api_call`/`read_file` actions in an
hour is indistinguishable from a legitimate run under default config
until a human reads the log afterward.

## Solution

Extend the existing guards rather than rebuilding them (60% is built):

1. **Default-enforced budgets**: absent `budgets:` section no longer
   means unenforced — the executor applies deployment-safe default
   ceilings (`max_actions_per_run`, `max_tool_calls_per_run`). Explicit
   policy values always win; malformed values still fail the policy load
   closed. The deployment (policy author) sets ceilings, never the
   agent.
2. **Default-enforced, fail-closed velocity**: absent `velocity:`
   section applies conservative default thresholds; on ledger error the
   guard fails CLOSED toward human review (`velocity_exceeded=True` →
   the existing `approval-velocity-guard` require_approval rule) with a
   loud `velocity_check_failed` entry, instead of the current silent
   proceed.
3. **Time-window tempo tripwires per action class**: new `tempo:` policy
   section, `(window_secs, max per class)` deterministic thresholds,
   injectable clock (production: `time.monotonic`). On trip: pause the
   whole run (sticky, all identities — the fleet rotates agent ids),
   chain a loud `velocity_tempo_trip` record, file a `velocity_resume`
   approval request, raise fail-closed. Resume requires a human
   `decide(approved)` on that record plus an explicit executor resume
   call that consumes the record (single-use).
4. **Metered token/spend accounting**: the executor mints deterministic
   synthetic `_usage` on every simulated result (governed side, via
   `_mint_result_usage` — overwrites any forged `_usage`); `_ingest_result` (and
   `ingest_foreign_result`) accrues it into `_tokens_used`/`_spend_used`
   (result path only — call-kwarg `_usage` is ignored, the agent cannot
   forge or deflate its meter); every `allowed_executed` /
   `approved_executed` entry carries the per-run meter
   (`tokens_used`, `spend_used`, `budget_actions`) — tamper-evident via
   the existing hash chain. The two S2-GAP-1 `expectedFailure` tests
   flip to real tests.

## User Stories

1. As a deployment operator, I want per-run action budgets enforced
   even when the policy file has no `budgets:` section, so that a
   misconfigured policy cannot silently become unlimited.
2. As a deployment operator, I want to override the default ceilings
   in policy, so that legitimate high-volume runs can be authorized
   without weakening the default posture.
3. As a security reviewer, I want bulk-tempo `api_call` exfiltration
   (GTG-50014 shape) to pause the run fail-closed, so that a run
   dumping thousands of token sets cannot complete silently.
4. As a security reviewer, I want trickle-across-the-window tempo
   (low rate, high total) to still trip a control, so that pacing the
   attack does not evade the tripwire.
5. As a security reviewer, I want the whole run paused (not just the
   tripped identity), so that a 13-agent fleet (GTG-10007 shape) cannot
   evade by rotating agent ids.
6. As a security reviewer, I want a velocity-guard ledger failure to
   route the call to human review rather than proceed silently, so that
   a tampered ledger cannot disable the cross-run signal.
7. As an operator, I want to resume a paused run only after a human
   approves the filed `velocity_resume` request, so that "pause" is a
   real containment state and not a retry loop.
8. As an auditor, I want per-execution token/spend meters chained on
   the audit log, so that metered accounting is tamper-evident and
   reviewable offline.
9. As a finance/procurement reviewer, I want spend ceilings that can
   actually trip, so that the "economic" half of the finding is a live
   control, not dead config.
10. As a legitimate-run developer, I want human-tempo runs (tens of
    actions) to pass untouched, so that the new controls do not brick
    normal governed work.
11. As an agent, I must not be able to set my own budgets, forge my
    usage, or resume my own paused run — budgets come from policy, usage
    from the result path, resume from a human.
12. As a regression-test author, I want deterministic tempo tests via an
    injectable clock, so that tempo behavior is pinned without sleeps.

## Implementation Decisions

- **Do not rebuild**: F33 volume guards, `max_actions_per_run` /
  `run_limits.max_tool_calls_per_run`, and S5 `_query_velocity` /
  `_record_velocity` are extended in place. New code lives in
  `gov/executor.py` (+ a small `gov/velocity.py` helper for the tempo
  state machine, mirroring `_SpawnBudget`'s precedent as a
  deployment-constructed, executor-routed primitive).
- **Action-class taxonomy for tempo**: `read` = {`read_file`},
  `write` = {`write_file`, `delete_file`},
  `egress` = {`send_email`, `http_post`, `api_call`} (`api_call` is
  exfiltration-capable; F1's read-classification is a policy routing
  detail, not a tempo class). `install_package` is out of tempo scope
  (its own allowlist/pin/integrity gates already bound it); unlisted
  tools are uncounted by the tempo wire (documented residual, same
  pattern as S5's `_VELOCITY_TOOLS` scoping).
- **Budget defaults and who sets them**: policy, never the agent.
  Defaults (absent section): `max_actions_per_run` = 200,
  `run_limits.max_tool_calls_per_run` = 400 (counts every attempt,
  denied included, per S4). Explicit values override; 0 is a legal
  explicit value (deny-first run). Malformed policy fails load closed
  (existing normalizer behavior).
- **Tempo wire config**: new `tempo:` policy section —
  `window_secs` (default 60), `max_read` (default 300),
  `max_write` (default 60), `max_egress` (default 30). Deterministic
  thresholds (no ML — explicit non-goal). Counts charge at the two F33
  execution boundaries (direct allow path AND approved-execution
  sweep): denied/queued-but-unexecuted calls do not charge tempo; an
  approved execution charges once. Monotonic timestamps; the clock is
  `self._tempo_clock` (default `time.monotonic`), injectable for
  deterministic tests.
- **Tripwire semantics**: windowed count > threshold on charge →
  chain `velocity_tempo_trip` (event `tool_call`, decision
  `velocity_paused`, flag `velocity_tempo_trip`, class + window +
  counts), set sticky `_tempo_paused`, file `velocity_resume` into the
  `ApprovalQueue` (PolicyDecision require_approval,
  policy_id `velocity-tempo`, flag `velocity_tempo_trip`), raise
  `VelocityTempoTripError` fail-closed. Subsequent `call()` raises
  `VelocityRunPausedError` fail-closed (sticky, all identities).
  `resume_after_velocity_pause(approval_id)` requires `status ==
  "approved"` and unconsumed — then clears the pause, resets the
  tripped class's window (the human reviewed the burst and authorized
  continuation; without the reset the next call would re-trip inside
  the still-hot window), and consumes the record via `mark_executed`
  (single-use). Two shapes: on the call() path the executor auto-files
  the `velocity_resume` record and the approval id must match it; on
  the approved-execution sweep path there is no calling identity, so
  the pause stands without an auto-filed record and resume requires an
  operator-filed `velocity_resume` record (`tool == "velocity_resume"`,
  `args.run_id == this run`). No resume path for the agent: `decide()`
  already excludes the requesting agent from self-approval (separation
  of duties), and resume is executor-side.
- **Fail-closed velocity**: `_query_velocity` on ANY ledger trouble
  returns True (treated as exceeded → `approval-velocity-guard`
  require_approval queues the call for a human) and chains
  `velocity_check_failed` (flag, loud) instead of
  `velocity_check_skipped`. The call never proceeds silently; the
  heuristic-never-denies contract is preserved (human gates, not
  auto-deny).
- **Metered accounting format**: every `allowed_executed` and
  `approved_executed` entry gains `usage: {"tokens": int,
  "spend": float}` (this execution's minted usage) and
  `budget_meter: {"tokens_used": int, "spend_used": float,
  "budget_actions": int}` (per-run accrued). Usage is minted by
  `_simulate` as `result["_usage"]` (deterministic: per-tool base +
  payload/content bytes // 4); spend = tokens/1000 ×
  `price_per_1k_tokens` (0 when unconfigured). Accrual happens only in
  `_ingest_result` / `ingest_foreign_result` on the result path —
  call-kwarg `_usage`/`_tokens_used`/`_spend_used` remain ignored (the
  existing anti-forgery test stays green). Real adapters (MCP/foreign)
  must route real results through `ingest_foreign_result` to accrue
  (documented; the sim is synthetic).
- **Do not weaken**: F33 defaults, loop-guard, byte budget, S5 queue
  behavior, S2 ceiling conventions (`>` for actions, `>=` for
  token/spend, crossing call completes), and all existing policy
  defaults stay exactly as-is.

## Testing Decisions

- What makes a good test: behavior at the public seams only —
  `ToolExecutor.call()`, `execute_approved()`,
  `resume_after_velocity_pause()`, the chained log — never internals.
  Deterministic: fake clock for tempo; no sleeps; seed nothing.
- Modules tested: `gov/executor.py` (verdict path, both execution
  boundaries), `gov/velocity.py` (window state machine), `gov/policy.py`
  (tempo section normalization), `gov/log.py` (meter fields present and
  chained — implicitly via `read_entries`).
- Prior art: `tests/test_budgets.py` (S2 seam: `_run(budgets)` policy
  text helper + `_api` call helper — reuse its shape for tempo tests);
  `evals/f142_break.py` (break-first battery shape, verdict vocabulary
  BREAK/CLOSED/CONTROL/ERROR, module-level
  `GOV_DEPLOYMENT_MODE=staging`, harness `make_run`); `tests/` unittest
  only, no pytest.
- The red battery (`evals/f162_velocity_break.py`) is written FIRST
  and must go red pre-fix: bulk-exfiltration tempo (tight-loop
  `api_call` token dumps), token-amplification tempo (bulk `api_call`
  against cloud-shaped endpoints), and trickle-across-window tempo
  (spread under the tempo window, high total) all complete silently
  under default config, and `_tokens_used` stays 0; post-fix each trips
  fail-closed while legitimate-tempo controls (tens of actions,
  human pace) pass. Verified standalone under normal env AND
  `env -u GOV_DEPLOYMENT_MODE`.

## Out of Scope

- ML/behavioral anomaly detection (deterministic thresholds only —
  this is the stated non-goal; the wave-76 detection monitor stays
  untouched).
- Cross-run tempo aggregation (v1: per-run tempo; cross-run stays the
  S5 queue-signal, now fail-closed on ledger errors).
- Resume authorization beyond the existing approval-queue SoD (no new
  identity primitive for approvers).
- Dynamic/adaptive pricing (spend = static configured price; the sim's
  usage is synthetic by design).
- `install_package` tempo and unlisted-tool tempo (documented residual).
- Metering inside the agent-side sandbox worker (out-of-process agents
  report usage via `ingest_foreign_result`).
- **Record-side ledger failure stays fail-open by design**: `_query_velocity`
  is fail-closed on ANY ledger trouble (the enforcement point), but
  `_record_velocity` (post-effect accounting) logs `velocity_check_skipped`
  and continues when the ledger cannot be written. Rationale: the query
  already gated the call, so a record-side failure is a narrow post-query
  race; failing closed after the side effect cannot un-execute it, and a
  broken ledger already halts future work at the F17 gate and the sweep's
  `require_verified`. The residual is one lost accounting entry in that
  race, not a bypass of the tripwire.
- **Fail-closed routing depends on the `approval-velocity-guard` rule**:
  on ledger trouble `_query_velocity` returns True, which only queues the
  call when the deployment's policy includes the `approval-velocity-guard`
  rule (present in the default policy). A deployment that removes the rule
  loses the human-review routing; the `velocity_check_failed` audit entry
  still fires loud.
- **Test hygiene**: default-enforced S5 recording means many more tests
  write `kind: velocity` entries to the shared `$TMPDIR/egress_ledger.jsonl`.
  Tests that construct `ToolExecutor` directly (not via `make_run`) must pass
  an explicit hermetic `ledger_path` inside their run dir, otherwise foreign
  test keys trip the F17/velocity fail-closed gates. Fixed in
  `test_hardening_r23`, `test_w52_rt19`, `test_w75_governors`.
- **Resume audit atomicity**: `resume_after_velocity_pause` consumes the
  approval, clears the pause, resets the wire, then appends the chained
  `velocity_resumed` audit entry. If that final append fails, the run is
  unpaused without the chained resume record. The security invariant holds
  (single-use: the approval queue is authoritative and the approval is
  consumed before unpause, so it cannot be reused), but the action log has
  a gap. Two-system commit; accepted residual.

## Further Notes

- Close-when (binding, from the amended finding text): the red battery
  (`evals/f162_velocity_break.py`) demonstrates the residual pre-fix
  (bulk tempo AND trickle-across-window tempo pass silently under
  default config, spend stays 0) and trips fail-closed post-fix while
  legitimate-tempo controls pass; the two S2-GAP-1 tests flip from
  `expectedFailure` to passing; the canonical suite, registry gate, and
  realistic battery stay green.
- Defaults are a policy posture choice, not physics: 200 actions/run
  and 30 egress/60s are conservative for a governance product whose
  threat model is machine-speed misuse; deployments doing legitimate
  bulk work raise them in policy explicitly (audited).
