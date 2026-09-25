# F167 Closure Spec — Tempo Pause Survives Executor Rotation
## (filed 2026-09-24, quality-audit of Wave-109; Wave-110 executor-persistence lane)

This spec synthesizes the F167 finding and its closure direction. No
interview was run (per the `to-spec` skill: synthesize what is known).
Seam: `ToolExecutor.__init__` tempo block + `_charge_tempo` /
`resume_after_velocity_pause` in `gov/executor.py`. No new seams.

## Problem Statement

The F162 tempo tripwire pauses the run (`_tempo_paused = True`, sticky
across identities) — but the pause and the wire live only in executor
memory. The tree documents fresh-executor-per-sweep as a real
deployment pattern (the F60 pattern). Rotating the executor over the
same run_dir drops containment: the new executor starts unpaused and
executes freely. The "sticky run-wide pause" the F162 closure claims
evaporates on rotation; `resume_after_velocity_pause` on the new
executor reports "not paused". The canary halt persists via a marker
file — the in-tree precedent this should have followed. Deterministic
repro: `~/workspace/audits/wave110/vrfy_pause_volatile.py` (trip on
ex1 → ex2 over the same run_dir → `ex2._tempo_paused is False`, call
executes).

## Solution

Derive the pause from the chained run log at construction (option (b)
from the finding). The trip path already chains a `velocity_paused`
record and the resume path already chains a `velocity_resumed` record;
the log is the existing tamper-evident, deployment-owned substrate, so
no new sidecar file and no new MAC plumbing is needed.

1. **Rehydration at `__init__`**: after the tempo wire is built, scan
   the run's own chained log for the latest entry whose `decision` is
   `velocity_paused` or `velocity_resumed`. The run starts paused iff
   the latest such entry is a `velocity_paused`. A fresh run_dir (no
   such entries) starts unpaused; a `velocity_resumed` (human-approved
   resume) clears the persisted pause exactly once, automatically.
2. **Adversarial posture**: only entries carrying the log's own chain
   bookkeeping (integer `seq`, string `hash` — keys the log sets and
   strips from caller input) are honored; malformed/planted lines are
   skipped, never trusted (F28/F52 convention). The scan reads the
   deployment-owned log file directly — never through the F163
   exchange-read policy check, which at construction time would
   mis-attribute the executor's own bookkeeping as a cross-run read.
   The agent cannot plant entries: agent file writes are jailed to the
   sandbox, and forging a chained entry requires the deployment HMAC
   key. I/O trouble during the scan is best-effort (canary-marker
   precedent): the executor starts unpaused, and a truly unreadable
   log fails closed at the first append anyway.
3. **Ordering hardening**: the `velocity_paused` record is chained
   BEFORE `_tempo_paused` is set, and `velocity_resumed` is chained
   BEFORE the flag is cleared — memory and log can never diverge on an
   append failure (fail-closed propagation is preserved).
4. **The wire is deliberately NOT rehydrated**: `TempoWire` hit
   timestamps are monotonic-per-boot; rehydrating them across a restart
   would be dishonest (the F166 lesson). The pause makes the wire moot
   until resume, and resume resets the tripped class's window anyway.
   Post-rotation the wire starts cold — documented residual, not a
   containment gap.
5. **`_tempo_resume_aid` / `_tempo_trip_class` are not rehydrated**
   (stay `None`): the operator-filed branch of
   `resume_after_velocity_pause` covers rotation — the auto-filed
   record carries `tool == "velocity_resume"` and
   `args.run_id == run_id`. Resume with `trip_class=None` resets all
   classes: the human reviewed the burst, so this is the fail-safe
   direction.

## User Stories

1. As a deployment operator rotating executors per sweep (F60
   pattern), I want a tempo-tripped run to stay paused across
   rotation, so containment cannot be dropped by re-construction.
2. As a security reviewer, I want the pause state to be derivable from
   the tamper-evident chained log rather than a new sidecar file, so
   there is no new self-unpause primitive to MAC-bind.
3. As a human approver, I want `resume_after_velocity_pause` on a
   rotated executor to accept the auto-filed `velocity_resume`
   approval, so rotation does not brick the legitimate resume path.
4. As a deployment operator, I want a fresh run_dir to never inherit a
   stale pause, so new runs are unaffected.
5. As an auditor, I want the trip record to exist whenever the pause
   flag is set (no memory/log divergence), so the audit trail is the
   pause's source of truth.

## Implementation Decisions

- Pause derivation lives in `ToolExecutor.__init__`'s tempo block via
  a `_rehydrate_tempo_pause()` helper; scan is a small tolerant JSONL
  parse of `self.log.path` (blank/malformed lines skipped; entries
  must be dicts with `decision` in the pause/resume pair plus int
  `seq` and str `hash`).
- `_charge_tempo`: build the trip entry, `self.log.append` it, THEN
  set `_tempo_paused` / `_tempo_trip_class`; queue the resume approval
  after (unchanged fail-closed comment: the pause stands even if
  queueing fails).
- `resume_after_velocity_pause`: `mark_executed`, then append the
  `velocity_resumed` record, THEN clear `_tempo_paused` /
  `_tempo_resume_aid` / `_tempo_trip_class` and reset the wire.
- No wire-state persistence; no new files under run_dir.

## Testing Decisions

- A good test drives the public seam (`ToolExecutor(...)`
  construction over a shared run_dir) and asserts the user-visible
  behavior: rotated executor raises `VelocityRunPausedError` on
  `call()`; it does not assert on private scan helpers.
- Prior art: `tests/test_velocity_f162.py` (trip/resume behavior),
  `tests/test_w52_rt19.py` (canary marker survives restarts).
- Red-first: new `tests/test_f167_pause_persistence.py` must FAIL
  against the unfixed code (scratch copy) — the rotated executor
  executes freely pre-fix.
- Cases: rotation preserves pause; resume on the rotated executor via
  the auto-filed approval clears it exactly once (second resume with
  the same id refused); fresh run_dir starts unpaused; trip record
  precedes the flag (log shows `velocity_paused` whenever a rotated
  executor reports paused); planted unchained `velocity_resumed` line
  (no `seq`/`hash`) does not unpause.
- Both deployment modes: normal and `env -u GOV_DEPLOYMENT_MODE`.

## Out of Scope

- Rehydrating wire hit timestamps across boots (dishonest under
  monotonic clocks; documented residual).
- Changing the single-use approval-consumption ordering in
  `resume_after_velocity_pause` (`mark_executed` before the resume
  append is pre-existing; the failure mode is fail-closed).
- Verifying the full HMAC chain at construction (the log verifier
  remains the component that fails closed on corrupt lines, F28).

## Further Notes

- The scan is O(n) JSONL parse per executor construction; runs carry
  an F22 size guard, and the F60 rotation pattern constructs
  executors per sweep — acceptable, documented residual (a tail index
  is future work, not this wave).
- Cross-boot honesty decision (required by the finding): the wire's
  monotonic timestamps are per-boot by construction; persisting them
  would let a restarted process misread stale windows as live. Fresh
  wire + sticky pause is the honest composition.
