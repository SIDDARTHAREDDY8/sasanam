# F152 — Capability gate on the approval-execution sweep spec

**Finding:** F152 (MEDIUM), filed 2026-09-24. The capability gate (Wave-101) verifies
assessment existence, freshness, binding, and seal on `ToolExecutor.call()` and
`ToolExecutor.spawn_sub_agent()` — but `ToolExecutor.execute_approved()`, the sweep that runs
human-approved queued actions, never consults the gate. Break battery:
`evals/f152_hunt_break.py`, probes t1a/t1b/t1c BREAK (approved write executes with the
assessment removed / expired / downgraded to INSUFFICIENT between approval and sweep),
t1d HELD (`call()` post-removal refuses).

## Problem

The gate's contract — "governed-core execution requires a bound, fresh, SUFFICIENT, sealed
capability assessment" — is enforced at queue time but not at execution time. The approval is
legitimate (quorum intact, MAC-bound), so no approval-layer check catches this: an assessment
rotated, revoked, or downgraded between the human's decision and the sweep still executes.
Two of three execution paths are gated; the sweep is the third.

## Seams (existing, public — no new seams)

- `ToolExecutor.execute_approved()` — the sweep seam (observe executed actions + the
  quarantined side effect; do NOT reach inside `_execute_approved_locked`).
- `ToolExecutor.update_capability_assessment(assessment)` — the rotation seam.
- `gov.capability_gate.verify_assessment(binding, assessment)` — the gate seam (already used
  by `_check_capability_gate`).

## Design

Re-verify the capability assessment at the execution boundary, inside
`_execute_approved_locked`, once per approved record, immediately after the F135
delegation re-validation block (the precedent: delegation tokens are re-checked at the same
boundary for the same reason — state can change between approval and sweep).

1. **Check.** If `self._capability_gate_binding` is bound, run
   `capability_gate.verify_assessment(binding, self._capability_assessment)` — the same
   function `call()` enforces through `_check_capability_gate`, so the contract is identical:
   assessment exists, fresh, bound to this harness (id + config digest), report digest
   matches, sealed by a trusted key, aggregate verdict SUFFICIENT.
2. **Refusal.** On `CapabilityGateRefusal`: refuse via the sweep's existing `_refuse`
   helper — flag `capability_gate_failed_at_execution`, `policy_id`
   `capability-gate-execution-refused`, reason naming the approval id, the refusal cause
   (machine-readable, from `refusal_cause`), and the refusal message. The record keeps
   `execution_refused_reason` and stays **approved-but-unexecuted** (fail-safe, retriable):
   a fresh assessment (or a rebuilt executor with one) lets a later sweep execute it —
   the queued record stores no assessment reference, mirroring the F135 comment that the
   approval stands while the gate checks CURRENT state.
3. **No binding.** Executors with no gate bound (raw pipeline, acknowledged-ungoverned mode)
   skip the check: they have no gate to re-run, and today's sweep behavior is unchanged.
4. **Audit.** The refusal chains the standard `approval_execution_refused` event with the
   refusal cause in the reason string (same pattern as every other execution-time
   re-validation). No second `capability_gate_refused` chain here: `_refuse` is the sweep's
   single refusal record, as with the F135 delegation refusals.

## What this does NOT do

- It does not bind the assessment to the approval record at queue time (the closure
  direction's alternative). Current-state verification is strictly stronger against
  rotation and keeps the retriable approved-but-unexecuted posture.
- It does not gate D1-bridge records (foreign-executed, never swept — skipped before this
  point) or executors that never bound a gate.

## Close-when

- t1a/t1b/t1c flip to HELD (sweep refuses with no / expired / insufficient assessment),
  t1d stays HELD, t2* and t3* unchanged.
- Regression tests pin the sweep path at the public seam: refusal on removed / expired /
  insufficient assessment (record kept approved-but-unexecuted with
  `execution_refused_reason`), execution resumes on rotation back to a valid assessment,
  and no-behavior-change for unbound (acknowledged-ungoverned) executors.

## Residuals (honest)

- Direct edits to `gov/` still bypass the runtime gate (governing-the-governors threat —
  the gate is a runtime check, not code integrity).
- Assessment freshness is a deployment risk decision (`freshness_seconds` is
  deployment-set); a short window is a deployment choice, not enforced here.
- The sweep's other execution-time re-validations (expiry, integrity, policy staleness,
  delegation, volume) are unchanged; this adds the capability dimension.
