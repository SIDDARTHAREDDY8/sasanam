# RT21 — Sterile Cockpit Break-First Report (Wave 54, Priority 1)

**Date:** 2026-09-22. **Pattern:** RT21 (sterile-cockpit enforcement).
**Surface reviewed:** `gov/sterile.py`, sterile integration in
`gov/executor.py`, `tests/test_w53_sterile_integration.py`, approval
digest/decision behavior in `gov/approvals.py`.

## Battery

Ephemeral break-first battery `/tmp/w54_rt21_breakfirst.py` (24
probes, pre-fix) + 7 registered registry probes + 8 unit tests
(`tests/test_w54_rt21_f124.py`).

**Pre-fix:** 16 HOLD, **1 genuine MISS**, 2 RESIDUAL, 5 BOUNDARY,
0 ERROR.

**Post-fix:** 17 HOLD, 0 MISS, 2 RESIDUAL, 5 BOUNDARY, 0 ERROR.

## The one genuine miss: F124 (MEDIUM, CLOSED 2026-09-22)

An approved human window-close approval could close a first window
entry, then be **replayed** to close a newly opened entry with the same
window id in the same run and TTL — with no fresh human decision.
`_verify_close_approval` checked run match, approved status,
tool/window match, and TTL, but nothing marked the approval used.

**Fix (additive, fail-closed):**
- `gov/approvals.py`: `window_close_consumed` added to
  `_SECURITY_PAYLOAD_FIELDS` — consumption state is digest-bound.
  Pre-change queued records fail current digest verification (schema
  upgrade: drain the queue before upgrading).
- `gov/executor.py`: `_verify_close_approval` rejects
  `window_close_consumed`; new `_consume_close_approval` flags and
  re-MACs via crash-atomic queue `_rewrite` (F38/F57 pattern) and
  audits `window_close_approval_consumed`. Consumption happens only
  after a *successful* close — a failed close does not burn the
  approval (pinned: `redteam.rt21.failed_close_no_burn`).
- `attach_loop_contract` while windows are open now audits
  `loop_contract_attached_with_windows_open`; open windows are NOT
  retro-engaged (pinned: `redteam.rt21.late_attach_audited`).

**Ordering residual (reviewed and hardened, wave-54):** consumption is
a second file write after the window is already closed and the exit
audited — no transaction spans the audit log and the queue file. If
the rewrite fails at that instant, the window stays closed but the
approval is unconsumed. That fault class is crash/disk between two
writes, not agent-reachable without run-dir write (F59 family), but it
is now **fail-loud**: `request_window_close` lands a
`window_close_approval_consumption_failed` audit event naming the
suspect approval and re-raises fail-closed. Pinned by
`test_consumption_failure_is_loud_not_silent`.

**Fix-verification probes (registry, all green):**
`redteam.rt21.close_approval_replay_stopped`,
`redteam.rt21.close_approval_consumed_bound`,
`redteam.rt21.fresh_approval_per_entry`,
`redteam.rt21.failed_close_no_burn`,
`redteam.rt21.late_attach_audited`.

## Residuals (documented, kept visible)

1. `redteam.rt21.expiry_pending_approval_asymmetry` — expiry does not
   run the agent-declared pending-approval check; pending actions stay
   pending, expiry records `task: incomplete`. Asymmetry, not bypass.
2. `redteam.rt21.human_close_pending_asymmetry` — a human-approved
   close can succeed while another in-window action approval is still
   pending; that action still needs its own human decision. Deliberately
   NOT hardened to deny: the wave-53 `test_human_approval_round_trip`
   legitimate flow relies on this.

## Boundaries (harness-trusted, not agent-reachable)

- A silently no-op loop cannot be verified by the executor (the loop is
  harness-trusted code; FakeLoop-only boundary).
- Re-attaching a second loop replaces the first; release/reissue route
  to the newest loop (harness wiring).
- Poison returned by `reissue_reads` is logged as `post_window_delta`,
  never marked vetted.
- No agent-facing detach API. Snapshot audit copy resisted loop-side
  mutation. No-loop mode emits `loop_contract_absent` plus
  per-loop-owned-channel `window_declared_unenforceable`.
- MAC stripping, cross-window/cross-run replay, and pending-record
  tampering all fail closed (digest verification at verify time).

## What this did NOT change

Wave-49's reverted SoD hardening and Wave-50's leaf-vs-envelope lesson
are untouched. No legitimate behavior was narrowed: fresh approvals
per entry, failed-close-no-burn, and agent-declared flows are all
pinned green.

## Accounting

- Findings: **F124 filed MEDIUM, CLOSED same wave.** Next free: F125.
  F81 remains LOW OPEN (unchanged).
- Unit: `tests.test_w54_rt21_f124` 8/8 green;
  `tests.test_w53_sterile_integration` 30/30 green (re-run 2026-09-22).
- Registry: 7 RT21 scenarios, all oracle-matched.
- Statistical pilot (`evals/trial_runner.py`): the 5 green RT21 pins
  held 25/25 (DETERMINISTIC-HOLD); the 2 asymmetry pins held 25/25
  "break" (DETERMINISTIC-RESID).
