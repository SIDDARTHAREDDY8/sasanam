# Sterile Cockpit — Executor Integration Design

**Wave-53 P1, 2026-09-22. Status: integration design + executor
integration shipped (executor-side enforcement + loop-contract
wiring).**

Parent: `workstreams/architect/STERILE_COCKPIT_DESIGN.md` (wave-52:
design + adversarial review + `gov/sterile.py` state-machine
prototype, deliberately no executor integration). This document
resolves the four named blockers from §12 into an integration
design, adversarially reviews the integration on paper, and records
the verdict: **integrate** — with explicit, named deployment
obligations for the loop side.

## 0. Verdict up front

The design review holds end-to-end **for the executor-mediated
surface**, and the loop contract is **wired, not just specified**:
on window entry the executor calls `freeze_context(snapshot_ref)`
and `withhold(channel)` for loop-owned channels; on close/expiry
it calls `release(channel)` (union semantics for nested windows)
and `reissue_reads()`; a half-implemented loop is rejected at
attach time. What the executor cannot do — verify a *real*
deployment loop honors the contract — remains a named boundary:
in-repo there is no model loop, so end-to-end sterility is proven
only against a synthetic loop (the `FakeLoop` in the integration
tests pins the call sequence). A deployment without the loop gets
executor-side enforcement only, declared in audit
(`loop_contract_absent` + per-channel
`window_declared_unenforceable`) — not claimed as end-to-end
sterility. Forcing a stronger claim would be dishonest; refusing
integration would waste a working enforcement layer over a
documented boundary.

Explicitly **not** shipped / still blocked (named, not hidden):
- Loop-side enforcement of C4/C6/C7 and `freeze_context` — the
  interface is specified; no in-repo loop implements it.
- C7 re-vetting at window entry — needs the compaction primitive
  (wave-50 residual, still open).
- Approval-web close UI — the queue path exists; the UI is a later
  wave.
- Taint tracking for pre-positioned poison — out of scope by
  design; §2 states the honest promise.

## 1. Blocker 1 — the deployment-loop contract (RESOLVED)

### 1.1 The interface

`gov/sterile.py::LoopContract` — an adapter interface the
deployment's model loop implements. Four methods, all deployment
side:

- `freeze_context(snapshot_ref) -> None` — the loop pins the
  agent's working context to the entry snapshot (the executor's
  `sterile_window_enter` event carries `snapshot_ref`: the policy
  hash + the log-seq range of tool results delivered this run).
  New arrivals on suspended channels are not added to context.
- `withhold(channel) -> None` / `release(channel) -> None` —
  the loop stops delivering / resumes delivering arrivals on a
  channel the executor cannot mediate (C4 operator messages, C6
  skill content, C7 summary state). The executor calls `withhold`
  on entry for each suspended loop-owned channel (skipping ones an
  outer window already holds) and `release` on close/expiry with
  union semantics — a channel is released only when no other open
  window still needs it.
- `reissue_reads(reads) -> [ReadResult]` — on window exit the
  executor hands the loop the refused-during-window read list;
  the loop re-issues each through the **full content-defense
  stack** and returns results with a `delta_vs_snapshot` flag.
  The loop MUST NOT mark re-issued content vetted (design §8 R4 —
  the invariant is pinned by test).

### 1.1a Wiring, handshake, and atomicity (paper-review round 2)

The contract is not just specified — the executor calls it.
`attach_loop_contract` runs an explicit capability handshake: a
loop that leaves any of the four methods as the base
`NotImplementedError` stub is rejected with `TypeError` at attach
time (half-implemented loops fail loud, never silently partial).
The `sterile_window_enter` audit event carries `snapshot_ref`
(`policy_hash` + `log_seq_first/last` of the run log), computed at
entry; the loop's `freeze_context` pins to that reference.

Atomicity across executor and loop is the deployment's
responsibility — a two-phase commit is not achievable from the
executor side. If a loop call fails (entry `freeze_context` /
`withhold`, close/expiry `release`, `reissue_reads`), the executor
audits `loop_contract_error{window, phase, error}` and continues
degraded: executor-side channel suspension still holds (the
executor's own gate is unaffected), and the loop-side gap is an
audited fact naming the failed phase, so a partially applied
entry (freeze ok, withhold failed) is visible to a reviewer, not
silent. `withhold` is expected to be idempotent across nested
entries; the executor additionally skips channels an outer window
already holds.

### 1.2 Degraded mode (the honest scoping)

`ToolExecutor.attach_loop_contract(loop)` installs the contract.
When windows are declared but no loop is attached, the executor
audits `loop_contract_absent` once per run and enforces
executor-side only: C1/C2/C3 suspension is real; C4/C6/C7 are
*declared suspended but unenforceable* — the declaration itself is
audited (`window_declared_unenforceable{channel}`) so the gap is
visible, not silent. The claim a deployment may make is then
"executor-side sterile windows," never "sterile cockpit."

### 1.3 Why this resolves the blocker

The wave-52 question was "define `freeze_context`/`withhold`
before claiming end-to-end sterility." The definition is now
written, with the degraded mode making the partial claim honest.
No in-repo model loop exists to integrate against — inventing one
would be theater. The executor integration does not wait for the
loop; it names the loop's obligations.

## 2. Blocker 2 — taint tracking for pre-positioned poison (RESOLVED as a boundary)

Taint tracking (data-lineage from fetch to critical arg) is **out
of scope** — the wave-53 brief says so explicitly, and building a
half-lineage would be worse than none (it would invite reliance).
The design therefore states exactly what the integration
**honestly promises** about pre-positioned poison:

1. **Frozen vetting verdicts.** At window entry the executor
   records `snapshot_ref`: the policy hash and the seq-range of
   tool results delivered this run. "Pre-vetted" means "passed the
   content stack when delivered" — the window freezes the
   verdicts, it does not re-prove them.
2. **Entry-time re-scan (opt-in, `entry_rescan: true`).** The
   executor retains delivered read contents (`_read_contents`,
   capped at `_MAX_READ_STORE`). At window entry it re-runs the
   *current* DLP/content stack over the retained pre-window
   content. This catches *stack improvements since delivery*
   (a pattern added after the fetch); it does **not** catch
   lineage — a clean-looking poison is still clean-looking.
   Findings route to audit (`window_entry_rescan_hit`), never to
   silent remediation.
3. **Explicit non-promise.** No data-lineage, no
   fetch→arg provenance. Poison already in context before entry
   is unaffected — boundary R1/§9.1 stands unchanged.

The honest claim remains: the window governs *mid-operation
arrival*, never *pre-positioned content*.

## 3. Blocker 3 — close-verification semantics (RESOLVED)

The wave-52 question: can the executor verify *task* completion,
or is `agent_declared` close permanently a judgment call? Answer:
**the executor verifies mechanics; completion stays a judgment
call, surfaced in policy.** The integration implements both close
paths as specified in design §5–§6:

### 3.1 The `window_close` primitive

`ToolExecutor.request_window_close(identity, window_id=None,
approval_id=None)` — a governance method, **not a tool**. It is
never dispatched through `call()`'s tool path:

- A literal `call(identity, "window_close", ...)` is denied in the
  sterile gate (`policy_id: sterile-reserved`, audited
  `window_close_denied{reason: reserved_tool_name}`) — tool-call
  parameters can never reach the controller.
- The caller identity is verified (`_check_identity`); a failed
  identity never mutates window state.
- LIFO is enforced by the controller; non-innermost and
  no-window closes are denied and audited.

### 3.2 `agent_declared` — mechanics verified

Grant conditions (all must hold): window open, target is
innermost, caller is the run's agent identity, no approval
pending for a call made inside the window. On grant the
controller returns the refused-during-window read list; the
executor audits a single merged `sterile_window_exit{reconcile:
[...]}` (the controller's exit event is folded into the
executor's — one event per close, not two) and — if a loop
contract is attached — hands the list to `loop.reissue_reads()`.
Without a loop the list is recorded as `reconcile_pending` (the
deployment fulfills it).

The pending-approval check uses a strict reading, deliberately:
an approval queued at/after window entry blocks `agent_declared`
close — *including the trigger call's own approval* (under the
default policy, outbound sends queue for approval, so the call
that opened the window is frequently the pending one). Rationale:
the window quarantines the critical operation's mid-flight
arrivals; closing it while the operation that opened it is still
awaiting human review would end the quarantine before the
critical action resolves. The human decides the approval, then
close proceeds; window expiry remains the backstop if the human
never responds. `human_approval` windows skip this check — the
human's explicit close approval is the judgment call.

### 3.3 `human_approval` — the approval-queue round trip

`request_window_close` with no `approval_id` **queues** a close
request via the existing approval queue
(`action={"tool": "window_close", "window": <id>, "type":
"window_close"}`, `PolicyDecision("require_approval", ...,
policy_id="sterile-window-close")`, F42 `caller_identity`) and
returns `{"closed": False, "status": "queued", "approval_id":
...}`. The deployment's human approves in the normal queue flow.
The deployment then calls `request_window_close(identity,
window_id, approval_id=...)`; the executor verifies the record:
exists, `status == "approved"`, `run_id` matches, `action.type ==
"window_close"`, `action.window` matches, `decided_at` within
`approvals.ttl_hours`, not `late_decision`. Any failure → denied
and audited. This reuses the queue's MAC/digest integrity
(F38/F43) instead of inventing a second human channel.

Wave-53 review fix: the first implementation verified only the
record's *fields* (status, run_id, window, TTL) via
`ApprovalQueue.get()`, which does NOT verify the MAC on read — a
post-decision rewrite of the queue file would have passed the
field checks. `_verify_close_approval` now verifies the keyed
digest first via `approval_digest_ok` (the F34/F43 invariant:
every state-changing path verifies the digest, same as
`execute_approved()`), failing closed on a tampered record.
Regression: `test_close_approval_post_decision_tamper_denied` in
`tests/test_w53_sterile_integration.py`.

### 3.4 The residual (§6, unchanged)

The executor cannot verify "the migration really finished."
`agent_declared` close is a policy-author judgment — the lint
(§5) warns when `on_tools` matches known-irreversible tool
families with `agent_declared`. Irreversible windows default to
`human_approval` by convention, enforced by review, not by proof.

## 4. Blocker 4 — refusal-rate telemetry (RESOLVED)

Every refusal is already audited (`window_suspended_refusal`).
The integration adds the telemetry *use*:

- `ToolExecutor.sterile_refusal_summary()` → `{window_id:
  {"refusals": n, "enter_count": m}}` from in-executor counters
  (deterministic; the hash-chained log remains the durable
  record and is independently queryable).
- Optional per-window `refusal_alert_after: N` (non-negative
  int, validated at load). When refusals in the current
  incarnation exceed N, the executor audits
  `window_refusal_rate_alert` — the deployment's signal that the
  window is mis-scoped (too broad, too long, wrong channels),
  per design §10. High refusal rate is a *policy-tuning*
  signal, never a user problem.
- Expiry runs at the top of the sterile gate on every `call()`
  (`_sterile_expire`), so windows expire even on quiet runs
  (fail-closed). Expiry is not a bare controller pop: the executor
  releases loop-withheld channels (union semantics), re-issues the
  refused-during-window read list through `loop.reissue_reads()`
  when a loop is attached (never marked vetted — R4), and emits
  one merged `sterile_window_exit{reason: expired, task:
  incomplete, reconcile, released_channels}` per expired window.

## 5. Where the window lives inside `call()`

Placement (after the delegation-verification block, before the
role-allowlist check — `gov/executor.py`, "1b. sterile windows"):

1. **Tick** — expire overdue windows (fail-closed), drain
   controller events into the run log.
2. **Reserved name** — `tool == "window_close"` → denied.
3. **Entry** — `maybe_open(tool)` for identity-verified callers
   only; unverified callers never mutate window state. Entry
   happens even if the call is later denied/queued by policy
   (the attempt signals critical intent). DLP-blocked and
   identity-denied calls never reach the gate — documented.
4. **Refusal** — `check(tool)`; suspended channel →
   `{"status": "window_suspended", "window": <id>}` (audited);
   the call never executes. Unknown tools during an open window
   are refused fail-closed (`channel: unknown_tool`) —
   deployments register custom tool→channel mappings; the lint
   warns on unmapped tools in `on_tools`.
5. **Reconciliation** — on exit, per §3.2.

DLP still runs before the gate on the attempt path (content
analysis is side-effect-free); the canary tripwire still runs
first on the egress path (a trip halts before any window logic).
Default-off: no `critical_windows:` block → `self.sterile is
None` → zero behavior change (pinned by test).

## 6. Policy authoring — what authors declare, what the defaults are

- `critical_windows:` is a top-level policy key (added to
  `KNOWN_TOP_LEVEL_KEYS`; F90 unknown-key refusal applies).
  Invalid blocks raise `SterilePolicyError` at policy load —
  fail-closed load, never half-applied at runtime.
- `WindowPolicy` validation (from the prototype, unchanged):
  unknown channels, trusted-channel suspension, missing expiry,
  bare-`*` patterns, duplicate ids, missing rationale — all
  raise.
- New optional fields: `entry_rescan` (bool, default false),
  `refusal_alert_after` (non-negative int).
- `lint_windows(policy_block, known_irreversible=...)` returns
  *warnings* (not errors): `on_tools` matching no known tool
  (unmapped channel → fail-closed refusal at runtime),
  irreversible-family tools with `agent_declared` close,
  `suspend: []` (a window that suspends nothing — probably a
  mis-declaration), `max_duration_s` outliers. Warnings are for
  the simulator/review workflow (§8 R2 mitigation).
- Safe defaults: feature off unless declared; `close_policy`
  defaults to `agent_declared` (the lint pushes irreversible
  tools toward `human_approval`); `max_duration_s` mandatory
  (no immortal windows).

## 7. Adversarial review of the integration (on paper)

**Pre-positioned poison.** Unchanged boundary (R1). The
integration promises §2's three items and nothing more. An
evaluator re-running the wave-52 R1 probe against the integrated
executor gets the same result: pre-window poison in the frozen
snapshot is unaffected. The `entry_rescan` option narrows the
*stale-stack* sub-case only; the design says so.

**Window-escape via tool-call parameters.** The controller is
reachable only through `maybe_open`/`check` (called by the
executor, never the agent) and `request_window_close` (identity-
checked method). Tool-call kwargs never reach it; the
`"window_close"` tool name is reserved and denied. An agent
smuggling `window_close` inside another tool's params gets a
normal tool execution — the params are data to that tool.
**Holds.**

**Reconciliation-read injection.** The exit path hands the
refused-read list to the loop for re-issue through the content
stack; the executor never marks reconciled content vetted, and
the `post_window_delta` attachment is flagged for review, not
trusted. The R4 invariant ("a future implementer who optimizes
this into a trusted refresh re-opens the hole") is pinned by a
test asserting the exit path never sets a vetted flag.
**Holds**, conditional on the loop honoring `reissue_reads`
— a deployment obligation, named in §1.

**Over/under-declared critical patterns.** Over-declaration →
`overly_broad_window` lint error (bare `*`) + `refusal_alert_after`
telemetry signal; under-declaration → `lint_windows` warning
(irreversible tool without a window) naming the gap. Residual
judgment risk documented (§6 of the parent design) — inherent,
not fixable by mechanism.

**Refusal-DoS (attacker keeps the agent in windows).** Windows
open only on the agent's own tool calls matching declared
patterns (R8: executor-side entry, agent cannot opt out — and
conversely an *attacker* cannot open windows except by
influencing the agent's pre-window plan, which is the
pre-positioning boundary). Every window has mandatory expiry;
every refusal is audited; starvation is observable, unlike
silent poisoning. Prolonging via injected sub-tasks is bounded
by the same expiry. **Holds** — DoS is the fail-closed
direction.

**Net:** no review item blocks integration. The integration is
*not* an end-to-end sterility claim — it is executor-side
enforcement with a specified loop contract and documented
boundaries. That is the honest shape, and it ships.

## 8. What the executor refuses vs. what it audits

| Situation | Executor action |
|---|---|
| Tool whose channel ∈ suspend set, window open | **Refuse** `window_suspended` (audited) |
| Unknown tool, window open | **Refuse** fail-closed (audited) |
| `window_close` as a tool call | **Deny** reserved name (audited) |
| C4/C6/C7 arrival during window, no loop contract | **Audit** `window_declared_unenforceable` (cannot withhold) |
| C4/C6/C7 with loop contract | Loop withholds per §1.1; executor audits the declaration |
| Pre-positioned poison | **Boundary** — unaffected (R1); entry re-scan optional |
| Refusals beyond `refusal_alert_after` | **Audit** `window_refusal_rate_alert` (tuning signal) |
| Close-escape attempts (non-LIFO, no window, bad approval) | **Deny** + audit `window_close_denied` |

## 9. File map (shipped this wave)

- `gov/sterile.py`: `LoopContract` interface, `lint_windows()`,
  `refusal_alert_after` + `entry_rescan` optional fields,
  `SterileController.peek()` (executor reads entry metadata for
  expiry reconciliation and the pending-approval check).
- `gov/log.py`: `ActionLog.tail_seq` read-only property (entry
  snapshot reference; no log behavior change).
- `gov/policy.py`: `critical_windows` top-level key + fail-closed
  validation at load.
- `gov/executor.py`: controller construction (opt-in),
  `attach_loop_contract()` with capability handshake, the `call()`
  gate (1b), reserved name, `request_window_close()` (merged
  single exit event, pending-approval check, channel release),
  `sterile_tick()` / `_sterile_expire()` (expiry with loop
  release + reconcile re-issue), `sterile_refusal_summary()`,
  entry re-scan, loop-absent audit + per-channel
  `window_declared_unenforceable`, `loop_contract_error` audit on
  loop failures.
- `tests/test_w53_sterile_integration.py`: 29 tests pinning the
  integration (default-off, fail-closed load, entry/refusal/
  close/queue-approve/expiry/telemetry/loop-absent, plus the
  paper-review-round-2 wiring: freeze/withhold/release call
  sequence, union release on nesting, snapshot_ref on enter,
  pending-approval denial, half-loop rejection, single exit
  event, loop-error audit).
- This document.

## 10. Open questions for Wave-54+

1. Approval-web close UI for `human_approval` windows (queue
   path exists; UI deferred).
2. C7 re-vet at entry when the compaction primitive lands.
3. Empirical tuning: refusal-rate data informing
   `max_duration_s`/`suspend` defaults per deployment.
4. `LoopContract` reference implementation against a real
   deployment loop (none in-repo to bind against).
5. Blast-radius simulator replay for `critical_windows`
   (design §8 R2 mitigation, not yet built).
