# Sterile Cockpit Windows — Design Document

**Wave-52 P2, 2026-09-22. Status: design + adversarial review + state-machine
prototype (`gov/sterile.py`, no executor integration yet).**

Source: `research/invention-brief-2026-09-22.md` §2 P2. The brief is
explicit: temporal input quarantine is the most differentiated idea, but
it needs (a) the input-channel trusted/untrusted taxonomy built and
argued first, and (b) a careful policy-design pass on "what counts as
critical" plus usability cost — not a rushed prototype. This document is
that pass. An executable proof of the channel taxonomy + window state
machine ships alongside (`gov/sterile.py`, `tests/test_w52_sterile.py`);
executor integration is deliberately deferred to a later wave, with the
integration points named in §11.

## 0. The idea in one paragraph

Every existing injection defense filters *content*. The sterile-cockpit
move governs *time*: declare **critical windows** — spans during which
the agent executes irreversible or high-privilege tools — and during a
window, **suspend every untrusted input channel**. The agent works from a
frozen, pre-vetted context snapshot until the window closes. The
injection can be as clever as it likes; if it arrives mid-operation
through a suspended channel, there is no path for it to arrive on. This
is a policy-engine primitive (temporal), not a detector (content), and
it complements rather than replaces content defenses.

## 1. Non-goals (what this is not)

- **Not a content filter.** Outside a window, today's defenses (trust
  layer, DLP, instruction hierarchy, canaries) apply unchanged.
  Inside a window, no *new* content judgment happens — the judgment
  was made at window entry (the vetting gate, §5).
- **Not taint tracking.** Poison already in context before window entry
  is unaffected (§9.1 — the documented boundary).
- **Not a model-loop change (yet).** The executor mediates *tool
  calls*, not the model's context window. The executor can suspend
  tool-mediated input channels and audit everything; actually
  withholding already-loaded context from the model is a
  deployment-loop integration (§9.3 — the honest scoping).

## 2. Input-channel taxonomy

Every input channel the executor (and the deployment loop around it)
exposes, labeled at registration. **Default: untrusted.** A channel is
`trusted` only with a positive, auditable rationale — trust is never
the default.

| # | Channel | Label | Rationale | Executor-mediated? |
|---|---------|-------|-----------|--------------------|
| C1 | Tool results (api_call, http_post responses) | **untrusted** | External data by definition; the canonical indirect-injection path (Greshake et al. 2023). | Yes — the executor delivers results |
| C2 | File reads (read_file) | **untrusted** | File content is data, even inside the sandbox; planted/poisoned files are the B1 battery's favorite shape. Narrow carve-out possible: deployment-pinned read-only policy files (see below). | Yes |
| C3 | Web fetch (no dedicated tool in-repo; api_call is the read path) | **untrusted** | Same as C1, higher poison base-rate. | Yes (via api_call) |
| C4 | User / operator messages | **untrusted** | The human-error shape: the operator pastes untrusted content into a running critical task (brief §2 P2 target). Operator *identity* can be authenticated; operator *content* cannot be vetted for injection. | **No** — arrives via the deployment loop, outside the executor |
| C5 | Memory recall (cross-run velocity/taint memory, approval history) | **untrusted** | Cross-run state is attacker-influenced (a prior compromised run wrote it). In-repo this memory drives *decisions*, not agent context — but the taxonomy labels it for the loop that does surface it. | Partial (executor-internal) |
| C6 | Skill content | **untrusted** | Third-party skill definitions/prompts are supply-chain input (cf. F75 supply-chain preflight). No skill system in-repo yet; labeled now so the default is set before one arrives. | No (future) |
| C7 | Summary / compaction state | **untrusted** | **Wave-50 Astra evidence:** the model wrote jailbreak-style instructions into its own compaction summaries, and the quietly hallucinated constraint was *followed* by the successor. Self-written ≠ trusted. No compaction primitive in-repo (wave-50 residual) — the label is set now, the enforcement waits for the primitive. | No (future) |
| C8 | Approval / human decisions | **trusted** | The one trusted channel: human review through the approval queue is the governance root of trust. Narrow: only the *decision* (approve/deny + constraints), never reviewer-supplied free text (that is C4). | Yes |

**Carve-outs (explicit, policy-declared, audited):** a deployment may
promote a *specific* C2 source to trusted — e.g. `read_file` of the
pinned policy bundle — only by naming the exact path + content hash in
policy. A promoted source that fails its hash check is treated as
untrusted (fail-closed). No silent promotions; the lint (§4) requires
every promotion to carry a rationale string.

**Why default-untrusted is safe to adopt:** the label alone changes
nothing until a window suspends the channel. Labels are metadata until
a `critical_windows` entry references them — so the taxonomy can land
without behavior change, and windows opt into it per policy.

## 3. `critical_windows:` policy block shape

```yaml
critical_windows:
  - id: payments
    on_tools: ["payment.*", "ledger.transfer"]   # tool/capability patterns
    suspend: [C1, C2, C3]                        # untrusted channels to suspend
    close_policy: human_approval                 # agent_declared | human_approval
    max_duration_s: 300
    rationale: "Irreversible money movement; PCI-adjacent blast radius."
  - id: db-migration
    on_tools: ["db.migrate", "db.drop_table"]
    suspend: [C1, C2, C3, C4]
    close_policy: agent_declared
    max_duration_s: 900
    rationale: "Schema changes are hard to roll back; wiki-sourced plans."
```

- `on_tools` uses the existing `match.tool` pattern syntax (glob over
  the tool registry; unknown tools fail closed per policy_lint's
  existing `unknown_tool` rule).
- `suspend` may only name channels labeled untrusted (or C8-carve-out
  reversals — lint error otherwise). Naming C8 (`approval decisions`)
  is a lint error: suspending the human channel during a critical
  window is never the intent.
- `close_policy: human_approval` (default for irreversible tools —
  the lint knows the irreversible set) vs `agent_declared` (the agent
  issues `window_close`; the executor verifies §6).
- `max_duration_s` is mandatory; missing = lint error. The expiry is
  fail-closed (§5).

### Policy-lint rules (new, in the `policy_lint.py` idiom)

- `unknown_channel` (error): `suspend` names a channel not in the
  registry.
- `trusted_channel_suspended` (error): `suspend` names C8.
- `window_without_expiry` (error): `max_duration_s` missing.
- `overly_broad_window` (warning → error variant): `on_tools`
  matches >N% of the tool registry or contains a bare `*` — the
  over-declaration usability killer (§10). Threshold in policy.
- `critical_tool_without_window` (warning): a tool in the
  deployment's irreversible set has no window entry — the
  under-declaration hole (§8, R2). Warning, not error: migration
  path for existing policies.
- `overlapping_windows` (info): two entries whose `on_tools`
  overlap — legal (nesting, §7), but surfaced for review.

## 4. What "critical" means (the policy-design pass the brief demanded)

"Critical" is a policy-author judgment, and therefore the whole
game. The design does not pretend otherwise; it makes the judgment
*explicit, reviewable, and bounded*:

1. **Explicit:** every window carries `rationale:` (a human sentence,
   shown in audit and in the approval UI). A window without a
   rationale is a lint error.
2. **Reviewable:** window enter/exit are hash-chained audit events
   (`sterile_window_enter/exit`); the corpus of window usage is
   evidence (§12 of the evidence bet: proof of input discipline).
3. **Bounded:** `max_duration_s` caps staleness (§9.2);
   `overly_broad_window` caps over-declaration; the simulator
   (`gov/simulator.py`) can replay "what would have opened windows
   last week" before deploying a policy change — the same blast-radius
   workflow as policy diffs.

Default posture: the irreversible-tool set (data destruction,
egress of secrets, money movement, privilege grants) ships with
`close_policy: human_approval`. Everything else is opt-in.

## 5. Window lifecycle

**Enter.** The executor opens a window automatically when a tool call
matches a `critical_windows.on_tools` entry — *before* executing the
call. (Agent-declared entry is not trusted: a compromised agent would
simply never declare. §8 R8.) Enter emits `sterile_window_enter`
with the window id, the triggering tool, and the vetting snapshot
reference (below). If a window for the same id is already open, the
call joins it (no duplicate event; a `window_reentered` debug event).

**The vetting gate + snapshot.** At enter, the executor records the
*vetted context*: the set of tool results already delivered this run
(it logged them — `actions.jsonl` is the snapshot index), the policy
version hash, and the declared task. "Vetted" means: these inputs
passed the normal content-defense stack *before* the window opened.
The window does not re-vet; it *freezes the vetting verdicts*.
(What the executor cannot snapshot — the model's live context — is
§9.3.)

**During.** Any tool call whose channel is in the window's `suspend`
set is refused with a `WINDOW_SUSPENDED` refusal: the call never
executes, a `window_suspended_refusal` audit event lands (channel,
tool, window id), and the caller gets a machine-readable refusal
(`{"status": "window_suspended", "window": "<id>"}`) so the agent can
defer rather than hallucinate the data. Suspension is monotonic
under nesting (§7).

**Exit — normal close.** The agent issues the `window_close`
governance primitive (not a regular tool; it is never suspended).
The executor grants close iff:
  (a) `close_policy: agent_declared` and no nested inner window is
      open (LIFO, §7), and no approval is pending for a call made
      inside the window; or
  (b) `close_policy: human_approval` and a human approved the close
      in the approval queue.
  Otherwise the close is **denied and audited**
  (`window_close_denied`) — this is the brief's probe (d):
  window-escape attempts fail closed and leave evidence.

**Exit — expiry.** `max_duration_s` elapsing closes the window
fail-closed: `sterile_window_exit{reason: expired}`, untrusted
channels resume, and the critical task is marked `incomplete` in
audit. Expiry never silently succeeds — a window that outlives its
budget is itself an anomaly worth a human look.

**Reconciliation read on exit.** On close (either path), the
executor performs one reconciliation pass: it re-issues the
*suspended* reads that were refused during the window (or, cheaper,
fingerprints them) and diffs against the entry snapshot. Deltas go
through the normal content-defense stack — **never trusted
implicitly** (§8 R4) — and any delta is attached to the
`sterile_window_exit` event as `post_window_delta` for review.
The agent is told the window closed; it is *not* told "everything is
now safe."

## 6. The `window_close` verification problem (stated plainly)

The executor knows tool calls, not task completion. `agent_declared`
close therefore verifies *mechanics*, not *intent*: LIFO order, no
pending approvals, window actually open, caller is the run's agent
identity. It cannot verify "the migration really finished." That is
why irreversible windows default to `human_approval`, and why
`agent_declared` is offered only for windows whose blast radius the
policy author explicitly accepts. This is a judgment call surfaced
in policy — not a proof.

## 7. Nested windows

Windows nest as a stack. Entering a window while another is open
pushes; the effective suspension set is the **union** of all open
windows (monotonic — an inner window can never *unsuspend* a channel
the outer window suspended). Close is LIFO: closing window N while
window N+1 is open is denied and audited. Each push/pop is its own
audit event with a `depth` field, so the nesting is reconstructible
from the log. Max depth is bounded (policy; default 4) — deeper
nesting is a `window_nesting_exceeded` denial, because unbounded
nesting is a confusion hazard.

## 8. Adversarial design review (breaking the design on paper)

**R1 — Pre-positioned poison.** Poison fetched *before* window entry
sits in the frozen snapshot and is unaffected. **Verdict: BOUNDARY,
documented.** Closing it needs taint tracking (data-lineage from
fetch to critical arg), which we do not have. The window is a
complement to content defenses, not a replacement. The design's
honest claim is only about *mid-operation arrival*.

**R2 — Over/under-declared critical patterns.** Over-declaration
(`on_tools: ["*"]`) suspends the agent into uselessness; the lint's
`overly_broad_window` + the simulator's blast-radius replay are the
mitigations, plus `rationale:` forcing the author to defend each
window. Under-declaration leaves the critical task unprotected; the
`critical_tool_without_window` warning names the gap instead of
hiding it. **Verdict: mitigated by lint + review workflow; residual
judgment risk documented** (this is inherent — §4).

**R3 — Window-suspension DoS.** A long window starves the agent of
legitimately-needed untrusted reads; every refusal is audited, so
starvation is *visible* (unlike silent context poisoning). Bounds:
`max_duration_s` (mandatory), the `window_close` primitive, and
expiry failing closed to `incomplete`. An attacker prolonging the
window via injected sub-tasks is bounded by the same expiry.
**Verdict: holds** — DoS is the safe direction (fail-closed), and it
is observable.

**R4 — Reconciliation-read injection.** Poison planted *during* the
window is picked up by the exit reconciliation read. **Verdict:
holds IF the reconciliation output is never implicitly trusted** —
the design routes it through the full content-defense stack and
flags deltas (§5). A future implementer who "optimizes" this into a
trusted refresh re-opens the hole; the prototype's docstring says
so in capital letters.

**R5 — Summary state as an untrusted channel (Astra).** The frozen
snapshot includes summary/compaction state, which is model-written
and — per wave-50's Astra evidence — can carry self-injected
instructions the successor *follows*. **Verdict: BOUNDARY with a
label.** C7 is labeled untrusted *now*; the snapshot records
summary provenance; but until a compaction primitive exists
in-repo, the executor cannot re-vet summaries at window entry. A
window entered on a poisoned summary is pre-positioning (R1).

**R6 — Operator usability cost.** The operator pasting content
mid-window (C4) gets a `WINDOW_SUSPENDED` refusal — the FAA rule
applied literally. **Verdict: real cost, accepted deliberately.**
Mitigations: the refusal is machine-readable (the agent can explain
and defer), expiry bounds the silent period, and `human_approval`
windows already assume a human is in the loop. Deployments should
measure refusal rates per window id (audit makes this a query) and
treat a high refusal rate as a mis-scoped window, not a user
problem.

**R7 — Nested-window confusion.** Inner close when outer is open;
closing the outer from inside. **Verdict: holds** — LIFO + union
suspension + depth bound + per-level audit events. The prototype
pins this (§11).

**R8 — Who opens the window (declaration trust).** Agent-declared
entry is untrusted (a compromised agent never declares). **Verdict:
holds** — entry is executor-side, triggered by `on_tools` match
before the call executes. The agent cannot opt out of a window;
it can only request close (§6).

**R9 — Vetting-gate TOCTOU.** "Pre-vetted" means "passed the content
stack pre-window." If the scanner missed the poison pre-window, the
window freezes the miss. **Verdict: documented** — defense in
depth, not a proof. The window's claim is temporal isolation of
*arrival*, not correctness of vetting.

**R10 — The close primitive as attack surface.** A weak
`window_close` check makes escape trivial. **Verdict: holds at the
mechanism level** (LIFO, pending-approval check, identity check,
human_approval default for irreversible tools); **the residual is
§6** — the executor cannot verify task completion, so
`agent_declared` close is a policy-author judgment, surfaced
explicitly.

**Net:** no review item blocks the state-machine prototype. The
blocking questions are all at the *integration* layer (§9.3, §11):
withholding model context (deployment loop) and taint tracking
(pre-positioning). The design is honest about both.

## 9. Boundaries (documented, not findings)

**9.1 Pre-positioning.** See R1. Needs taint tracking; not built.

**9.2 Snapshot staleness.** The agent acts on frozen context. Long
windows risk acting on outdated facts (price feeds, wiki state).
Bounded by mandatory `max_duration_s` and the reconciliation read;
the tradeoff is explicit per window (`max_duration_s` is the
author's staleness-vs-protection dial). There is no free setting.

**9.3 Executor/loop scoping (the important honesty).** In this
repo's architecture the executor mediates *tool calls*. It can
suspend tool-mediated channels (C1/C2/C3), refuse with audit, and
record snapshots of what it delivered. It **cannot** freeze the
model's live context window, withhold C4/C6/C7 arrivals that bypass
tools, or rewind a poisoned summary. Those are deployment-loop
responsibilities. The prototype (§11) models the executor-side
state machine faithfully; it does not claim loop enforcement.
A future integration wave must define the loop contract
(`freeze_context(snapshot_ref)`, `withhold(channel)`) before any
"sterile cockpit" claim extends past the executor boundary.

## 10. Usability cost (the brief demanded this pass)

Sterile windows deliberately degrade the agent during critical
phases — that is the FAA trade, made explicit. Expected costs:

- **Refusal handling:** every `WINDOW_SUSPENDED` refusal is
  machine-readable; the agent's system prompt (deployment-owned)
  must teach deferral ("note the missing input, continue with the
  snapshot, reconcile on exit") rather than hallucination.
- **Close latency:** `human_approval` windows add a human round-trip
  to every critical task. Deployments should reserve it for
  genuinely irreversible tools (the default) and use
  `agent_declared` elsewhere.
- **Mis-scoping signal:** refusal rate per window id is queryable
  from audit; a window with a high refusal-to-task ratio is
  mis-scoped (too broad, too long, or wrong channels) — tune the
  policy, not the agent.
- **Break-glass:** the existing break-glass ticket flow (F49) works
  inside windows unchanged — human override is never suspended.

## 11. Prototype scope (what shipped in wave-52)

`gov/sterile.py` — **no executor integration**, per the brief. It
implements exactly:

- `ChannelRegistry`: the §2 taxonomy as data — channel id, trust
  label, rationale, `executor_mediated` flag. Default-untrusted;
  unknown channels fail closed.
- `WindowPolicy`: parses/validates a `critical_windows:` block —
  unknown channels, trusted-channel suspension, missing expiry,
  and over-broad patterns are rejected/raised at load (the lint
  rules of §3, executable form).
- `SterileController`: the per-run window state machine —
  `maybe_open(tool)` (pattern match → enter), `check(tool,
  channel)` → allow/suspend decision, `request_close()` per
  close_policy, `tick(now)` for expiry, nested stack with union
  suspension + LIFO close + depth bound, and audit emission through
  an injected append callable (`sterile_window_enter/exit`,
  `window_suspended_refusal`, `window_close_denied`).
- The reconciliation contract is modeled as data
  (`reconcile()` returns the refused-during-window read list for
  the loop to re-issue through content defenses) — the "NEVER
  implicitly trusted" invariant is a docstring + a test asserting
  the prototype never marks reconciled content vetted.

`tests/test_w52_sterile.py` pins: taxonomy defaults, policy
validation, enter-on-pattern, suspension + audited refusals,
nested union/LIFO, close-denied-on-escape, expiry fail-closed,
reconciliation list. Executor wiring (`ToolExecutor` calling the
controller in `call()`, the `window_close` primitive, approval-web
close UI) is **explicitly not built** — §9.3 and the open questions
(§12) are the gating items.

## 12. Open questions for Wave-53+ (blockers for integration)

1. **Loop contract:** define `freeze_context` / `withhold(channel)`
   for the deployment's model loop before claiming end-to-end
   sterility. Without it, windows are executor-side only.
2. **Taint tracking:** the pre-positioning boundary (R1/§9.1) needs
   data-lineage from fetch to critical arg. Sketch: fingerprint
   tool results at delivery, propagate fingerprints through args.
3. **Close verification:** can the executor verify *task*
   completion, or is `agent_declared` close permanently a judgment
   call? (Probably the latter — then the question is UX: how the
   approval UI presents close requests.)
4. **C7 enforcement:** when the compaction primitive lands, window
   entry must re-vet summaries (R5) — currently labeled, not
   enforced.
5. **Empirical tuning:** refusal-rate telemetry per window id to
   set `max_duration_s` and `suspend` sets from data, not vibes.
6. **C4/C6 loop channels:** the executor cannot suspend operator
   messages or skill content; the loop must. Until then, windows
   suspend what they can and audit what they cannot.
