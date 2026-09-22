# D1-core Design Spec: Durable Approval Queue — Delegation + Quorum

**Status:** DRAFT for engineering-lead review · **Date:** 2026-09-22
**Scope:** `gov/approvals.py` core design only. No production code, no test
code, no `gov/` or `tests/` edits in this document.
**Inputs:** `research/competitive-deep-dive.md` (AGT has M-of-N quorum; no
durable queue, no delegation), `workstreams/architect/STRATEGY_ROADMAP.md`
(§1 "D1 core queue work"), `workstreams/architect/REALWORLD_BAR.md`,
`gov/approvals.py`, `gov/approval_web.py` (docstring + structure),
`policies/default.yaml`, `gov/policy.py` + `gov/policy_lint.py`
(approvals sections), `gov/executor.py` (`execute_approved` /
`_execute_approved_locked`).

**Dependency note (F80):** the web-UI sections (§9) are **post-F80** — they
touch the same session/CSRF renderer paths as the in-flight logout-CSRF
fix and must land after it. Everything in §§1–8 (core `gov/approvals.py`
data model, state machine, policy surface, lint, CLI) proceeds
independently of F80.

---

## 0. Design summary

D1-core adds two capabilities to the durable approval queue:

1. **Delegation** — a pending record's decision stewardship can be
   reassigned from one human principal to another. Delegation is a MACed,
   audited transition. It can **never** route back to the requesting agent.
2. **Quorum** — a record can require M-of-N authenticated human votes to
   decide. **One deny vetoes** (non-negotiable). The requesting agent can
   never vote and can never be in the eligible set.

Both are enforced by the same primitives the queue already trusts: the
keyed record MAC (`_SECURITY_PAYLOAD_FIELDS`, F43), the pending-state
canonical check, the queue lock, and the tamper-evident action log. The
three load-bearing decisions are called out in §10; everything else is
derivation.

---

## 1. Data model

### 1.1 New record fields

All fields live on the queue record (JSONL, `approvals.jsonl`). Absent
fields bind as `None` in the MAC (same convention as §F43).

| Field | Type | Meaning |
|---|---|---|
| `decision_mode` | `"single"` \| `"quorum"` | Decided by one human vs M-of-N votes. Defaults to `"single"` when absent (backward compatible read; see §1.3). |
| `delegated_to` | `str` \| `None` | Current assignee principal. `None` = unassigned (any operator may decide/delegate, as today). Set by `delegate()`. |
| `delegation_chain` | `list` of `{from, to, at, reason}` | Append-only. Every reassignment appends one hop. Empty list (or absent) = never delegated. |
| `quorum` | `None` \| `{min_approvals, eligible_principals, deny_veto, opened_at}` | **Snapshot** of the quorum config taken at queue time (see §1.2). `None` for single-decider records. |
| `votes` | `list` of `{vote_id, voter_principal, voter_identity, approve, reason, ts, nonce}` | One row per cast vote. `voter_identity` is the `AgentIdentity.as_dict()` of the voter at vote time. `vote_id = sha256(record_id + voter_principal + nonce)`. Votes are final (no retraction, no change — see §4.3). |
| `bridge_expired` | `bool` | Set by `mark_bridge_expired()` when a bridge wait (e.g. the future AGT-Python shim's bounded wait) times out. Default `False`. |
| `bridge_expired_at` | `str` \| `None` | Timestamp of the marker. |
| `late_decision` | `bool` | Set by `decide()` when the record was already `bridge_expired` at decision time. Labels the decision audit-only. |

### 1.2 Quorum snapshot, not live config

At `queue()` time, when the active policy's `approvals.quorum` section
applies to the record (see §5.1), the queue copies
`{min_approvals, eligible_principals, deny_veto}` into `record["quorum"]`
and MACs it. **Votes are checked against the snapshot, never the live
policy file.** Rationale: a policy edit between queue and vote must not
be able to shrink `min_approvals` or swap `eligible_principals` to launder
a decision (quorum-bypass-by-config-edit). A policy reload only affects
records queued after it — same precedent as `policy_hash` pinning.

### 1.3 MAC binding and per-field fail-closed behavior

All six fields are added to `_SECURITY_PAYLOAD_FIELDS` (F43 extension),
so they ride the existing HMAC-SHA256 keyed digest (`approval_record_digest`,
`_pending_record_content_ok`, `approval_digest_ok`). Every state-changing
method verifies the pending digest **before** mutating and re-MACs
**after** — the F38 pattern. What breaks, per field:

| Tampered field | Detection point | Fail-closed behavior |
|---|---|---|
| `delegated_to` rewritten (attack: reroute the decision to a confederate, or back to the requesting agent) | `decide()`'s `_pending_record_content_ok` pre-check, and `approval_digest_ok` at execution | Decision refused (`ValueError`), audited as `approval_decision_attempt`/`approval_integrity_violation`. The wrong principal's decision can never be laundered through a re-MAC because the re-MAC is refused first. |
| `delegation_chain` truncated or edited (attack: hide hops, erase the requester-loop) | Same pre-check | Same refusal. Chain history is integrity-bound, not advisory. |
| `quorum.min_approvals` lowered (attack: 2-of-3 → 1-of-3) | `cast_vote()` pre-check; finalize pre-check | Vote/finalize refused; record stays collecting. |
| `quorum.eligible_principals` edited (attack: add a confederate, remove a skeptic) | `cast_vote()` pre-check | Refused. The snapshot is the authority. |
| `votes` row edited (attack: flip `approve:false`→`true`; delete a deny) | `cast_vote()` pre-check on every vote; finalize pre-check; `approval_digest_ok` at execution | Refused at the earliest check. A flipped deny-vote can never reach execution because execution re-verifies the full payload including `votes`. |
| `bridge_expired` flipped `true`→`false` (attack: resurrect a timed-out bridge approval for execution) | `_execute_approved_locked`'s `approval_digest_ok` check (execution) | Execution refused (`approval_execution_refused`, flag `bridge_expired`). The marker cannot be cleared without the log key, and clearing is not offered by any API. |
| `decision_mode` flipped `quorum`→`single` (attack: dodge the M-of-N gate via direct `decide()`) | `decide()`'s pre-check MAC fails (payload changed) | Refused. There is no downgrade path from quorum to single. |
| `late_decision` flipped `true`→`false` (attack: make an audit-only late decision look normal) | Execution-time `approval_digest_ok` | The flag is display/audit labeling; execution refusal keys off `bridge_expired`, not this flag — flipping it changes nothing executable. Still MAC-bound so forensics is intact. |

**Fail-closed upgrade note (same precedent as F34/F38/R11):** extending
the MAC payload means records queued *before* D1-core lands will not
verify after the upgrade. Queued items must be decided or drained before
upgrading; post-upgrade, pre-D1 digests fail verification automatically.
This is documented behavior, not a migration.

### 1.4 Audit events (new)

| Event | When |
|---|---|
| `quorum_opened` | `queue()` creates a quorum-mode record (carries the snapshotted config). |
| `approval_delegated` | `delegate()` succeeds (from, to, hop number, reason). |
| `delegation_refused` | `delegate()` refuses (exact reason: self-delegation, requester-target, loop, max-hops, unregistered, wrong-delegator, not-pending, tamper). |
| `quorum_vote` | `cast_vote()` succeeds (voter principal, approve/deny, running tally). |
| `quorum_vote_refused` | `cast_vote()` refuses (ineligible, duplicate, requester-vote, decided-already, tamper). |
| `quorum_finalized` | M approvals reached (voters listed) or deny veto fired. Precedes the `approval_decision` entry. |
| `bridge_wait_expired` | `mark_bridge_expired()` sets the marker (bridge id, wait duration). |
| `approval_late_decision` | `decide()` records a decision on a `bridge_expired` record — audit-only, never executable. |
| `bridge_expired_after_execution` | `mark_bridge_expired()` called on an already-executed record — anomaly, operator investigates (the TOCTOU already resolved the other way). |

All new events carry the standard attribution fields (`run_id`,
`agent_id`, `role`, `principal`, `approval_id`, `policy_id`) matching
existing entries.

---

## 2. State machine

### 2.1 States

`DELEGATED` and `QUORUM_COLLECTING` are **substates of `pending`**,
derived from record fields — not new top-level `status` values (see §10,
decision 1). `DECIDED` = `status` in (`approved`, `rejected`).

```
                       ┌────────────────────────────────────────────┐
                       │ PENDING (status="pending")                 │
                       │  substate SINGLE      : decision_mode=     │
                       │                         "single",         │
                       │                         delegated_to=None │
                       │  substate DELEGATED   : delegated_to set  │
                       │  substate QUORUM_COLL : decision_mode=    │
                       │                         "quorum", not     │
                       │                         yet finalized     │
                       └────────────────────────────────────────────┘
                          │ delegate()          │ cast_vote()
                          │ (SINGLE→DELEGATED,  │ (tally < M, no deny)
                          │  DELEGATED→DELEGATED│
                          ▼                     ▼
                     DELEGATED stays       QUORUM_COLLECTING stays
                     pending; only the    pending; votes accumulate
                     assignee may decide. (MACed, audited each vote)

  PENDING/DELEGATED/QUORUM_COLLECTING ──cast_vote(deny)──▶ DECIDED(rejected)  [veto]
  QUORUM_COLLECTING ──cast_vote(approve) reaching M──▶ DECIDED(approved)      [finalize]
  PENDING/DELEGATED ──decide()──▶ DECIDED(approved|rejected)
  any pending substate ──TTL──▶ EXPIRED (existing path, unchanged)
  any pending substate ──mark_bridge_expired()──▶ same substate + bridge_expired=true
  bridge_expired record ──decide()──▶ DECIDED with late_decision=true (audit-only)
```

### 2.2 Transition table (guards → audit)

| # | Transition | Guards (all must hold; else fail-closed refusal + audit) | Audit on success |
|---|---|---|---|
| T1 | SINGLE → DELEGATED via `delegate()` | (a) status pending; (b) `approvals.delegation.enabled` true; (c) delegator is the current assignee (`delegated_to`, or the default operator label when unassigned); (d) `to_principal` passes the never-back-to-requester check (§3.3); (e) no loop (target not in chain, not the delegator); (f) `len(chain)+1 ≤ max_hops`; (g) target registered if a PrincipalRegistry is configured; (h) `_pending_record_content_ok` pre-check. Then re-MAC. | `approval_delegated` |
| T2 | DELEGATED → DELEGATED (re-delegate) | Same as T1; hop count increments. | `approval_delegated` (hop n) |
| T3 | DELEGATED → DECIDED via `decide()` | (a)–(b) as T1-pending; (c) **`decided_by` == `delegated_to` exactly** — no one else may decide a delegated record; (d) pending-digest pre-check; then re-MAC with decider bound. | `approval_decision` |
| T4 | SINGLE → DECIDED via `decide()` | Unchanged existing guards (pending, SoD, digest pre-check, re-MAC). | `approval_decision` |
| T5 | → QUORUM_COLLECTING (at `queue()`) | (a) `approvals.quorum` section valid (lint-clean at load); (b) record's flag matches `quorum.flags` (or no `flags` list = all records); (c) **runtime eligibility check**: `eligible_principals ∩ {record.agent_id, record.principal} = ∅` — else `queue()` raises (audited `quorum_misconfigured`), fail closed, no silent downgrade to single. Then snapshot + MAC. | `quorum_opened` |
| T6 | QUORUM_COLLECTING → QUORUM_COLLECTING via `cast_vote(approve)` | (a) status pending and `decision_mode=="quorum"` and not finalized; (b) voter is an authenticated `AgentIdentity` (F26 pattern: isinstance + executor verifier when installed); (c) `voter_principal ∈ quorum.eligible_principals` (snapshot); (d) voter ≠ requesting agent (`voter_principal`/`agent_id` not in `{record.agent_id, record.principal}`); (e) voter has no existing row in `votes`; (f) pending-digest pre-check; then append vote row (with fresh nonce) and re-MAC. | `quorum_vote` (tally n-of-M) |
| T7 | QUORUM_COLLECTING → DECIDED(rejected) via `cast_vote(deny)` | Same guards as T6, then **immediate terminal finalize**: no further votes accepted. `decide()`-equivalent re-MAC with `decided_by="quorum/veto:<voter>"`. | `quorum_vote` + `quorum_finalized` (veto) + `approval_decision` (rejected) |
| T8 | QUORUM_COLLECTING → DECIDED(approved) | T6 guards; on the M-th distinct eligible approval, internal finalize: re-MAC with `decided_by="quorum:<M>-of-<N>"`, voters listed in the audit reason. | `quorum_vote` + `quorum_finalized` + `approval_decision` (approved) |
| T9 | `decide()` called directly on a QUORUM_COLLECTING record | **Always refused.** The M-of-N gate cannot be bypassed by the single-decider path. `ValueError` + audited `decision_refused` (`quorum_direct_decide`). Only the internal finalize (T7/T8) may decide quorum records. | `decision_refused` |
| T10 | any pending substate → `bridge_expired=true` via `mark_bridge_expired()` | (a) record exists; (b) not already executed (if executed → audit `bridge_expired_after_execution` anomaly, no state change); (c) digest pre-check; then set marker + `bridge_expired_at`, re-MAC. Works on pending AND on approved-but-unexecuted records (the exact TOCTOU window). | `bridge_wait_expired` |
| T11 | bridge_expired record → DECIDED via `decide()` | Normal decide guards (T3/T4 as applicable); sets `late_decision=true`; re-MAC. The decision is recorded and audited but **can never execute** (T12). | `approval_late_decision` (+ `approval_decision`) |
| T12 | execution sweep sees `bridge_expired` | In `_execute_approved_locked`, before the TTL check: `if rec.get("bridge_expired"): _refuse(reason, "bridge_expired")`. Audited `approval_execution_refused`. **This is the roadmap's invariant: late human decisions after a bridge timeout are audit-only and never executable.** The check runs on every sweep — a record that becomes `bridge_expired` between decision and sweep is still refused. | `approval_execution_refused` (flag `bridge_expired`) |
| T13 | delegation on a QUORUM_COLLECTING record | Transfers one **vote slot**, not decision power: the delegator must be an eligible principal with no vote cast yet; on success the delegator is removed from the record's `quorum.eligible_principals` snapshot and the delegatee added; M unchanged; chain hop appended; re-MAC. All T1 guards (d)–(h) apply to the delegatee. A delegator who already voted cannot delegate (their vote stands — votes are final). | `approval_delegated` (vote-slot transfer) |

### 2.3 Interactions with existing machinery (no behavior change unless noted)

- **TTL/expiry:** unchanged; applies to all pending substates. Votes do not extend TTL.
- **`execute_approved()` sweep:** unchanged except the new T12 `bridge_expired`
  check (placed before the TTL check; both refuse, with distinct flags).
  Rejected/vetoed records never reach the sweep (status filter).
- **F45 interrupted-execution reconciliation:** preserves all D1 fields
  (`decision_mode`, `delegated_to`, `delegation_chain`, `quorum`,
  `votes`, `bridge_expired`). Votes already cast stand — a crash does not
  erase human votes. The reset-to-pending re-MAC covers the preserved
  fields.
- **Batch decide:** quorum records are **never** batch-decided in either
  direction — returned as `excluded` (`needs_individual_decision`), like
  F21 security items. Rationale: the quorum contract is "M humans weigh
  in"; a single batch rationale violates it even for rejections.
  Delegated single-decider records may be batch-decided only if the batch
  `decided_by` equals each record's `delegated_to`.
- **Auto-approve:** never fires on quorum records (zero-human-decision
  path cannot satisfy M-of-N) and never on delegated records whose
  `delegated_to` is set (the delegation names a specific human).
- **Break-glass:** refused on quorum-collecting records — the emergency
  path must not bypass an M-of-N gate the policy deliberately imposed.
  (`break_glass()` raises `ValueError`, audited `break_glass_refused`.)
  Unchanged for single-decider records.
- **Flood/anomaly/risk:** unchanged. Quorum and delegation add no risk
  factors; the detail view surfaces delegation/quorum state.
- **`audit_status()`:** pending quorum-collecting records count as
  pending; the status dict gains `quorum_collecting_ids` and
  `delegated_ids` for operator visibility.

---

## 3. Delegation rules

### 3.1 Who may delegate

Delegation authority is exactly co-extensive with decision authority: the
**current assignee** may delegate. For an unassigned record
(`delegated_to=None`) that is the default operator (the principal that
would `decide()` it today — CLI: the terminal trust root; web: the
session operator). For a delegated record, **only** the principal named
in `delegated_to` may re-delegate or decide — T3's exact-match guard.

`delegate(approval_id, to_principal, reason, delegated_by)`:
`delegated_by` must equal the current assignee exactly (string equality
on the principal). A mismatch raises `ValueError` and audits
`delegation_refused` (`wrong_delegator`). `reason` must be non-empty.

### 3.2 Re-MAC on reassignment

`delegate()` follows the F38 pattern strictly: verify
`_pending_record_content_ok(target)` **before** mutating; append the hop
`{from: delegated_by, to: to_principal, at: _utcnow(), reason}`;
set `delegated_to = to_principal`; recompute `args_digest` over the
extended payload; rewrite; audit `approval_delegated`. There is no
code path that changes `delegated_to` without re-MACing.

### 3.3 The never-back-to-requesting-agent invariant

**Exact check** (evaluated in `delegate()` before any mutation, and again
in T13 for quorum vote-slot transfers):

```python
requester_ids = {record["agent_id"], record["principal"]}
if to_principal in requester_ids:
    refuse  # audited `delegation_refused`, reason "requester_target"
```

Both `agent_id` (e.g. `"agent-7"`) and the authenticated `principal` are
checked because deployments may mint agent identities whose principal
string equals the agent id — checking only one leaves the alias shape
open. The check additionally refuses:

- `to_principal == delegated_by` (self-delegation — a no-op that would
  launder the chain; refused, not silently accepted);
- `to_principal` already present as a `to` in `delegation_chain`
  (loop — A→B→A refused at the second hop);
- `len(delegation_chain) + 1 > max_hops` (policy `approvals.delegation.max_hops`).

**Exact failure mode:** `delegate()` raises
`ValueError("delegation refused: <specific reason>")`; the record is
**not mutated** (no hop appended, no re-MAC, `delegated_to` unchanged);
a `delegation_refused` event is appended to the tamper-evident log with
`approval_id`, `delegated_by`, attempted `to_principal`, and the reason.
Refusals are loud and forensically complete — same contract as the
existing `decide()` rejected-attempt logging.

### 3.4 Delegation display and CLI

- CLI: `gov.approve delegate <id> --to <principal> --reason "..." [--by <delegator>]`.
  The decision-target view (`_print_decision_target`) renders before
  confirmation, same as decide/batch/break-glass.
- `list` shows `delegated to: <principal> (hop n)` and the chain on the
  detail view.

---

## 4. Quorum rules

### 4.1 Which identity binds a vote

`cast_vote(approval_id, approve, reason, voter_identity)` requires
`voter_identity` to be an `AgentIdentity` (F26 pattern — bare principal
strings raise `TypeError`). When the executor installed an identity
verifier, the identity must pass it (minted by this deployment).
The vote row stores:

- `voter_principal` = `voter_identity.principal` (the eligibility key —
  compared against the snapshotted `eligible_principals`);
- `voter_identity` = `voter_identity.as_dict()` (full binding for
  forensics: agent_id, role, principal, provenance);
- `approve` bool, `reason` (non-empty), `ts`, `nonce`
  (`secrets.token_hex(8)`), `vote_id`.

**Web path (post-F80):** votes are cast from an authenticated session.
Open question 1 (§11) covers the current anonymous-session gap: the spec
recommends the console bind a human principal name at login (or per vote)
so the vote's `voter_principal` is meaningful; until then web votes carry
the session-bound principal and the honest-limits doc says so.

### 4.2 Eligibility

- Voter must be in the record's snapshotted `eligible_principals`.
- The requesting agent is excluded **twice**: at `queue()` time (T5 — the
  whole record is refused if the configured eligible set contains the
  requester's `agent_id` or `principal`) and at `cast_vote()` time
  (T6 guard (d) — defense in depth against a record hand-built before
  the queue-time check existed).
- One vote per principal per record. A second vote from the same
  principal is refused (`quorum_vote_refused`, `duplicate_vote`) — even
  if it would flip approve→deny. **Votes are final** (§4.3).

### 4.3 One-deny veto semantics

`deny_veto` is **unconditionally true** — it is not a tunable. Policy
lint emits an **error** on an explicit `deny_veto: false` (see §5.2);
the engine's normalizer raises `ValueError` at load. The first deny vote
finalizes the record as `rejected` immediately (T7); subsequent votes are
refused (`quorum_vote_refused`, `already_finalized`). There is no veto
override, no re-open, no vote retraction in D1-core: if the action is
re-attempted, it queues as a **new** record with a fresh MAC and fresh
votes. Rationale: a veto that can be outvoted or retracted is a
rubber-stamp amplifier; the terminal veto is the fail-safe core that
differentiates this quorum from AGT's plain M-of-N.

### 4.4 Replay protection for votes

Four layers, tied to the existing replay discipline:

1. **Voter-uniqueness (canonical state check).** `cast_vote()` refuses a
   vote from a principal already in `votes`. Re-POSTing the same vote
   form (the web replay shape) hits this and is refused — the direct
   analogue of the existing web rule "replays hit the canonical
   pending-state check (409)".
2. **Finality state check.** After T7/T8 the record is no longer
   quorum-collecting; any further `cast_vote()` is refused
   (`already_finalized`). A captured vote cannot be replayed into a
   decided record, and cannot be replayed into a *different* record
   because…
3. **Record binding.** `vote_id` and the vote row are covered by the
   record MAC, which binds `record["id"]`. Splicing a vote row from
   record A into record B's JSONL breaks B's
   `_pending_record_content_ok` — refused at the next vote/finalize/
   execution check.
4. **Nonce uniqueness.** Each vote carries a fresh `nonce`; identical
   rows cannot collide and the audit trail distinguishes replays from
   distinct votes forensically.

Web votes additionally ride the post-F80 CSRF/session discipline (same
per-session token + `compare_digest` as decision forms).

### 4.5 Finalize accounting

- Approval finalize: `decided_by = "quorum:<M>-of-<N>"` (e.g.
  `"quorum:2-of-3"`), bound into the re-MAC; the `approval_decision`
  audit reason lists every voter's principal.
- Veto finalize: `decided_by = "quorum/veto:<voter_principal>"`.
- Both labels are human-operator labels (never an agent id), so
  separation-of-duties semantics are unchanged, and both are
  forensically distinct from CLI/web single decisions.

---

## 5. Policy surface

### 5.1 New `approvals:` subsections

```yaml
approvals:
  ttl_hours: 24
  batch_excluded_queue_reasons: [...]   # unchanged

  delegation:
    enabled: true
    max_hops: 1                 # int, 1..5; default 1
    # default_assignee: "human-operator"   # optional; who owns unassigned records

  quorum:
    min_approvals: 2            # int, >= 1
    eligible_principals:        # non-empty, unique, non-empty strings
      - alice
      - bob
      - carol
    flags:                      # optional; default = all require_approval records
      - cross_run_campaign
      - dlp
    deny_veto: true             # must be true or absent; explicit false = load error
```

Applicability: a queued record gets `decision_mode="quorum"` when the
`quorum` section is present and valid **and** (`flags` absent, or the
record's `policy_flag` ∈ `flags`). Otherwise `decision_mode="single"`.
Delegation (`delegate()`) is available on single-decider records when
`delegation.enabled` is true, and on quorum records as vote-slot transfer
(T13).

### 5.2 Lint rules (`gov/policy_lint.py` + `gov/policy.py` normalizer)

Invalid configs are **rejected at load, fail closed**: the engine's
normalizer raises `ValueError` (same pattern as
`_normalize_auto_approve`); `policy_lint` reports the same conditions as
`error` findings. Lint is advisory; the normalizer is the enforcement
point.

| # | Rule | Severity | Rationale |
|---|---|---|---|
| L1 | `approvals.delegation` must be a mapping when present | error | malformed shape |
| L2 | `delegation.enabled` must be bool (default `false` when section absent — delegation is opt-in) | error | fail closed: no silent enable |
| L3 | `delegation.max_hops` int, `1 ≤ max_hops ≤ 5` | error | bounds the chain; >5 is a laundering vector, not a feature |
| L4 | `approvals.quorum` must be a mapping when present | error | malformed shape |
| L5 | `quorum.min_approvals` int `≥ 1` | error | |
| L6 | `quorum.eligible_principals` non-empty list of unique non-empty strings | error | duplicates would let one human fill two slots |
| L7 | `quorum.min_approvals ≤ len(eligible_principals)` | error | otherwise quorum is unreachable — silent starvation, fail closed at load |
| L8 | explicit `quorum.deny_veto: false` | error | veto is non-negotiable (§4.3); fail closed, never a silent majority-overrides-dissent |
| L9 | `quorum.flags`, when present, must be a list of non-empty strings | error | |
| L10 | `quorum` section present but `delegation.enabled` true and a flag in `quorum.flags` also in `batch_excluded_queue_reasons` | info | no conflict — quorum records are batch-excluded anyway (§2.3); informational only |

**Byte-identical twin:** `gov/data/default.yaml` must carry the same new
sections verbatim — the drift-guard test covers it. The default policy
ships `delegation.enabled: false` and **no** `quorum` section (both
features opt-in; the default posture is today's single-decider queue).

---

## 6. `bridge_expired` — the late-decision invariant (core contract)

This is the D1-core half of the roadmap's bridge design; the bridge shims
themselves (`gov/bridges/agt.py`, etc.) are **not** D1-core. D1-core
provides the enforcement both sides rely on:

- **Core provides:** `ApprovalQueue.mark_bridge_expired(approval_id, bridge_id, reason)`;
  the `bridge_expired`/`bridge_expired_at` MACed fields (§1.1); the T10
  transition; the T12 execution-sweep refusal placed **before** the TTL
  check in `_execute_approved_locked`; the T11 audit-only late-decision
  path (`late_decision=true`, `approval_late_decision` event).
- **Bridge contract (for the later bridge work):** when a bridge's
  bounded wait times out, it calls `mark_bridge_expired()` and returns
  deny to its caller (fail-safe, matching AGT's deny-on-timeout). The
  record stays pending in the durable queue. A later human decision is
  permitted and fully audited (T11) but **never executable** (T12) —
  closing the TOCTOU where a slow human approval executes an action the
  bridge already denied.
- **Ordering guarantee:** `mark_bridge_expired()` re-MACs, so a decision
  recorded *before* the marker keeps its pre-marker MAC and fails the
  sweep's integrity check if the marker lands first — either order is
  fail-closed: marker-before-decision → T11/T12; decision-before-marker →
  the sweep re-reads the record (under the queue lock) and sees the
  marker. There is no interleaving in which a bridge-timed-out approval
  executes.

---

## 7. Adversarial test plan (wave-22 destination)

Each situation is a sketch: setup → attack → expected verdict. All are
destined for `evals/w22_probes.py` / `tests/test_approvals_d1.py` (to be
written by the implementing agent — this spec is design only).

| # | Situation | Expected verdict |
|---|---|---|
| S1 | **Delegate to the requesting agent (by agent_id).** `delegate(id, to="agent-7")` where `agent-7` queued the record. | Refused: `ValueError`, `delegation_refused` (`requester_target`); record unmutated. |
| S2 | **Delegate to the requesting agent's principal (alias shape).** Record's `principal` is `"agent-7"` (minted principal == agent id); delegate `to="agent-7"` checked against both fields. | Refused, same as S1 — the check covers `agent_id` **and** `principal`. |
| S3 | **Delegation loop.** A→B succeeds; B→A attempted. | Second hop refused (`delegation_loop`); chain stays `[A→B]`. |
| S4 | **Self-delegation.** Assignee delegates to themselves. | Refused (`self_delegation`), not silently accepted. |
| S5 | **Max-hops exceeded.** `max_hops: 1`; A→B then B→C. | Second hop refused (`max_hops_exceeded`). |
| S6 | **Delegate a decided record.** `decide()` then `delegate()`. | Refused — pending-state canonical check (`not_pending`). |
| S7 | **Tamper `delegated_to` in JSONL.** Hand-edit `delegated_to` to a confederate between `delegate()` and `decide()`. | `decide()` refuses: `_pending_record_content_ok` fails → `approval_integrity_violation`; the confederate's decision is never re-MACed. |
| S8 | **Requesting agent votes.** Quorum record; the requesting agent mints an identity and calls `cast_vote(approve)`. | Refused (`quorum_vote_refused`, `requester_vote`); no vote row appended. |
| S9 | **Vote replay.** Voter's approve POST re-sent (same principal, same content). | Refused (`duplicate_vote`) — voter-uniqueness canonical check; web path additionally returns the 409-style replay refusal. |
| S10 | **Replay after finalize.** Capture a valid vote; replay it after the record is decided. | Refused (`already_finalized`) — finality state check. |
| S11 | **Forged vote row.** Flip a stored vote's `approve: false`→`true` in the JSONL (or delete the deny row). | Next `cast_vote()`/finalize/execution refuses: record MAC fails → `approval_integrity_violation`. The veto can never be edited away. |
| S12 | **Quorum bypass via direct `decide()`.** Call `decide()` on a quorum-collecting record with a single `--by` operator. | Refused (`decision_refused`, `quorum_direct_decide`) — T9. The single-decider path cannot touch quorum records. |
| S13 | **Ineligible principal votes.** Principal not in the snapshotted eligible set calls `cast_vote()`. | Refused (`not_eligible`). |
| S14 | **Deny veto vs majority.** M=2-of-3: two approves cast, then a deny. | Record finalized `rejected` at the deny (T7); a third approve is refused (`already_finalized`). Dissent is terminal. |
| S15 | **Quorum-bypass by config edit.** Shrink `min_approvals` 2→1 in the policy file mid-collection, then cast one vote. | Vote checked against the **snapshot**, still needs 2 — refused-or-still-collecting; the config edit changes nothing for this record. |
| S16 | **Expired-bridge execution.** Bridge wait times out (`mark_bridge_expired`); human approves later; sweep runs. | Decision recorded with `late_decision=true` (`approval_late_decision`); sweep refuses execution (`approval_execution_refused`, flag `bridge_expired`). Never executable. |
| S17 | **Bridge marker tamper.** Flip `bridge_expired` true→false in JSONL, then sweep. | Sweep's `approval_digest_ok` fails → `approval_integrity_violation` refusal. The marker cannot be cleared without the log key. |
| S18 | **Eligible set contains the requester.** Policy lists the requesting agent's id in `eligible_principals`; `queue()` is called. | `queue()` raises (`quorum_misconfigured`), audited; no silent downgrade to single-decider. |
| S19 | **Break-glass on a quorum record.** `break_glass()` a quorum-collecting record. | Refused (`break_glass_refused`) — the emergency path cannot bypass M-of-N. |
| S20 | **Delegation-chain truncation.** Delete a hop from `delegation_chain` in JSONL. | Next transition refuses — chain is MAC-bound (`approval_integrity_violation`). |

Coverage note for wave-22: S1–S7 (delegation), S8–S15/S18 (quorum),
S16–S17 (bridge invariant), S19–S20 (interactions). Each must also assert
the **audit event** exists (not just the refusal), per the battery's
loudness discipline.

---

## 8. CLI surface (core, proceeds independently of F80)

- `gov.approve delegate <id> --to <principal> --reason "..." [--by <delegator>]`
- `gov.approve vote <id> --approve|--deny --reason "..." --by <principal>`
  (CLI binds `--by` into an `AgentIdentity`, terminal trust root — same as
  `break-glass`/`review-resolve` today).
- `list` renders delegation state (`delegated to: X (hop n/N)`), quorum
  tally (`votes: 1-of-2; deny veto armed`), and vote rows with principals.
- All three decision paths render `_print_decision_target` before
  committing (F66 semantics: decide on the exact digested bytes).

---

## 9. Web UI (post-F80 only)

New routes, same security discipline as the existing decide handler
(session required, per-session CSRF `compare_digest`, canonical
`ApprovalQueue` methods under the queue lock, re-read record from disk,
409 on replay/non-pending):

- `GET /approvals/<id>` — detail page additionally renders: delegation
  chain (hops with from/to/at/reason), current assignee, quorum config
  snapshot + live tally (`n-of-M`), vote rows (principal, approve/deny,
  ts, reason), veto state.
- `POST /approvals/<id>/delegate` — form fields: `to`, `reason`, `csrf`.
  Delegator is the session operator; must equal the current assignee.
- `POST /approvals/<id>/vote` — form fields: `decision` (approve/deny),
  `reason`, `csrf`. Voter principal is the session-bound principal
  (see §11 Q1).
- Break-glass records stay read-only (existing Architect decision);
  quorum/delegation introduce no web break-glass path.
- Batch/auto-approve remain CLI-only (existing honest limits).

**Do not implement until F80 lands** — the delegate/vote forms share the
`_page` CSRF/logout renderer paths the F80 fix touches.

---

## 10. The three consequential decisions (and why)

1. **DELEGATED and QUORUM_COLLECTING are substates of `pending`, not new
   top-level statuses.** Derived from `delegated_to` / `decision_mode`
   fields. Why: the sweep, TTL expiry, `audit_status()`, flood/anomaly
   detection, the CLI, and the web list all key off `status`. New
   top-level statuses would force every consumer to learn new states and
   risk exactly the silent-skip class this codebase exists to prevent
   (cf. F45's lesson). The substate model keeps every existing
   fail-closed check working untouched; only the new transitions need
   new code.
2. **One-deny veto is non-negotiable — `deny_veto: false` is a load
   error.** Why: an M-of-N scheme where dissent can be outvoted is a
   rubber-stamp amplifier under social pressure, not a safety gate. The
   terminal veto is the fail-safe core and the honest differentiator
   against AGT's plain M-of-N quorum (deep-dive §3.1). Making it
   unconfigurable removes the most dangerous misconfiguration at the
   cheapest point (load time).
3. **Requester exclusion is enforced at runtime (queue/delegate/vote
   time), not just by lint.** Why: lint cannot see the requesting
   agent's identity at policy-load time, so a static check is
   structurally insufficient. The record MAC binds `agent_id`/`principal`
   (F42/F43), and the exact-match refusal (`to_principal ∈
   {agent_id, principal}`) at the transition is the real invariant —
   audited, fail-closed, and independent of whatever the config file
   said. This is the same "never trust the config alone" posture as
   F42's caller-identity stamping.

---

## 11. Open questions for the lead (max 5)

1. **Web vote identity.** Web sessions are currently anonymous
   ("operator"). A quorum vote bound to an anonymous session has weak
   forensic value — five votes could be one human five times.
   *Recommendation:* bind a human principal name at login (typed by the
   operator, echoed on every vote form) and record it as
   `voter_principal`; document that it is self-asserted at the
   localhost console (honest-limits), and require PrincipalRegistry
   backing before any network deployment (per D5's deployment
   contract). Do not block D1-core on this — ship with the honest
   label.
2. **`max_hops` default.** Chains beyond one hop let an approver launder
   responsibility ("I just passed it on") and complicate forensics.
   *Recommendation:* default `max_hops: 1` (single reassignment);
   operators who need chains raise it explicitly to ≤5. The lint
   ceiling stays 5 either way.
3. **Vetoed-record lifecycle.** Should a deny-vetoed record be
   re-openable (e.g. second human overrides the veto)?
   *Recommendation:* no in D1-core. Veto is terminal; the action
   re-queues as a new record with a fresh MAC and fresh votes. An
   override path is a rubber-stamp vector and can be designed later
   with its own quorum if real demand appears.
4. **PrincipalRegistry for delegation targets.** Should `delegate()`
   require the target principal to be registry-known when a registry is
   configured?
   *Recommendation:* yes — refuse unregistered delegatees
   (`unregistered_delegatee`) when `note_registry_configured()` has
   fired; without a registry, principal strings are the terminal trust
   root (documented localhost-grade limit, same as CLI `--by` today).
5. **`bridge_expired` ownership.** Should the marker method live in core
   (`ApprovalQueue.mark_bridge_expired`, this spec) with bridges as
   callers, or in each bridge module?
   *Recommendation:* core owns the marker, the MAC field, and the
   execution-sweep check; bridges only call it. That way the
   audit-only-never-executable invariant holds identically for the
   AGT-Python shim, the future .NET ingress, and any later bridge —
   and D1-core can land and be adversarially tested before any bridge
   exists.

---

## 12. Explicit non-goals

D1-core does **not** include:

- The AGT-Python `CallbackApproval` shim (`gov/bridges/agt.py`), the
  AGT-.NET webhook ingress (`gov/bridges/agt_webhook.py`), and the AWS
  approval-event producer bridge (`gov/bridges/aws.py`) — D1-bridges
  work, sequenced after D1-core. Only the `bridge_expired` enforcement
  contract (§6) is in scope here.
- Vote retraction or veto override; cross-run delegation (records stay
  in their run; `run_id` remains MAC-bound); delegation of decided or
  expired records.
- Anything on the roadmap STOP list: policy-engine racing/perf work,
  Merkle-proof audit crypto, sandboxing beyond the prototype, new
  framework adapters, compliance mappings, SSO/TLS/multi-tenancy for
  the console, MCP scanner duplication, identity racing
  (beyond the registry check in Q4).
- Quorum or delegation for break-glass records (break-glass stays the
  single-operator CLI emergency path; it is refused on quorum records).
- Changes to `decide()` semantics for existing single-decider records,
  except the T3 assignee-exact-match guard which only activates when
  `delegated_to` is set.

---

*End of D1_CORE_SPEC.md — design only; no code changed. Awaiting lead
review before implementation dispatch.*
