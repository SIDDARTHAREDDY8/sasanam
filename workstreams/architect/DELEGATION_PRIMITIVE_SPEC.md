# Governed Authority Delegation — Design Spec (P10)

**Status:** DRAFT for engineering-lead review · **Date:** 2026-09-22 (wave-23)
**Scope:** design only — no product code, no `gov/` or `tests/` edits.
**Problem (B1 partial):** agent-to-agent delegation is currently only
*labeled*, not governed. `ToolExecutor.call()` pops `on_behalf_of` /
`delegated_by` as untrusted framing kwargs and records
`delegation_attempted: true` in the audit entry — the action then
executes under the *acting* agent's authority with no check on the claim
(`evals/w_incident_probes.py::sit_p10_unscoped_delegation` asserts exactly
this: executed + flagged). There is no primitive by which agent A can
*grant* agent B scoped authority, and no policy surface to deny unscoped
claims.

**Terminology (binding, per A12):** this spec governs **authority
delegation** (agent→agent grant of tool-call authority). It is a different
primitive from **approval delegation** (D1-core: human reassignment of
approval-queue stewardship). Docs, code, and audit events must keep the
terms distinct.

**Inputs read:** `gov/executor.py` (`call()` framing-kwarg handling,
identity checks), `gov/identity.py` (`AgentIdentity`, F55 provenance,
`PrincipalRegistry`), `gov/approvals.py` (record MAC/F43 pattern,
`_SECURITY_PAYLOAD_FIELDS` extension precedent), `policies/default.yaml`,
`evals/w_incident_probes.py` (P10 probe).

---

## 0. Design summary

A **delegation grant** is a server-side, MAC-bound record minted *only* by
the delegator's verified identity through an explicit executor method —
never by self-claimed kwargs. The delegatee invokes tool calls by
presenting the grant id; the executor verifies the grant (existence,
integrity, expiry, revocation, scope, chain, delegatee match) *before*
policy evaluation, and the audit entry carries dual attribution (acting
agent + delegator + grant id). Unscoped framing claims (`on_behalf_of`
without a grant) become policy-governed: deniable, defaulting to today's
flag-and-execute only where the operator explicitly keeps it.

---

## 1. Data model

### 1.1 Delegation grant record

Grants live in a dedicated store (`delegations.jsonl` in the run dir —
same JSONL + MAC discipline as the approval queue; see §1.3). Fields:

| Field | Type | Meaning |
|---|---|---|
| `grant_id` | `str` | `sha256(delegator_agent_id + delegatee + nonce)`; the invocation handle. |
| `delegator` | `{agent_id, role, principal, provenance}` | Verified `AgentIdentity.as_dict()` of the minter **at mint time**. |
| `delegatee` | `str` | Agent id (or principal) authorized to invoke. Exact-match at invocation. |
| `scope` | `{tools: [str], max_risk: str?, arg_constraints: {...}?, flags: [str]?}` | What the grant covers. `tools` is an explicit allowlist (no wildcards in v1). |
| `issued_at` / `expires_at` | `str` (UTC) | TTL from policy (`delegation.default_ttl_minutes`); hard ceiling `max_ttl_minutes`. |
| `chain` | `[{grant_id, delegator, at}]` | Append-only ancestry. Empty = root grant. Depth ≤ `max_depth`. |
| `run_id` | `str` | Bound at mint. Cross-run only if `cross_run: true` was set explicitly. |
| `cross_run` | `bool` | Default `false`. |
| `single_use` | `bool` | Optional; when true the grant is consumed by first successful invocation. |
| `revoked` | `bool` | Set by `revoke_grant()`; revocation is itself an audited, MACed transition. |
| `nonce` | `str` | Fresh per grant (`secrets.token_hex(8)`). |

### 1.2 Mint-time checks (fail closed, all audited)

`executor.delegate_grant(delegator_identity, delegatee, scope, ttl_minutes=None, ...)`:

1. **Verified identity only.** `delegator_identity` must be an
   `AgentIdentity` passing the executor's identity verifier (F26/F55
   pattern). Bare principal strings raise `TypeError`. A mid-run
   *minted* identity may grant — but the grant records `provenance` and
   policy may restrict grants to provisioned-session identities for
   high-risk scopes (see §5).
2. **No amplification.** Every tool in `scope.tools` must be in the
   delegator's *own* authority at mint time: the delegator's role must
   allow the tool under the active policy's role allowlist, and any
   `require_approval` flags on those tools propagate into the grant's
   scope (the delegatee's invocation still queues approvals — delegation
   never bypasses the approval gate). Violation → `ValueError`
   (`delegation_refused`, `scope_amplification`), nothing minted.
3. **No self-delegation laundering.** `delegatee` must differ from the
   delegator's `agent_id` *and* `principal` (the D1-core §3.3 alias
   check, reused).
4. **Depth bound.** Root grants have `chain=[]`. A sub-grant
   (`parent_grant_id` supplied) requires the parent to verify (§2),
   appends one hop, and **narrows** scope: `sub.scope.tools ⊆
   parent.scope.tools`, `sub.expires_at ≤ parent.expires_at`. Widening
   or extension is refused. `len(chain)+1 ≤ max_depth` (default 1 —
   single hop; operators raise to ≤3 explicitly).
5. **Delegatee eligibility.** If a `PrincipalRegistry` is configured and
   the delegatee names a principal, it must be registry-known
   (A11/Q4 precedent). Agent ids are checked against the run's known
   agents where available.
6. **MAC.** The grant is MACed over the canonical security payload
   (§1.3) with the run's log key before it is stored. There is no
   code path that stores an un-MACed grant.

### 1.3 Integrity binding

Grant records extend the same HMAC-SHA256 keyed-digest discipline as the
approval queue (F34/F43 precedent): a `_DELEGATION_SECURITY_PAYLOAD_FIELDS`
tuple covering `grant_id, delegator, delegatee, scope, issued_at,
expires_at, chain, run_id, cross_run, single_use, revoked, nonce`.
Every state-changing method (`invoke` path verification,
`revoke_grant`) re-verifies before acting. Tampered store → invocation
refused (`delegation_refused`, `grant_integrity_violation`), loud.

### 1.4 Invocation

`executor.call(identity, tool, ..., delegation_grant_id="<id>")`:

1. Grant lookup by id; missing → refuse (`unknown_grant`).
2. Integrity re-verify (MAC); failure → refuse.
3. `revoked` → refuse (`grant_revoked`).
4. `expires_at` in the past (with a small clock-skew margin, documented)
   → refuse (`grant_expired`).
5. Delegatee match: `identity.agent_id == grant.delegatee` (or principal
   match when the grant names a principal) → else refuse
   (`delegatee_mismatch`). **The grant is not a bearer token**: presenting
   the id from a non-matching identity is useless.
6. Scope check: `tool ∈ scope.tools`, arg constraints satisfied →
   else refuse (`scope_exceeded`).
7. Chain verify: each ancestor grant re-verified recursively (integrity,
   expiry, revocation, narrowing) → any break refuses (`chain_broken`).
8. Run binding: `grant.run_id == identity.run_id` unless
   `grant.cross_run` → else refuse (`cross_run_denied`).
9. `single_use` + already consumed → refuse (`grant_consumed`); on
   successful invocation, mark consumed (MACed transition, audited).
10. **Then** normal policy evaluation runs with the *delegator's*
    authority ceiling already enforced at mint; the approval gate still
    applies per the propagated flags.

The audit `tool_call` entry gains `delegation_grant_id`, `delegator`
(agent_id + principal), and `delegation_scope` — dual attribution,
forensically complete. `delegation_attempted` stays as the framing label.

### 1.5 Unscoped framing claims (the P10 probe shape)

`on_behalf_of` / `delegated_by` kwargs **without** a grant id remain what
they are today — untrusted labels — but become policy-governed:

```yaml
delegation:
  enabled: true
  default_ttl_minutes: 60
  max_ttl_minutes: 240
  max_depth: 1                 # 1 = single hop; ≤3
  require_provisioned_for:     # scopes needing the F55 session identity
    - break_glass_tools
  unscoped_delegation: flag    # flag | deny
```

- `unscoped_delegation: deny` — any call carrying `on_behalf_of` /
  `delegated_by` without a valid `delegation_grant_id` is **denied**
  (`policy_id: delegation-unscoped`, flag `unscoped_delegation_denied`)
  before tool execution, audited. Recommended for any deployment past
  the prototype line.
- `unscoped_delegation: flag` (default) — today's behavior: executes
  under the acting agent's authority, labeled `delegation_attempted:
  true`. Kept as the default so benign orchestration patterns don't
  break silently; the lint emits a **warning** when `flag` is set on a
  policy whose threat model includes multi-agent privilege escalation.

This is the B1 close-out: the P10 probe's "flagged, not denied" verdict
becomes a *configuration* with a documented default, and the governed
grant path becomes the way to delegate with authority.

### 1.6 Revocation

`executor.revoke_grant(grant_id, revoker_identity, reason)`: revoker must
be the delegator or the provisioned session identity (operator). Sets
`revoked=true`, re-MACs, audits `delegation_revoked`. Revocation is
checked at every invocation (§1.4 step 3) — there is no caching window in
v1 (grants are per-run, low-volume; document the O(1)-per-call cost).

### 1.7 Audit events (new)

| Event | When |
|---|---|
| `delegation_granted` | mint succeeds (grant_id, delegator, delegatee, scope summary, ttl, depth). |
| `delegation_refused` | mint refuses (exact reason: `scope_amplification`, `self_delegation`, `depth_exceeded`, `scope_widened`, `unregistered_delegatee`, `tamper`, …). |
| `delegation_invoked` | invocation verifies (grant_id, acting agent, delegator, tool). |
| `delegation_invocation_refused` | invocation refuses (exact reason: `unknown_grant`, `grant_integrity_violation`, `grant_revoked`, `grant_expired`, `delegatee_mismatch`, `scope_exceeded`, `chain_broken`, `cross_run_denied`, `grant_consumed`). |
| `delegation_revoked` | revocation succeeds (grant_id, revoker, reason). |
| `unscoped_delegation_denied` | framing claim denied under `unscoped_delegation: deny`. |

---

## 2. Chain semantics (sub-delegation)

Sub-delegation exists for supervisor→worker→sub-worker patterns, but
each hop can only **narrow**: fewer tools, shorter or equal TTL, never a
new principal outside the parent's delegatee line (the sub-delegator must
be the parent's delegatee — verified identity match). Depth default 1
(single hop); `max_depth` lint ceiling 3. A broken ancestor (revoked,
expired, tampered) invalidates the whole descendant line at invocation
time — revocation propagates downward for free, which is the point.

## 3. Interactions with existing machinery

- **Approval queue:** a delegated invocation that hits `require_approval`
  queues under the *delegator's* identity as requester (SoD preserved:
  the delegator can never approve their own delegated request — the
  D1-core never-back-to-requesting-agent invariant covers both
  `agent_id` and `principal`). The approval record's audit notes the
  grant id.
- **D1-core approval delegation:** unrelated primitive (human
  stewardship). Authority-delegation grants never confer
  approval-decision power: a grant cannot authorize `decide()`,
  `cast_vote()`, or `break_glass()` — those require human principals
  (and break-glass additionally requires the provisioned session
  identity, A9). Attempted use → refused (`non_delegable_power`).
- **A2 Rule-of-Two:** a grant does not launder taint. If the delegator's
  session is tainted, the delegatee's invocation inherits the taint
  state for Rule-of-Two purposes (recorded in the audit entry).
- **Quorum votes:** `cast_vote()` requires a human `AgentIdentity`;
  authority grants are agent→agent and never satisfy voter eligibility.
- **S2/S4/S5 (budgets, step budget, velocity):** usage accrues to the
  *acting* agent; the audit entry's dual attribution lets operators
  aggregate by delegator too. No double-counting: accrue once, attribute
  twice.

## 4. Policy surface

```yaml
delegation:                       # authority delegation (agent→agent)
  enabled: false                  # opt-in; default preserves today's label-only behavior
  default_ttl_minutes: 60         # 1..max_ttl_minutes
  max_ttl_minutes: 240
  max_depth: 1                    # 1..3
  require_provisioned_for: []     # tool/flag names needing F55 session identity as delegator
  unscoped_delegation: flag       # flag | deny
```

**Lint rules** (`gov/policy_lint.py`, errors unless noted): `delegation`
must be a mapping; `enabled` bool (default false — fail closed, no silent
enable); TTL ints with `1 ≤ default ≤ max`; `max_depth` int 1..3;
`unscoped_delegation` ∈ {flag, deny}; `require_provisioned_for` list of
strings; `unscoped_delegation: flag` → **warning** (not error) citing the
P10 residual. `gov/data/default.yaml` twin carries the section verbatim
(drift-guard). Default ships `enabled: false`, `unscoped_delegation:
flag` — today's behavior, explicitly labeled.

## 5. Adversarial test plan (wave-23 red-team destination)

| # | Situation | Expected verdict |
|---|---|---|
| S1 | **Unscoped claim on a privileged tool, `unscoped_delegation: deny`.** `on_behalf_of="boss-agent"` + `write_file`, no grant. | Denied (`delegation-unscoped`); audited `unscoped_delegation_denied`. |
| S2 | **P10 regression (default config).** Same call under default `flag`. | Executed + `delegation_attempted: true` labeled (documents the default; the probe notes the lint warning). |
| S3 | **Forged grant id.** Random/unknown `delegation_grant_id`. | Refused (`unknown_grant`); nothing executes. |
| S4 | **Expired grant.** Grant TTL elapsed; invoke. | Refused (`grant_expired`). |
| S5 | **Revoked grant.** `revoke_grant()` then invoke. | Refused (`grant_revoked`); descendant sub-grants also refuse (`chain_broken`). |
| S6 | **Scope amplification at mint.** Delegator whose role can't `write_file` grants it. | Mint refused (`scope_amplification`); no grant stored. |
| S7 | **Scope exceeded at invoke.** Grant covers `read_file`; invoke `write_file`. | Refused (`scope_exceeded`). |
| S8 | **Delegatee mismatch (stolen grant id).** Attacker presents victim's grant id with own identity. | Refused (`delegatee_mismatch`) — grants are not bearer tokens. |
| S9 | **Sub-delegation widens scope.** Child grant adds a tool the parent lacked. | Mint refused (`scope_widened`). |
| S10 | **Depth exceeded.** `max_depth: 1`; delegatee tries to sub-delegate. | Refused (`depth_exceeded`). |
| S11 | **Tampered grant store.** Flip `scope.tools` in `delegations.jsonl`, invoke. | Refused (`grant_integrity_violation`) at the pre-invocation MAC check. |
| S12 | **Single-use replay.** `single_use` grant invoked twice. | First executes; second refused (`grant_consumed`). |
| S13 | **Cross-run smuggling.** Grant from run A presented in run B. | Refused (`cross_run_denied`) unless `cross_run: true` was explicit. |
| S14 | **Grant launders approval power.** Delegatee calls `decide()`/`cast_vote()` citing the grant. | Refused (`non_delegable_power`) — human powers never delegate via authority grants. |
| S15 | **Self-delegation.** Delegator names own agent_id as delegatee. | Mint refused (`self_delegation`). |
| S16 | **Taint laundering via delegation.** Tainted delegator grants; delegatee invokes privileged tool. | Invocation carries the taint; A2 Rule-of-Two still gates it. Delegation is not a clean-room. |

Each situation must assert the **audit event** exists (loudness
discipline), and the P10 incident probe is updated: under a
`deny`-configured policy the probe's verdict becomes `stopped`; the
`flag` default keeps the current `flagged` verdict with an explicit note.

## 6. The three consequential decisions (and why)

1. **Grants are server-side records referenced by id, never bearer
   credentials in args.** Why: a bearer string in tool args leaks into
   logs, prompts, and tool outputs (A3's steganography ceiling applies);
   a server-side record verified against the caller's identity can't be
   replayed by whoever copies the string. The `delegatee_mismatch`
   refusal is the load-bearing check.
2. **Mint enforces no-amplification against the live policy; invocation
   re-verifies everything.** Why: mint-time is the only point where the
   delegator's authority is knowable (lint can't see runtime roles);
   invocation-time re-verification closes TOCTOU between grant and use
   (revocation, expiry, tamper). This mirrors D1-core's snapshot-vs-
   runtime split (quorum config snapshotted at queue time).
3. **Unscoped framing stays label-by-default, deny-by-configuration.**
   Why: flipping the global default to deny would silently break benign
   orchestration (supervisor framings with no privilege change) — the
   same "don't break the world silently" reasoning as A11. The lint
   warning + explicit `deny` option moves deployments toward governance
   without a flag-day, and the P10 probe documents both postures.

## 7. Explicit non-goals

- Inter-deployment delegation (single deployment trust domain; K-026
  authenticated inter-agent messaging is the transport when built).
- Delegation of human powers (`decide`, `cast_vote`, `break_glass`) —
  refused, always.
- Wildcard scopes (`tools: ["*"]`) in v1; capability URLs / bearer-token
  grants; delegation of quota/budget ownership (usage accrues to the
  actor).
- Changes to `on_behalf_of`/`delegated_by` handling when
  `delegation.enabled: false` (label-only, as today).
- Anything on the roadmap STOP list.

## 8. Open questions for the lead (max 5)

1. **Default for `unscoped_delegation`.** Spec defaults to `flag`
   (today's behavior, lint-warned). *Recommendation:* keep `flag` for
   one wave so the red team can measure breakage under `deny` in evals
   before any default flip is even proposed.
2. **Grant store backend.** *Recommendation:* `delegations.jsonl` in the
   run dir with the approval-queue JSONL+MAC discipline (not the audit
   log — grants are mutable state: revoke/consume transitions).
3. **Cross-run grants.** Default `false`; explicit opt-in per grant.
   *Recommendation:* additionally require operator (provisioned
   identity) approval for `cross_run: true` in v1 — cross-run authority
   is the highest-risk shape.
4. **`require_provisioned_for` default.** *Recommendation:* ship empty,
   document `break_glass_tools` as the canonical example; let operators
   populate. (Break-glass itself is non-delegable regardless — §3.)
5. **Should `delegate_grant` require a human approval for high-risk
   scopes?** *Recommendation:* not in v1 — the no-amplification rule
   plus propagated `require_approval` flags already route the risky
   *invocations* through the queue. Revisit if red-team finds a
   mint-then-invoke shape that evades it.

---

*End of DELEGATION_PRIMITIVE_SPEC.md — design only; no code changed.
Implementation (new `gov/delegation.py` or executor methods + policy
section + lint + tests + P10 probe update) is dispatched after lead
sign-off. Next free finding number remains F83.*
