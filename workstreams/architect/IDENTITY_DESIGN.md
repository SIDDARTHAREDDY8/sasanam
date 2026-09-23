# Identity — design (wave-74, Part 4: Identity)

**Status: implemented 2026-09-22** (`gov/delegation_tokens.py`;
`gov/provenance.py` delegation sub-schema v2; executor gate).
Load-bearing inputs: `research/agent-governance-learnings-2026-09-22.md`
Part 4 (ranked recommendations 1–3, adopted as the converged answer —
no fourth token shape invented), `workstreams/architect/PROVENANCE_DESIGN.md`
§7 (the delegation contract this wave fills), and
`research/intake-wave74-2026-09-22.md` (fresh corroboration).

Session IDs existed; lineage didn't. This document specifies the
machinery that turns "which user, which deployment, which parent agent
spawned this one" into verifiable structure chained into the log like
everything else.

---

## 1. The converged answer, adopted — not invented

Three sources converge on one shape (intake §1–§3):

1. **South et al., "Authenticated Delegation and Authorized AI Agents"**
   (arXiv:2501.09674; ICML 2025): user ID token + agent-ID token +
   **delegation token issued and signed by the human delegator**,
   referencing hashes of the other two, carrying scope, expiry,
   revocation endpoint, audit URLs. The paper's answer to "on whose
   behalf." Our `tokens_schema` marker is literally `"south-3token/v1"`.
2. **The SPIFFE two-layer split** (Red Hat Emerging Technologies, June
   2026; Red Hat Kagenti ADR-006): transport layer answers *who is
   calling* (workload/service identity); application layer answers *on
   behalf of whom* (user + agent delegation chain). MongoDB's "Three
   Questions" (July 2026) states the enforcement rule exactly:
   *"an action should proceed only when the requester's permissions,
   the agent's permissions, and the tool's permissions all allow it."*
3. **Per-hop attenuation** (MongoDB Pattern 4 — A2A authority chaining):
   *"each handoff produces a signed token that records the full chain
   back to the originating user, narrows the scope at every hop so
   each downstream agent can do strictly less than the one before, and
   lets every recipient verify the chain rather than trust it."*
   Its two break points are our two pinned probes: a hop that does not
   narrow scope re-broadens authority; a recipient that trusts claims
   rather than verifying signatures defeats the signing.

What each layer is **in our tree** (the task demands this be exact):

| Layer | Question | In our tree |
|---|---|---|
| Transport | *Who is calling?* | The **deployment-provisioned session identity** (F55): the workload that holds the `ToolExecutor` — `(agent_id, role, principal, provenance="provisioned")`, created once at executor construction, never mintable mid-run. There is no mTLS transport in this local model; the process boundary + provisioned identity is the workload identity. |
| Application | *On behalf of whom?* | The **three-token chain** — user token + agent token + human-signed delegation token, plus per-hop parent-signed sub-delegation tokens. Carried in the `prov` delegation hops (v2 `tokens` slots), verified by `gov/delegation_tokens.py`, enforced at the executor gate. |

The layers are separated: transport identity authenticates the *caller*
to the governance layer; the delegation chain authorizes the caller's
*actions* on behalf of the user. A valid transport identity with no
delegation token fails closed — that is the wave-74 construction.

**What identity replaces:** the `agent_id: "system"` string theater the
learnings memo names — including, honestly, parts of our own early tree
(`validate_provenance` still warns on the ambient-authority string).
A bare string is a claim; a token is a *verifiable* claim: issuer,
subject, scope, expiry, session binding, signature. What identity does
**not** replace: the deployment's trust in its own key custody
(wave-69/70), the anchor against key-holders (wave-72), or the human
approval paths (D1-core). Identity binds the *who*; it does not make
the *who* trustworthy.

**China's centralized identity layer** (arXiv 2607.23207, per the memo):
state-operated real-identity association with per-agent key pairs —
direction, not mechanism. It confirms identity is becoming
infrastructure, not a feature (Forrester named "Agent Control Plane" a
category Dec 2025; NIST launched a federal AI Agent Standards Initiative
Feb 2026 anchored on agent identity + authorization). It is not
transferable to our model: we do not build a central registry or
real-identity binding.

---

## 2. Token formats

One envelope, three kinds. **Ed25519-signed, not HMAC** — justified
below; no PKI (deployment-controlled public-key roster, the
`gov/signing.py` offline-root trust model).

```jsonc
{
  "token_version": 1,
  "token_kind": "user" | "agent" | "delegation",
  "issuer": "<key id of the signing key>",
  "subject": "<who the token is about>",
  "issued_at": "<ISO-8601>",
  "not_before": "<ISO-8601>",
  "expires_at": "<ISO-8601>",
  "session_id": "<session/run binding>",
  "claims": { /* kind-specific, flat str/str-or-list */ },
  "sig": "<ed25519 hex over the canonical body>"
}
```

Kind-specific `claims`:

- **user** (`token_kind: "user"`): `{"user_id", "display_name",
  "permissions": [...]}`. Issued by the identity-provider stand-in key.
  `permissions` is the user's entitlement set (capability strings —
  see §6).
- **agent** (`token_kind: "agent"`): `{"agent_id", "role",
  "principal", "workload_id", "capabilities": [...]}`. Issued by the
  deployment's **registration-authority key** (the agent as OAuth 2.0
  native client, per South et al.). `capabilities` is what this agent
  build is allowed to do.
- **delegation** (`token_kind: "delegation"`): `{"delegator",
  "user_token_hash", "agent_token_hash", "scope": [...],
  "revocation_endpoint", "audit_urls": [...], "delegation_depth": 0,
  "parent_token_hash": null}`. **Issued and signed by the human
  delegator.** `user_token_hash` / `agent_token_hash` are the SHA-256
  refs of the other two tokens (South et al.'s binding).
- **sub-delegation** (spawn lineage): same `token_kind:
  "delegation"`, with `delegation_depth ≥ 1`,
  `"delegator": "<parent agent_id>"`, `parent_token_hash` = ref of the
  parent's delegation token, `scope` ⊆ parent scope, **signed by the
  parent agent's key**. The spawn-lineage mechanism and the swarm
  control in one (§7).

### Why Ed25519, not HMAC (the required justification)

The human-signature and parent-signature properties are
*unforgeability-by-the-verifier* properties: the agent (and the
in-process governance layer it shares memory with) must be able to
**verify** a delegation without being able to **mint** one. HMAC is
symmetric — the verifier holds the signing key, so any verifier-side
key holder (the agent) can forge "human-signed" delegations. That would
make the signature theater: the break-first probe "forge a delegation
token without the human key" would be vacuous, because the "human key"
would sit in the same process as the attacker.

Ed25519 gives the asymmetry the threat model needs: the human's private
key and each parent agent's private key never enter the agent's reach;
verifiers hold only public keys. This reuses the tree's established
asymmetric substrate — `gov/ed25519.py` (RFC 8032, byte-exact test
vectors), `gov/signing.py` (`Signer`/`Verifier`, offline-root trust
model: "Verifiers trust exactly one root public key") — and the wave-72
anchor wave's Ed25519 statements. The HMAC keyprovider substrate stays
where symmetric integrity is the right tool: the audit log's chain MACs
(wave-69/70), whose threat model is answered by the anchor, not by
non-repudiation. (`gov/ed25519.py`'s own docstring: HMAC gives no
non-repudiation between key holders — and non-repudiation between the
human delegator and the agent is exactly what a delegation token is.)

### No PKI

Public keys are registered **out-of-band in a deployment-controlled
roster** (`DelegationTrust`: human keys, registration-authority keys,
IdP keys, per-session agent keys). Key rotation = re-registration, and
re-registration is an audited deployment act (the Wave-75 author-identity
story will chain it). No certificate chains, no CA, no PKI to operate.

### The human-signature seam (stated honestly)

In the local/test model the "human delegator's key" is provisioned by
the deployment: the deployment registers the human's **public** key in
the trust roster out-of-band, and the human (operator console, admin
CLI — the deployer's identity key) signs with the private key. The
module seam: `issue_delegation(signer, ...)` takes a
`gov.signing.Signer` (private key held by the human/deployment, never
by the agent); `verify_delegation(...)` takes only public keys from the
roster. **In production this is the deployer's identity key** — the
human operator's key from the deployment's SSO/device-key
infrastructure, or the deployment admin's countersigning key. Tests use
`Ed25519Signer(secrets.token_bytes(32))` as the human stand-in, labeled
as such wherever it appears. The seam is honest about what it is: the
trust that the registered public key belongs to the human is a
deployment act, not a cryptographic proof.

---

## 3. Issuance, session binding, storage

**Issuance order at session start** (the session-open ceremony):

1. Deployment provisions the transport identity (F55 session identity).
2. IdP stand-in issues the **user token** (bound to `session_id`).
3. Registration authority issues the **agent token** (bound to
   `session_id`).
4. The human delegator issues the **delegation token**, referencing
   both hashes, with scope/expiry/revocation endpoint/audit URLs
   (bound to `session_id`).
5. `open_delegated_session()` writes the `session_open` provenance
   record: delegation hops (principal → agent) with v2 `tokens` slots
   filled — the three-token chain is **chained into the log at session
   start**, per the converged answer.

**Session/epoch binding:** every token carries `session_id` (the
governed run's id). A token presented in a different session/run fails
`verify` (`DelegationBindingError`) — the replay probe pins this. The
bind is to the session, not the wall clock: a token cannot migrate
across runs even within its TTL.

**Token storage — where the full tokens live, where they don't:**

- **In the log: never.** Prov hop `tokens` slots (v2) carry only
  *refs*: `{"tokens_schema": "south-3token/v1", "user_token_ref":
  "<sha256hex>", "agent_token_ref": "<sha256hex>",
  "delegation_token_ref": "<sha256hex>"}` — hashes, never secrets.
  (§7 contract, filled per this design's §2.)
- **Full tokens live in** the `DelegationContext` (enforcement memory,
  created at session open, held by the enforcement path — not
  agent-reachable as data) and the **deployment's token store** (the
  `audit_urls` in the delegation token say where an auditor resolves
  ref → token). The log's refs let an auditor chase them without the
  log ever carrying signing-capable material.

---

## 4. Expiry, clock skew, revocation

- **TTL:** default 3600 s (the SPIFFE SVID 1-hour grounding; the
  agent-fabric survey independently lands `exp` ≤ 1 h at trust
  boundaries). Per-issuance override; **hard cap 86400 s** (24 h) —
  beyond that is a re-delegation problem, and a day-long agent
  delegation is a standing privilege, not a delegation.
- **Clock skew:** 300 s each direction (matches provenance
  `_TIMING_SKEW`). Acceptance window: `not_before − skew ≤ now ≤
  expires_at + skew`. Verification takes an explicit `now`
  (testable); production passes the deployment clock. Skew games are
  bounded and stated: an attacker gains at most 5 minutes past expiry,
  and the bound is in the design, not hidden.
- **Revocation:** the delegation token carries `revocation_endpoint`
  (URI/identifier of the authority's revocation source) and
  `audit_urls`. The verifier exposes the seam: `revocation_checker`
  callable, `checker(token_ref) → bool`. The in-repo reference is
  `RevocationLedger` (a revoked-ref set, test-grade — the
  ConsumerRegistry `_revoked` pattern). **Default is TTL-only, and that
  is a stated boundary, not a gap we hide:** short TTLs paper over
  revocation; true propagation (Shared Signals-style, per the fresh
  WIMSE coverage in intake §4) is not built here. The learnings memo is
  explicit that short TTLs paper over this — the design says so too,
  in the token's own documentation and the verifier's docstring.

---

## 5. Permission intersection — fail closed by construction

Effective permission = **user permissions ∩ agent capabilities ∩
delegation scope** (MongoDB's conjunction: requester ∩ agent ∩ tool).
Enforced by `authorize_action()` in `gov/delegation_tokens.py`, called
by the executor's `call()` **before policy evaluation** when a
`DelegationContext` is installed.

"By construction, not by policy text" means: the check lives in Python
code on the call path; no policy YAML edit can remove it. The proof is
a test, not prose: with the policy file rewritten to allow-all, an
agent presenting an agent token but **no delegation token** is still
refused — `DelegationRequiredError` raised in code before the policy
engine is consulted. Conversely, policy text still narrows: a valid
delegation plus a policy deny → denied. Policy can only subtract from
the intersection, never add to it.

The "agent without delegation" case is therefore not a policy rule
that a mis-edited YAML could drop; it is a code path that raises. The
missing-delegation probe pins both directions.

---

## 6. Scope language and per-hop attenuation (spawn lineage)

Scope entries are capability strings: `"tool:<tool_name>"` or the
wildcard `"tool:*"`. v1 is deliberately tool-granular (resource-scoped
entries are future work — stated, not smuggled in).

**Spawn:** `spawn_sub_agent(parent_ctx, sub_agent_id, sub_scope,
parent_signer, ...)`:

1. `sub_scope` must be **covered by** the parent scope: every child
   entry is matched by a parent entry exactly, or by a parent
   `"tool:*"`. Expansion (`⊄`) → `DelegationAttenuationError` at
   issuance. (Monotonic non-increasing; equal scope is allowed —
   re-delegation — but pointless; the pin is that widening is
   refused.)
2. Empty `sub_scope` refused (a spawn with no authority is meaningless).
3. The child token is **signed by the parent agent's private key**
   (the parent's workload key, provisioned at the parent's spawn) and
   carries `parent_token_hash` + `delegation_depth = parent_depth + 1`.
4. **Depth cap 8** (swarm control; the agent-fabric survey enforces
   `max_chain_depth` the same way). Deeper chains are a design smell —
   re-delegate from the human instead.

**Chain verification** (`verify_delegation_chain`): every hop's
signature is verified against the right roster (human keys at depth 0,
the parent's session-registered key at depth ≥ 1), every hop's
`parent_token_hash` must equal the actual parent token's ref, scope
must be monotonic non-increasing hop-to-hop, and the root must be a
human-signed depth-0 token. A recipient **verifies the chain, never
trusts its claims** (MongoDB's second break point). The parent-signature
swap probe (child token signed by anyone except its actual parent)
and the truncation probe (drop a middle hop — the wave-73 binds
validator catches it against v2-filled tokens) pin this.

Each sub-agent hop in the provenance delegation path carries that
hop's own delegation token ref in its v2 `tokens` slot (user/agent
refs inherited from the session root — the user and the agent don't
change down the chain; each delegation hop adds its own authority).

---

## 7. Break model (what the probes show)

Registry `redteam.identity_w74.*` (8 probes, pattern RT22, all expected
`stopped`; `evals/w74_probes.py`, 8/8 HOLD 2026-09-22):

| Probe | Attack | Must show |
|---|---|---|
| `delegation_forgery_refused` | forge a delegation token without the human private key (re-sign with attacker key / tamper a signed scope claim) | `verify` fails — Ed25519 signature invalid against the human roster |
| `scope_escalation_refused` | sub-agent token with scope ⊄ parent scope | issuance refused (`DelegationAttenuationError`) AND a hand-built widened token fails chain verification |
| `missing_delegation_fails_closed` | agent acts with no delegation token; policy YAML rewritten to allow-all | `DelegationRequiredError` from code — policy text cannot re-enable it (construction proof); refusal audit-logged; tool never runs |
| `cross_session_replay_refused` | delegation token from session A presented in session B | `DelegationBindingError` at verify time AND at the executor gate |
| `expiry_and_skew_enforced` | expired token; token at expiry+skew+1s | refused; inside-skew accepted (bounded, stated) |
| `parent_signature_swap_refused` | sub-agent token signed by a non-roster key; correctly-signed child spliced onto a different parent hash | chain verification fails at the swapped/spliced hop |
| `middle_hop_truncation_detected` | drop a middle hop from a v2 delegation path | wave-73 `validate_delegation` (v2) breaks on the binds chain |
| `valid_chain_authorizes` | control: full issuance user→agent→delegation→sub-agent | binds, authorizes, spawns, executes; `open_delegated_session` fills v2 slots |

Every genuine independently-reachable miss → harden same-wave or file
**F129**.

---

## 8. Deliberately not done (Wave-75 or later)

- **Revocation propagation** — the seam exists (`revocation_endpoint`,
  `revocation_checker`, `RevocationLedger` reference); true
  push/propagation (Shared Signals-style) is a stated boundary.
- **Resource-scoped entries** (`tool:send_email:to:example.com`) —
  the scope language is tool-granular in v1 by design.
- **Selective disclosure / ZK property proofs** — research gap, no
  shipped answer anywhere (wave-73 §9 carried forward).
- **PKI for key distribution** — roster model only, by decision.
- **The commercial evidence pipeline** — no metering/billing/SaaS
  (strategic context only).
- **Live transport** — no mTLS/SPIRE in this local model; the
  transport layer is the provisioned session identity + process
  boundary, stated as such.

## 9. Wave-75 readiness (governing-the-governors)

Wave-75 needs "who changed the rules" — the author identity for policy
changes. This wave delivers the primitive it builds on: the **human
delegation token's `delegator` + signature** is the first human-keyed
identity in the tree with a real private key behind it (not a string).
Wave-75 can reuse the envelope for *policy-change authorship*: a policy
mutation signed by the human author's key, chained like a delegation
(`parent_token_hash` → the previous policy version's authorship token),
verified against the same roster. The roster's re-registration audit
trail is the key-management story Wave-75 inherits. Nothing in this
wave pre-builds the policy-change flow — it only makes the author key
exist as a first-class, verifiable thing.

---

## Changelog

- 2026-09-22 (wave-74, closeout): implementation review fixes landed —
  `bind()` raises `DelegationRequiredError` (not a confusing signature
  error) when no delegation token is presented; revocation-checker
  errors fail closed as `DelegationRevokedError` (catchable by the
  executor gate, never a raw crash); `enforce_tool_call` binds the
  leaf delegation's subject to the acting `AgentIdentity.agent_id`
  (siblings cannot borrow a delegation). Fresh intake corroboration
  (`research/intake-wave74-2026-09-22.md`): South et al. field mapping,
  Red Hat SPIFFE two-layer wording, MongoDB Pattern 4's two break
  points (pinned by `scope_escalation_refused` and the
  verify-not-trust chain walk).
- 2026-09-22 (wave-74): v1 of this document; three-token envelope
  (`south-3token/v1`), Ed25519 justification, SPIFFE layer mapping for
  our tree, human-signature seam, storage/expiry/skew/revocation,
  intersection-by-construction, per-hop attenuation, break model,
  Wave-75 handoff.
