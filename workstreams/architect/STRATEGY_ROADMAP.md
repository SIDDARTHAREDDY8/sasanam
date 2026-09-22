# Strategy Roadmap: D1–D5 → Executable Work Items

**Role:** Principal Architect (overnight, design only — no production code)
**Date:** 2026-09-22 · **Status:** DRAFT for engineering-lead review
**Inputs read:** `research/competitive-deep-dive.md` (full), `gov/approvals.py`,
`gov/approval_web.py` (docstring + structure), `gov/adapters/core.py`,
`policies/default.yaml`, `gov/policy.py` (header), `gov/keys.py` + `gov/kms.py`
(headers), BUILD_LOG.md (tail), `evals/ADAPTER_INTERFACE.md` (exists, not
re-read in full).
**Not available in this working copy:** `workstreams/architect/ROADMAP.md` and
`workstreams/architect/ADJUDICATIONS.md` do not exist in this ZIP export
(`workstreams/` contains only `market/` and `sandbox/`). The deep-dive's
references to prior architect decisions (P4 approval-web promotion,
"Architect decision" labels in `gov/approval_web.py`) were used as the
substitute record. If ROADMAP.md/ADJUDICATIONS.md exist elsewhere, reconcile
this document against them before dispatching work.

**Standing orders honored:** docs only (no `BUILD_LOG.md` edits, no commits,
no pushes, repo stays private, $0 spend — all new facts below are from
free public sources already cited in the deep-dive plus two fresh searches
run tonight).

---

## 0. TL;DR for the lead

| # | Decision | Verdict | Scale |
|---|----------|---------|-------|
| D1 | Durable approval queue + bridges into AGT/AWS | **BUILD** — but split into 3 sub-integrations with very different feasibility (see §1) | Core queue: weeks. AGT-Python shim: 1–2 weeks. AGT-.NET webhook: 3–6 weeks + protocol research. AWS bridge: 4–8 weeks, needs customer creds + policy cooperation |
| D2 | Battery as neutral benchmark vs their governors | **BUILD the harness; RUN vs AGT + Dogwood locally; PARK live-AWS runs** | Weeks; publish step gated on user approval |
| D3 | Freeze engine; Cedar export | **BUILD, with a fail-closed conflict resolved in §4** | 2–4 weeks |
| D4 | Audit narrowed to key lifecycle + enforced retention | **BUILD (small, real)** | 1–3 weeks; resolve Ed25519/Merkle conflict in §4 |
| D5 | Stay a component; upstream contribution as live option | **Posture + docs; contribution gated** | Days; license decision needed |

**Priority order (rationale in §6):** D1-core → D4 → D3 → D2 → D5.
**STOP list (§5):** policy-engine racing, signature/Merkle arms race (after
in-flight threshold lands), sandboxing ambition, new framework adapters,
compliance mappings, SSO/TLS/multi-tenancy for the console, MCP scanner
duplication.

**Two corrections to the deep-dive that change D1's shape** (both verified
tonight):
1. The deep-dive says "adapters that plug AGT's `require_approval` webhook
   and AWS's approval events INTO our queue." For AWS this is backwards:
   **AWS emits no approval events.** Temporal policies *gate on* trajectory
   events that customer code must produce (e.g. an `ApproveSale` action
   whose `response` has `output.approved: true`). Our AWS bridge is an
   approval-event **producer** into the trajectory, not a consumer of an
   AWS webhook. The deep-dive's framing would send an implementer looking
   for an ingress API that does not exist.
2. AGT's Python `WebhookApproval` (PR #1383) POSTs to **Slack/Teams/PagerDuty
   webhook URLs** — notification-shaped payloads, not a generic approval
   protocol. The clean Python integration is a `CallbackApproval` shim we
   ship (in-process), not a receiver for their webhook. The network-shaped
   integration lives on the **.NET side**: their README documents a
   `WebhookApprover` with a versioned payload (request + action digests,
   policy + chain versions, expiry) and verifier-gated responses — a real
   protocol surface, but one needing research against their actual code.

---

## 1. D1 feasibility pressure-test (per integration)

### 1a. AGT Python — `CallbackApproval` shim (RECOMMENDED path)

**What their side emits.** Per PR #1383 (verified in deep-dive + re-confirmed
tonight): `govern(tool, policy, approval_handler=handler)` pauses on
`require_approval`; handlers are `AutoRejectApproval`, `CallbackApproval(fn
+ timeout)`, `ConsoleApproval`, `WebhookApproval` (HTTP POST to
Slack/Teams/PagerDuty URLs). Semantics: 5-min default timeout, deny-on-timeout,
callback errors deny, deny rules bypass approval. `CallbackApproval` takes an
arbitrary function receiving the approval request and returning an
`ApprovalDecision` — **this is our documented seam**.

**What our adapter is.** A new module `gov/bridges/agt.py` exposing
`DurableQueueApprovalHandler` — a class conforming to AGT's `ApprovalHandler`
interface (implement `request_approval(context) -> ApprovalDecision`):
on call it translates the AGT request context into our
`ApprovalQueue.queue(...)` record (tool, args, policy id, agent identity,
preview), blocks on the decision with a **bounded wait shorter than AGT's
timeout** (configurable, default e.g. 4 min against their 5-min), then returns
`ApprovalDecision(approved=…, approver="…")`.

**What the adapter must validate / get right:**
- **Correlation:** every AGT request gets our queue-record id; the wait maps
  1:1, no cross-talk under concurrency (threading.Event per record or poll
  under the queue lock).
- **Timeout semantics (the sharp edge):** if our bounded wait expires, we
  return deny (fail-safe, matching their deny-on-timeout) — **but the record
  stays pending in our durable queue.** A human may decide it *later*. That
  late decision must be audit-labeled `late/superseded` and **must never be
  executable**: invariant — `execute_approved()` refuses records whose
  bridge wait already timed out (add a `bridge_expired` marker at timeout
  time; execution checks it). Otherwise a slow human approval could execute
  an action AGT already denied — a TOCTOU the red team would file instantly.
- **Identity mapping:** AGT agent identity (their `did:agentmesh:…`) → our
  `agent_id`/principal fields, recorded verbatim as untrusted framing; the
  human sees our executor-generated preview, never their text.
- **No secret handling:** the shim passes no credentials; it runs in-process.

**Verdict: weeks-scale adapter (1–2 weeks), low protocol risk.** It is a
library shim, not a protocol project. Limitation to state honestly: it only
works where our queue runs in the same process/deployment as the AGT-governed
agent — it is not "AGT Cloud posts to our SaaS." That is consistent with D5
(component, not platform).

### 1b. AGT .NET — `WebhookApprover` ingress (PROTOCOL INTEGRATION)

**What their side emits** (new finding tonight, from the .NET SDK README —
the deep-dive did not cover the .NET approval surface):
an `ApprovalRequest` coordinator (`OpenRequest` → `SubmitEntry` votes →
`ValidateForExecution`), quorum stages, and for remote workflows a
`WebhookApprover` attached to an `ApprovalStage`. Quote: *"Its versioned
payload carries the request and action digests, policy and chain versions,
and expiry. Approve responses are accepted only when a supplied
`WebhookResponseVerifier` returns an identity established through
authenticated transport or a verified assertion… `ResolveAsync` consumes an
allowed approval before returning."* Also: a chain with no required
non-advisory stage fails closed (`no_required_approval_stage`).

**What our adapter is.** An HTTPS ingress endpoint (new module, e.g.
`gov/bridges/agt_webhook.py`, mounted beside or behind `approval_web.py`)
that: receives their versioned payload → validates → creates a queue record
embedding their request digest + action digest + policy/chain versions →
human decides in our console → we return the approve/deny response in the
shape their verifier accepts.

**What the adapter must validate (fail-closed):**
- **Authenticity:** inbound POSTs must be authenticated — mTLS client cert
  or HMAC-signed payload with an out-of-band-exchanged key. Their side
  demands "authenticated transport or a verified assertion" for *responses*;
  we must demand the equivalent for *requests*, or anyone can inject
  approval requests into our queue (queue-poisoning → fatigue attack).
- **Replay / double-decision:** idempotency key = their `ApprovalRequestId`;
  mirror their consume-once semantics — a second POST for the same id is
  rejected (or returns the recorded decision, never re-queues). Replayed
  approvals must not produce two executions.
- **Schema:** strict validation of the versioned payload; unknown payload
  versions are rejected (fail closed), never parsed optimistically.
- **Expiry:** honor their `expiry`; expired payload → deny + audit, even if
  the human later approves (same late-decision invariant as 1a).
- **Digest binding:** their request/action digests go into our record's
  MACed security payload (extend `_SECURITY_PAYLOAD_FIELDS` or a
  bridge-specific binding) so a swapped payload between receipt and
  decision breaks verification.

**Verdict: 3–6 weeks + protocol research.** The contract is *partially*
documented in prose; the exact JSON schema and the `WebhookResponseVerifier`
mechanics must be read from their .NET source before we commit to field
names. Do not start implementation until the schema is pinned from their
code — this is the one D1 sub-item that is genuinely protocol research, and
it must not be hand-waved.

### 1c. AWS AgentCore — approval-event PRODUCER bridge (CORRECTED direction)

**What AWS actually provides** (verified tonight against AWS's temporal-
policies blog and the community samples):
temporal policies (`when temporal { formerly within 1h
AgentCore::Action::"ApproveSale"::response{ … output.approved: true } }`)
permit a privileged action only when a **matching prior trajectory event**
exists in the same session. The trajectory is per-session gateway traffic.
The approval event is **produced by customer code** — typically a tool call
through the Gateway named e.g. `approve_trade` whose response carries
`output.approved: true`, unconsumed, within the window (banking-assistant
sample). AWS provides the gate; the event producer is "composed via
HumanLayer or similar" — i.e., **us**.

**What our adapter is.** Two halves, both new (`gov/bridges/aws.py`):
1. **Denial watch → queue record.** When the customer's agent hits a
   temporal-permit denial (missing approval), *something* must create the
   human task. Options, honest: (a) the customer's agent code calls our
   bridge on denial (documented integration function — simplest, no AWS
   read API needed); (b) we poll AgentCore Observability / CloudWatch
   Transaction Search for approval-shaped denials (needs customer creds,
   eventual consistency, more moving parts). Ship (a) first; (b) is a
   documented future.
2. **Decision → trajectory event.** On human approval in our console, the
   bridge invokes the customer-named approval action **through their
   Gateway** (their endpoint, their IAM credentials, same session id and
   principal as the original request, input fields matching exactly what
   their Dogwood policy matches on — e.g. `input.stock`, `input.shares`,
   `eventResource`) with `output.approved: true`, so the trajectory
   contains the event the policy gates on. On human denial, it emits
   nothing (deny-by-default does the rest) but audits the denial.

**What the adapter must validate (fail-closed):**
- **Configuration binding:** the bridge refuses to run unless the approval
  action name, gateway ARN/endpoint, and the policy's match fields are
  explicitly configured — a misconfigured bridge must never emit an event
  the policy *wasn't* written to gate on (that would be a forgeable
  allow). Unknown/unconfigured → loud refusal.
- **Session/principal correlation:** the emitted event must carry the exact
  session id + principal of the gated request; cross-session approval
  events are refused (otherwise one approval could authorize another
  session's trade).
- **Single-use:** mirror the "unconsumed approval" pattern — each approval
  event carries our unique decision id; document the Dogwood pattern that
  consumes it; never re-emit for the same decision.
- **No credential custody in-repo:** the bridge takes credentials from the
  operator's environment/config at runtime; nothing ships, nothing is
  logged (the trajectory itself is the customer's AWS-side record; our
  audit log records *that we emitted*, not the credential).

**Verdict: 4–8 week project for one reference implementation, gated on
customer cooperation** (their IAM creds, their gateway, their Dogwood policy
naming the approval action). It is real protocol/integration work, not a
weekend webhook. **Hard constraint:** we cannot integration-test against
live AgentCore under $0/no-credentials — the reference implementation ships
with a `FakeGateway` test double (same honesty pattern as
`FakeKmsProvider`), and live validation is an operator-side step documented
in the bridge README, not a CI gate.

### D1 core queue work (the flagship itself)

The queue already has: file-backed records (restart-surviving), HMAC-bound
integrity (F34/F43), policy pinning, TTL, separation of duties, risk scoring,
flood + anomaly defense (F4), batch guards (F21/F24), break-glass tickets
(F49), and a 26/26 adversarial web battery. **What the deep-dive scopes as
missing:** delegation/reassignment, quorum (M-of-N — AGT already has this;
we must at least match it), and bridge ingress. Concretely:

**Build scope (files to create/touch):**
- `gov/approvals.py` — add **delegation**: a pending record may be
  reassigned to another human principal; delegation is itself a MACed,
  audited transition (re-MAC the record with `delegated_to` in the security
  payload; the original requester's separation-of-duties still holds —
  delegation never routes back to the requesting agent). Add **quorum**:
  `approvals.quorum:` policy section (`min_approvals`, eligible principals);
  each vote is an audited, identity-bound event; the record executes only
  when votes ≥ quorum AND no deny vote (deny-vote semantics: one deny =
  denied, fail-safe). Votes are part of the MACed payload.
- `gov/approval_web.py` — delegation UI (reassign form, same CSRF/session
  discipline), quorum vote display + vote buttons; **depends on F80 landing
  first** (logout CSRF fix touches the same session/CSRF renderer paths).
- `gov/bridges/agt.py` (new, 1a), `gov/bridges/agt_webhook.py` (new, 1b),
  `gov/bridges/aws.py` (new, 1c), each with a README contract.
- `policies/default.yaml` — `approvals.quorum:` + `approvals.delegation:`
  sections (lint-covered by `gov/policy_lint.py`); byte-identical copy in
  `gov/data/default.yaml` (drift-guard test).
- `tests/test_bridges_*.py` (new) + adversarial bridge probes in
  `evals/w22_probes.py` (replay, tamper, late-decision, quorum-bypass,
  cross-session approval).

**Fail-closed invariants to preserve/extend:**
- Every new record field that influences the decision (delegated_to, votes,
  bridge digests, expiry markers) enters the MACed security payload.
- Late decisions (after bridge timeout or payload expiry) are audit-only,
  never executable (`bridge_expired` marker checked in
  `execute_approved()`).
- Quorum: votes authenticated as human principals; requesting agent can
  never vote; one deny vetoes; corrupt vote store → refuse the sweep.
- Bridge ingress (1b): unauthenticated/replayed/expired/unknown-version
  payloads are refused loudly, never queued.

**Test/closure criteria:** full suite green; new unit tests for delegation +
quorum state machine; adversarial battery extended with ≥10 bridge
situations (replay of AGT payload, tampered digest, late approval after
timeout, quorum bypass by double-vote, cross-session AWS event, unconfigured
bridge refusal) — all stopped; threat-model entry for bridge trust
boundaries.

**Dependencies:** F80 (web CSRF) before web UI changes; F78 (tip manifest)
strengthens the audit binding D1 records rely on — coordinate, don't block;
wave-22 for the bridge probes.

---

## 2. D2 — battery as neutral benchmark (evidence infrastructure, not SKU)

**Problem statement.** The battery attacks *our own* enforcement layer
(~95 situations and growing; wave-21: 42 situations, 37 stopped). Nobody else
does this to *their* governor (AGT red-team = prompt-text audit; promptfoo/
Mindgard = model attacks). The commercial shape is not a product but a
neutral benchmark: run the same method against AGT's engine and AgentCore
policies, publish the methodology and results either way. Credibility
compounds; a benchmark only we can be accused of gaming is worthless, so
neutrality (including publishing our own failures) is the product.

**Build scope:**
- `evals/ADAPTER_INTERFACE.md` + `evals/real_adapters.py` already define a
  target-engine seam — add a `TargetEngine` ABC: `evaluate(scenario) ->
  verdict` mapping our situation corpus onto the foreign engine.
- `evals/targets/agt_engine.py` (new): install AGT's Python SDK from PyPI
  ($0, local), translate a *subset* of situations (policy-evasion,
  approval-ceremony, DLP-bypass classes) into AGT YAML policies + contexts,
  run, record allow/deny/require_approval vs expected. **Known semantic
  mismatch to document, not hide:** AGT resolves conflicts by
  MostSpecificWins; we resolve deny-first. The harness must compare
  *outcomes against the scenario's security expectation*, not engine-vs-
  engine parity — engines are allowed to differ where both are safe.
- `evals/targets/dogwood_local.py` (new): Dogwood is **open source,
  Apache 2.0** (`github.com/dogwood-policy/dogwood`; reference interpreter
  explicitly "not for production" — fine for eval). Translate our
  deny/allow rules to Cedar/Dogwood (this is also the D3 validation loop:
  the exporter and the benchmark target share the translator), evaluate
  locally, $0, no AWS account.
- **PARKED — live AgentCore:** running against a real Gateway needs an AWS
  account, IAM creds, and per-request metering. Under $0/no-credentials
  standing orders this is design-only. Do not fake it: a "simulated
  AgentCore" result presented as a benchmark would be exactly the kind of
  dishonest claim the deep-dive warns against. Revisit only with explicit
  user approval + a test account.
- Methodology doc `evals/BENCHMARK_METHOD.md` (new): scenario selection,
  translation rules, what "stopped" means per engine, residuals policy
  (publish ours too).

**Fail-closed invariants:** the benchmark never weakens our own gate to make
a foreign engine look better (translations are additive files; our engine's
semantics untouched); results are recorded with the translator version so a
translation bug can't masquerade as an engine failure (re-run on translator
change).

**Test/closure criteria:** harness runs N scenarios × {ours, AGT, Dogwood}
locally with a results table in `evals/`; at least one full run committed
with translator version pinned; methodology doc reviewed by the lead.

**Dependencies:** D3's translator (shared); wave-22 corpus expansion feeds
scenarios. **Publish gate (§4 conflict): anything public needs explicit user
say-so — the harness and local runs are fine; the "publish results" step is
a separate approval.**

---

## 3. D3 — freeze the engine; Cedar export (portability vs AWS lock-in)

**Problem statement.** AWS's lock-in is the enforcement plane (Gateway,
`BedrockGuardrails::*` functions, CloudWatch audit), not the policy
language — Cedar is open source and policy-as-code ports. A $0 self-hosted
authoring-and-testing layer whose policies deploy to AgentCore is a
coherent anti-lock-in story, and it is the one thing AWS's opaque
NL→Cedar authoring can't offer. Meanwhile our engine stays exactly what it
is: the harness's system-under-test, not a product.

**Build scope:**
- **Freeze:** `gov/policy.py` semantics frozen at version 2. No new effects,
  no perf chase (their 0.037 ms p99 eval is not our race), no hot-reload
  ambition. Changes allowed only for security fixes and lints.
- `gov/policy_export.py` (new): YAML v2 → Cedar/Dogwood policy text.
  - **Total mappings:** `deny` → `forbid` (forbid-wins ≡ our deny-first —
    genuinely aligned); `allow` → `permit`; default-deny ≡ default-deny;
    `role` allowlists → Cedar principal scoping; `tool` →
    `AgentCore::Action`; every other match key (`path_outside_sandbox`,
    `domain_allowlisted`, `carries_read_content`, `source_untrusted`,
    `read_sensitive`, `path_contains_any`, `when` comparisons) →
    typed `context` attributes under a **documented context schema**
    (`docs/cedar-context-schema.md`, new) that the operator's gateway
    mapper must populate. `min_sends/min_writes/min_deletes` and
    `min_external_calls` → Dogwood `count_within` temporal blocks
    (stateful — plain Cedar can't express them; see conflict below).
  - **Lossy point — `require_approval`:** Cedar has no such effect.
    Resolution (fail-closed): the exporter **errors** on
    `require_approval` rules *unless* a `bridge:` binding names the D1-AWS
    approval action, in which case it emits a Dogwood temporal permit
    gated on the bridge-produced approval event (`formerly within <ttl>
    AgentCore::Action::"<ApprovalAction>"::response{… output.approved:
    true }`, single-use pattern per §1c). **Never silently permit.**
  - Non-policy sections (`auto_approve`, `batch_excluded_queue_reasons`,
    `approvals.*`, `campaign_allowlist`, `log_limits`) do not export —
    they are operational, not authorization; documented as such.
- Validation: round-trip tests (export → evaluate under the open-source
  Dogwood interpreter → same verdicts as our engine on the scenario
  corpus); `gov/policy_lint.py` gains an `--export-check` mode.

**Fail-closed invariants:** exporter errors (exit non-zero, loud) on any
unmappable rule — no silent drops, no silent permits; exported text carries
a header pinning the source policy hash (drift detectable); the D3
translation is validated by D2's Dogwood target (§2) on every run.

**Test/closure criteria:** `policies/default.yaml` exports cleanly;
verdict-parity suite (our engine vs Dogwood-local on ≥50 scenarios)
green; exporter refuses a policy with unbridged `require_approval`.

**Dependencies:** D1-AWS bridge contract (§1c) for the `require_approval`
mapping; D2's Dogwood target is the validation loop. **Conflict resolved:**
see §4.

---

## 4. D4 — audit narrowed to key lifecycle + enforced retention

**Problem statement.** Don't claim better signatures (lost: AGT shipped
Ed25519 + Merkle + 157 conformance tests). Both competitors fumble the
operational side: AGT's `retention_days` is declaration-only and its
signing-key rotation story is undocumented; AWS's rotation story is
unverified. Our genuine niche: keys you can actually operate
(F19 rotation-safe verify, F73/F77 dev-key rejection, KMS envelope keyring)
plus retention that is *enforced*, not declared.

**Build scope:**
- **Key lifecycle (mostly landed — finish, don't expand):** land the
  in-flight Ed25519-threshold work as the *verifier* side of key lifecycle
  (external auditors verify without holding the HMAC key), then **freeze**.
  No Merkle-proof ambition — that race is lost to AGT's `MerkleAuditChain`;
  say so in the docs. `gov/kms.py` stays provider-neutral; real cloud
  wiring remains operator config (documented, not built); `FakeKmsProvider`
  stays dev-only behind `GOV_DEV_KEYS=1`.
- **Enforced retention (the actual build):**
  - `policies/default.yaml` (+ `gov/data` twin): a `retention:` section
    with `min_retention_days` and `max_retention_days`, where the engine
    **enforces** them (contrast: AGT declares). Enforcement points:
    `log_limits.max_log_bytes` already fails closed when full — extend to
    a `gov/retain.py` (new) CLI: `seal` (verify chain → write manifest →
    archive), `verify-archive`, and `expire` (delete archives past
    max_retention_days only with dual human approval recorded in the
    action log; deleting the *live* log is always refused).
  - F78's root-signed tip manifest (in flight) is the primitive `seal`
    builds on — sequence D4-retention after F78 lands.
- Docs: `docs/key-lifecycle.md` (new) — the honest operator story:
  rotation ceremony, dev-key rejection, what HMAC can't do
  (non-repudiation limits already in `gov/keys.py` docstring), KMS
  envelope, retention enforcement. This doc is the D4 "product."

**Fail-closed invariants:** rotation never proceeds on a tampered log
(already in `rotate_keyring`); archives verify with retired keys (already);
`expire` refuses without quorum-of-two human approvals and never touches
the live log; retention config missing → fail closed to a safe default
(documented), never to unbounded growth or silent deletion.

**Test/closure criteria:** retention CLI tests (seal/verify/expire,
refusals); rotation ceremony tests incl. dev-key archive rejection
(F77 regression); docs reviewed; suite green.

**Dependencies:** F78 (tip manifest) before `seal`; F77's `gov/keys.py`
hardening is the pattern to follow.

**Conflict resolved (§4):** the pre-deep-dive memory item "Ed25519 + Merkle
proofs" is superseded — land Ed25519-threshold (in flight), cancel Merkle.

---

## 5. D5 — stay a component; upstream contribution as a live option

**Problem statement.** No managed cloud, no SSO promises, no compliance-
paper chase. The honest-limits discipline (FINDINGS.md residuals, module
docstrings that say what isn't claimed) is our best marketing — keep it as
a *practice*, not just a tone.

**Build scope (docs + readiness, no product):**
- `docs/COMPONENT_POSTURE.md` (new): what we are (reference implementation
  + eval harness + approval queue that plugs into AGT/AgentCore), what we
  are not (not a platform, not a cloud, not a compliance vendor), and the
  deployment contract for the bridges (real auth + TLS + KMS-backed keys
  required before any network ingress — until then, in-process shim only).
- **Upstream readiness:** keep `gov/approvals.py` stdlib-only (it already
  is) so the queue *could* be contributed to AGT; keep bridge modules
  dependency-light. **Two gates:** (1) contributing upstream = publishing
  code = explicit user say-so (standing order); (2) the repo currently has
  **no LICENSE file** — any contribution or publication needs a license
  decision by the user first. Record both gates here so nobody "helpfully"
  starts the process overnight.
- If Microsoft ever ships a durable queue: our queue becomes a PR candidate
  and the battery is the reason they take it — that is the strategy, stated
  plainly, not a euphemism for losing.

**Closure criteria:** posture doc written and linked from README;
LICENSE decision explicitly parked as a user decision (not defaulted).

---

## 6. Priority order + rationale

1. **D1-core (delegation, quorum, bridge ingress auth)** — the flagship and
   the only wedge shaped like a product. Unblocks D3's `require_approval`
   mapping and gives D2's benchmark something with a network boundary to
   test. Within D1: core queue → AGT-Python shim → AWS bridge reference →
   AGT-.NET webhook (protocol research last, highest uncertainty).
2. **D4 (key lifecycle finish + enforced retention)** — small, genuinely
   unoccupied, auditor-visible. Sequences after F78.
3. **D3 (Cedar export)** — needs D1's AWS-bridge contract for the
   `require_approval` mapping; validated by D2's Dogwood target. Sells
   portability against the exact lock-in AWS monetizes.
4. **D2 (neutral benchmark harness)** — parallelizable with 1–3 once the
   translator exists; credibility compounds but doesn't unblock anything.
   Local runs now; publish later, gated.
5. **D5 (posture docs)** — cheap, do it in the gaps; the LICENSE/upstream
   gates are user decisions, not engineering.

**Rationale in one line:** build the thing only we have (queue), finish the
small thing neither competitor operates (keys/retention), then the
portability story (export) and the proof (benchmark) that make the queue
credible — posture throughout.

---

## 7. STOP list (the concession, itemized)

| # | Ambition | Verdict | What it frees |
|---|----------|---------|---------------|
| S1 | Policy-engine racing (perf vs AGT's 0.037 ms p99, new effects, hot-reload) | **FREEZE** `gov/policy.py` at v2 semantics; security fixes + lints only | Engine work → D1/D3 |
| S2 | Audit-signature arms race (Merkle proofs to match AGT's `MerkleAuditChain`) | **STOP** after in-flight Ed25519-threshold lands (verifier-side of key lifecycle, already nearly done) | Crypto nights → D4 retention |
| S3 | Sandboxing beyond the honest prototype (`gov/sandbox.py`) | **HOLD** — no container/VM ambition; AGT's own docs concede app-layer ≠ isolation | Sandbox work → red-team battery |
| S4 | New framework adapters (parity chase vs AGT's ~6 deep) | **FREEZE** at current set (langchain, openai_loop, mcp, generic, channels) — adapters exist only as harness SUT surface | Adapter work → D1 bridges |
| S5 | Compliance mappings (SOC 2 / EU AI Act / ISO 42001 paper) | **ZERO EFFORT** — reference AGT's mappings; never out-paper Microsoft | Compliance time → D4 docs |
| S6 | SSO/TLS/multi-tenancy for the web console | **NOT NOW** — stay localhost-grade per the module's honest limits; the deployment contract (D5) says what's needed before network ingress | Console hardening → delegation/quorum |
| S7 | MCP security scanner (duplicating AGT's MCP Security Gateway, 127 tests) | **DON'T BUILD** — keep our StruQ / instruction-hierarchy *controls* (prevention layer, different from their detection) | Scanner work → battery |
| S8 | Identity racing (SPIFFE/DID/Entra vs AGT) | **HOLD** — PrincipalRegistry stays minimal harness infrastructure | Identity work → D1 quorum votes |
| S9 | Standalone battery SKU / paid eval product | **NEVER** — it's evidence infrastructure (D2); no pricing, no packaging work | Productization → benchmark neutrality |

**Discipline:** any proposal touching S1–S9 needs a written override from
the lead citing new evidence (the deep-dive's §4 watch-list is the tripwire:
AGT ships a durable queue, AWS ships native HITL, AGT production-hardens
Cedar, etc.).

---

## 8. Conflicts between D1–D5 and landed architecture (flagged, with resolutions)

1. **D3 vs our policy model — the mapping is NOT total.** `deny`→`forbid`
   and `allow`→`permit` are total and semantically aligned (forbid-wins ≡
   deny-first; default-deny ≡ default-deny). The lossy points:
   (a) `require_approval` has no Cedar equivalent — resolved by the
   fail-closed exporter (§3: error unless a D1-bridge binding converts it
   to a Dogwood temporal permit); (b) stateful match keys
   (`min_external_calls`, `cross_run_campaign`, `velocity_exceeded`) have
   no plain-Cedar equivalent — they export to **Dogwood only**
   (`count_within`/temporal), and the exporter must refuse plain-Cedar
   output for policies containing them. The exporter targets Cedar for
   stateless policies, Dogwood for stateful ones — document this, don't
   blur it.
2. **D2 "publish results" vs standing orders.** Repo stays private; nothing
   ships publicly without the user's explicit say-so. The harness, local
   runs, and methodology doc are fine. The *publication* step (and any
   contact with Microsoft/AWS, e.g. sharing benchmark results) is a
   separately-gated user decision. Do not let D2's momentum carry it past
   the gate overnight.
3. **D5 "contribute upstream" vs standing orders + missing LICENSE.** Same
   gate as (2), plus: the repo has no LICENSE file. Contributing to AGT
   (MIT) or publishing anything requires a license decision the user has
   not made. Parked, recorded, not defaulted.
4. **Concession "stop racing audit crypto" vs in-flight Ed25519-threshold
   work.** Resolution: land the threshold work (it's the *verifier* side of
   D4's key-lifecycle story and nearly done), then freeze. The Merkle-proof
   ambition from the earlier priority list is cancelled — AGT's
   `MerkleAuditChain` + 157 conformance tests ended that race.
5. **D1 network ingress vs honest limits.** The web console is localhost-
   grade by design (in-memory sessions, no TLS — F80's fix doesn't change
   that). AGT-.NET webhook ingress (1b) and any AWS-facing endpoint must
   not ship until the D5 deployment contract (real auth, TLS, KMS-backed
   keys) is satisfied. Until then: AGT-Python shim is in-process (fine),
   AWS bridge is a documented reference with `FakeGateway` tests (fine),
   .NET ingress stays behind the contract gate.
6. **D1-AWS direction vs deep-dive wording.** Corrected in §1c: we produce
   approval events into the trajectory; we do not consume AWS approval
   webhooks. Any work item phrased as "receive AWS approval events" should
   be rejected at dispatch.
7. **D3's `require_approval`→Dogwood mapping depends on D1-AWS.** The
   exporter cannot be closed until the bridge's approval-action contract
   (§1c) is defined. Sequence accordingly; the exporter ships first for
   deny/allow-only policies.

---

## 9. Suggested dispatch sequence (for the lead's morning review)

1. F78 + F80 land → red-team verification wave → suite green (in flight).
2. D1-core: delegation + quorum in `gov/approvals.py` (+ policy sections,
   lint, drift-guard twin) → web UI (post-F80) → suite green.
3. D1 bridges: AGT-Python shim → AWS bridge reference (+ `FakeGateway`) →
   AGT-.NET protocol research (schema pinned from their source first).
4. D4: retention CLI after F78; key-lifecycle doc anytime.
5. D3: exporter for deny/allow; `require_approval` mapping after bridge
   contract; validated by D2's Dogwood target.
6. D2: harness + local runs vs AGT + Dogwood; publish gated.
7. D5: posture doc in the gaps; LICENSE decision parked for the user.
8. Wave-22 battery expansion runs alongside throughout (bridge probes feed
   D1; corpus growth feeds D2).

*End of STRATEGY_ROADMAP.md — design only; no code changed. Awaiting lead
review before any dispatch.*
