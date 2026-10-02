# Wave-279 Report — ranked steals, traps, deltas

**Lane:** standing prospecting (research only). **Worktree:** `~/workspace/teams/wave279-prospect/`
**Status:** complete. REPORT AND STOP — no follow-on lanes from this report.

---

## Top-5 steals (ranked by mechanism → gap → lane-shape)

### 1. OpenFGA contextual tuples — per-invocation ephemeral grants (STEAL pattern)

- **Mechanism.** Relationship tuples (`user:anne, relation: viewer, object: document:budget`)
  with **contextual tuples** supplied inline on the CheckRequest — grants that exist only for one
  query's duration. CEL conditions attenuate them (time, budget, arg-digest). BatchCheck for bulk
  pre-authz; Expand returns the resolution tree as decision provenance.
- **Gap.** Agent identity + the grant graph: today we hand-roll grant rules; OpenFGA gives us a
  declarative, versioned relationship graph keyed on stable agent identity — and the concrete
  answer to "single-use lease" semantics (no standing grant, pass the grant inline on the check).
  The `from`-traversal operator models "A delegated to B who may call tool T" without imperative
  code. Expand trees are half of an evidence bundle already.
- **Lane shape.** `fga-tuples-prototype` — spec-first (to-spec, no product code): type system
  (agent/tool/session/resource), relation set (`can_invoke`, `can_invoke_readonly`,
  `delegated_to`), condition set (expiry/budget/arg-digest). Success: a red-first battery of
  adversarial delegation scenarios (escalation, expired-grant replay, contextual-tuple omission)
  behaving correctly in the OpenFGA playground/Docker image *before* any stdlib re-implementation
  is proposed. Then port the semantics into stdlib — do NOT ship the Go sidecar (a network PDP
  hop makes fail-open the default failure mode).

### 2. Promptfoo plugin × strategy × grader — the adversarial battery language (STEAL)

- **Mechanism.** Three-role taxonomy: **plugins** = *what* to attack (`pii:direct`,
  `prompt-injection`, `excessive-agency`, `rbac`, …); **strategies** = *how* to deliver it
  (`jailbreak:hydra`, `crescendo`, `goat`, `multilingual`, encodings, `retry`); **graders** =
  *how to score* (deterministic assertions + `llm-rubric` judge). Declarative `redteam:` config
  (plugin `id` registry, per-plugin `{id, numTests, config}` overrides, `purpose`-driven
  generation, `owasp:agentic` compliance presets). **Generate → commit → eval**: the generated
  suite is a pinned, reviewable artifact; eval replays deterministically; `retry` replays past
  failures as regression seeds.
- **Gap.** Our adversarial batteries are hand-rolled per wave with bespoke probes and ad-hoc
  reporting. This is the missing **battery language**: one shared attack vocabulary across
  waves, the generate/eval replay split (a wave-279 suite still replays at wave-300), and
  machine-readable evidence rows (`metadata.pluginId`, `metadata.strategyId`, `gradingResult` +
  stats) that feed directly into evidence bundles — *"sell evidence, not the engine."*
- **Lane shape.** `battery-schema` lane: define a `battery:` config schema mirroring `redteam:`;
  split break batteries into `generate` (probe synthesis, committed) and `eval` (deterministic
  replay); emit JSON rows with `metadata.{pluginId,strategyId}` + stats; ship a `report`
  renderer (severity × remediation). First acceptance: re-express one existing wave battery in
  the schema and show eval-only replay byte-identical across two runs with no model calls.
  $0: stdlib-only, YAML schema + JSONL rows.

### 3. HumanLayer approval-request contract (ADAPT)

- **Mechanism.** `@require_approval` at the function layer — the gate lives in tool dispatch so
  the LLM cannot route around it (deterministic, prompt-injection-proof). Agent-initiated
  outer-loop framing: the agent asks and waits on a pending record. Semantics:
  approved → executes; denied → refusal value returned (agent continues); human may
  **edit the request**; timeout expires fail-closed. Complete audit trail of who/what/when/
  decided. **4-tier function-stakes taxonomy** (low/medium/high stakes) drives which tools get
  the decorator; `human_as_tool` generalizes the flow to free-text consultation.
- **Gap.** Wave-278 built the approval queue; this closes the **UX/contract half**: multi-channel
  delivery of approval requests to real humans, approve/deny/edit/timeout semantics with durable
  pending state, and an audit-trail contract for *what the human decided* — so the chain covers
  human-in-the-loop governance end to end.
- **Lane shape.** `approval-request-record` lane: an `ApprovalRequest` record (id, tool name,
  args digest + full args, requester identity, stakes tier, channel, expiry, decision
  {approved, denied, edited-args, timeout}) persisted *before* dispatch; timeout default
  fail-closed; edit-args as a first-class decision (human rewrites the dangerous arg; agent
  proceeds with the edited call); every terminal decision appended to the hash-chained audit
  log. Break-first acceptance: (a) denied call never executes under prompt-injected re-request,
  (b) timeout expires fail-closed, (c) edited args re-validated before dispatch, (d) the chain
  covers all four terminal states. $0: stdlib-only; channels as notification adapters.

### 4. Llama-stack shield registry + eval-task-as-evidence (ADAPT)

- **Mechanism.** **Named shield registry** (`shields register --shield-id --params`), attached
  per agent as `input_shields`/`output_shields` wrapping both the inbound turn and the outbound
  response/tool-call args; the loop emits `shield_call` step events with a `violation` field —
  shield verdicts as observable telemetry. **Eval tasks = dataset × scoring-functions** as
  registered, reproducible artifacts with JSON/HTML reports — the "benchmark as evidence" pattern.
  **Inline-vs-remote provider split** as an explicit trust boundary: guards in-process at the
  agent-runtime layer, tools/credentials fan out across the boundary.
- **Gap.** (i) Our policy engine decides, but we lack a standardized attach surface for guards at
  both the inference turn and the tool-invocation — `input_shields`/`output_shields` is that
  surface. (ii) Our batteries emit ad-hoc scores; the eval framework makes a benchmark run a
  pinned, reproducible evidence artifact — the currency evidence bundles need.
- **Lane shape.** `shield-registry` lane: a `Shield` registry (named shields, JSON params) at
  inbound (request/prompt) and outbound (response/tool-call args) seams, each emitting a chained
  audit event with the verdict; plus an `EvalTask` record (dataset id × scoring-function ids),
  runnable headless, whose output (score, dataset digest, scoring-function digests) is packaged
  as an evidence bundle. Acceptance: (a) a shield fails *closed* on error at both seams
  (break-first — one downstream project chose fail-open; we invert the default), (b) an eval
  task's evidence bundle verifies standalone via the offline verifier, (c) shield logic
  in-process, remote calls across a declared trust boundary. $0: stdlib-only.

### 5. Cerbos CheckResources contract + NDJSON decision records (ADAPT)

- **Mechanism.** The request/response contract —
  `{requestId, actions[], resource: {kind, instances: {id: {attr}}}, principal: {id, roles[], attr},
  auxData}` → per-instance, per-action `EFFECT_ALLOW`/`EFFECT_DENY` with matched-policy metadata
  and a stable `requestId`. **Derived roles** computed at request time from CEL (e.g. `owner` when
  `resource.attr.owner == principal.id`) — delegation-shaped roles without a separate identity
  system. Fail-closed by construction: no match → deny; duplicate `(resource kind, version)` is a
  **compile error**, never a silent override. NDJSON decision records (requestId, principal,
  resource, action, effect, matched policy) chain directly into an HMAC audit log.
- **Gap.** A cleaner decision-packet interface than our bespoke forms (the matched-policy metadata
  is the provenance evidence bundles want), and a canonical decision-record schema the HMAC audit
  chain consumes. Derived roles port the delegation primitive into our policy layer.
- **Lane shape.** `cerbos-contract-port` — tdd implement-lane: stdlib CheckResources contract
  (dataclasses), CEL-subset conditions, derived-role resolution, compile-time duplicate-kind
  detection, NDJSON decision-record emitter into the HMAC chain. Red-first battery: shadow-policy
  acceptance, missing-policy default-deny, log-tampering (drop/modify a record → chain
  verification fails). Success: our engine passes the same adversarial battery we'd run against
  the real binary, zero Go in the tree. Explicit non-goal: full CEL compat.

---

## Honorable mentions

- **smolagents soft-sandbox ladder** (ADAPT patterns; DROP as dependency): import-allowlist +
  `pkg.*` submodule wildcards as a soft pre-jail layer, op-cap + timeout as pre-jail resource
  bounds, the executor graduation ladder (local-soft → Docker → microVM) validating our jail
  direction — but the maintainers explicitly disclaim the local executor as a security boundary,
  so it's seasoning, never containment.
- **OpenFGA Expand trees** (part of steal #1): decision provenance as evidence-bundle material.
- **Cerbos compile-error-on-shadow** (part of #5): duplicate policy kinds fail at compile, not
  at incident-review time.
- **Promptfoo compliance presets** (`owasp:agentic`, MITRE ATLAS mapping) and
  `redteam discover` (probe the app's surface before generating attacks).
- **HumanLayer stakes taxonomy + `human_as_tool`** (part of #3): risk driver for approval
  requirements; approval-shaped flow generalized to consultation.
- **Llama-stack inline/remote trust split** (part of #4): the explicit declaration of which side
  of the boundary code and credentials live on.

## Dropped

- **smolagents as a dependency** (ADAPT patterns, DROP dep): no security boundary, no per-tool
  approval primitive, framework churn is a supply-chain cost we don't need.
- **The Cerbos and OpenFGA binaries in-tree**: both Go sidecars; a network PDP hop inverts
  fail-closed on PDP-down. Port contracts and patterns into stdlib; run the real binaries only
  as break-first oracles in the lab.

## License traps (bytes verified 2026-10-01)

1. **openfga/openfga** (Apache-2.0): GitHub's license-detection API may report the repo as
   `NOASSERTION` — future lanes must read in-repo LICENSE bytes, never the API field.
2. **cerbos/cerbos** (Apache-2.0): anonymous telemetry unless `CERBOS_NO_TELEMETRY=1`; Cerbos Hub
   (audit streaming, policy CI) is the commercial carve-out — designs must not depend on it.
3. **smolagents** (Apache-2.0, cleanest): the trap is technical — the non-security-boundary
   disclaimer must be repeated verbatim in any future lane's docs.
4. **promptfoo/promptfoo** (MIT): now part of OpenAI; Enterprise tier is commercial. Steal core
   patterns only; keep runs local (`PROMPTFOO_DISABLE_SHARING=true`,
   `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`).
5. **humanlayer/humanlayer** (Apache-2.0, short header): monorepo **deprecated**; SDKs removed
   (PR #646). The humanlayer.com rebuild is proprietary — steal from the legacy repo only.
6. **ogx-ai/ogx** (MIT): repo moved twice (`meta-llama/llama-stack` →
   `llamastack/llama-stack` → `ogx-ai/ogx`) — pin the OGX path. Llama *weights* stay under the
   Meta Community License; the MIT covers the stack code only.

## Upstream deltas since last look

- **llama-stack is now ogx-ai/ogx** ("model-agnostic, multi-SDK, production-grade") — any prior
  reference to `meta-llama/llama-stack` is stale; the old path redirects twice.
- **HumanLayer monorepo deprecated** — README says the code is "pretty much all deprecated";
  SDKs removed; living reference is the historical SDK shape plus the MIT `humanlayer/skills`
  and `humanlayer/fold` repos.
- **Promptfoo is now part of OpenAI** — OSS core remains MIT; Enterprise tier commercial. A
  third-party fixture's "Apache-2.0 / MIT" summary is sloppy; root LICENSE is MIT.

## Enforcement notes for future lanes

- No Go sidecars in-tree (OpenFGA, Cerbos): port contracts/patterns into stdlib Python;
  fail-closed on PDP-down is non-negotiable.
- Grant/decision records are per-request, ephemeral, and hash-chained at the seam — emit into
  the HMAC audit chain at decision time, never batched later.
- The smolagents soft layer is defense-in-depth seasoning, never the containment boundary —
  every bypass class in its red-first battery must name which rung actually contains it.
- Shield verdicts fail **closed** on error at both seams (invert the fail-open default seen in
  the wild); shield logic in-process, remote calls across a declared trust boundary.
- Human decisions join the same hash-chained audit log as engine decisions: who, what, when,
  decided — including denied, edited-args, and timeout terminal states.
- Evidence is the cross-cutting currency: pluginId/strategyId rows, Expand trees, decision
  records, eval-task digests — all packaged so an auditor verifies *without our engine*
  (offline-evidence-bundle direction landed 2026-09-27).
