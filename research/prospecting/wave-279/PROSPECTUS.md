# Wave-279 Prospectus — full teardown of 6 new targets

**Lane:** standing prospecting (research only — no clones, no product code, no findings).
**Worktree:** `~/workspace/teams/wave279-prospect/`
**Method:** two child researchers (A: OpenFGA / Cerbos / smolagents; B: promptfoo / HumanLayer /
llama-stack→ogx) + parent synthesis. All 6 targets verified NEW vs waves 273–279 prospectuses
(grep over PROSPECTUS.md files — zero hits).
**Freshness:** all licenses from LICENSE bytes fetched 2026-10-01.
**Status:** complete. REPORT AND STOP.

---

## 1. openfga/openfga — relationship-based authorization (ReBAC, Zanzibar-style)

**What it is.** Go authorization engine (HTTP/gRPC + SDKs incl. Python). Auth0 FGA in production
since Dec 2021; adopters Grafana Labs, Canonical, Docker. Backends: PostgreSQL/MySQL/SQLite/memory.

**Mechanisms that matter.**
- Tuple model: `user:anne, relation: viewer, object: document:budget`; usersets as `user` → the
  primitive for delegation chains. Model DSL (`schema 1.1`) composes relations with
  union/intersection/difference and the `from` tupleset-rewrite operator.
- **Contextual tuples**: tuples supplied on the check request, existing only for that query's
  duration — per-invocation ephemeral grants without persisting standing grants (the concrete
  answer to "single-use lease" semantics).
- **Conditions**: CEL expressions on tuples/checks (time-, value-, attribute-bounded grants:
  `grant_valid_until`, `max_budget_usd`, `allowed_arg_hash`) without new model versions.
- Query surface: `Check`, `BatchCheck` (bulk pre-authz of N planned tool calls), `ListObjects`
  ("which tools can this agent touch?" — the grant-listing answer), `Expand` (returns the full
  userset resolution tree — decision provenance, half of an evidence bundle already).
- Performance: graph traversal over indexed tuples + cached models; no policy eval per request.

**License.** Apache-2.0 from LICENSE bytes (© 2022 Okta, Inc.).
**Trap:** GitHub's license API may report this repo as `NOASSERTION` — trust in-repo LICENSE
bytes, never the API field. No dual-licensing, no enterprise carve-out, no CLA.

**Verdict: STEAL (pattern).**
1. Contextual tuples on the CheckRequest → `agent:<id>` as user, `tool:<name>` as object,
   relation per scope (`can_invoke`, `can_invoke_readonly`); executor passes single-use grants
   inline, writes no standing grant.
2. CEL condition context for attenuation — expiry, budget caps, arg digests as tuple conditions.
3. BatchCheck for bulk pre-authorization; Expand for decision explainability in evidence bundles.
4. `from`-traversal for delegation chains: `can_invoke: invoker from delegated_session`.

**Gap closed.** Agent identity (grant graph keyed on stable agent identity), policy engine
(declarative versioned ReBAC + `.fga.yaml` model test files break-testable red-first), evidence
bundles (Expand trees + conditional tuple writes are auditor-verifiable artifacts). Does NOT close
approval queues — OpenFGA decides, never pauses for humans.

**Lane shape.** `fga-tuples-prototype` — spec-first (to-spec, no product code): type system
(agent/tool/session/resource), relation set, condition set (expiry/budget/arg-digest),
contextual-tuples-per-invocation flow. Success criterion: red-first battery of adversarial
delegation scenarios (escalation, expired-grant replay, contextual-tuple omission) behaving
correctly in the OpenFGA playground/Docker image *before* any stdlib re-implementation is
proposed. Deliverable: model + battery + port-vs-sidecar verdict (recommended: port semantics
into stdlib; NOT recommended: ship Go sidecar — a network PDP hop makes fail-open the default
failure mode).

---

## 2. cerbos/cerbos — policy enforcement point for apps

**What it is.** Open-core Go PDP (CNCF sandbox). Policies are YAML (`apiVersion: api.cerbos.dev/v1`)
distributed via disk/Git/Hub bundles; `cerbos compile` lints/tests offline. Core engine Apache-2.0;
commercial layer is Cerbos Hub.

**Mechanisms that matter.**
- CheckResources contract: `{requestId, actions[], resource: {kind, instances: {id: {attr}}},
  principal: {id, roles[], attr}, auxData}` → per-instance, per-action `EFFECT_ALLOW`/`EFFECT_DENY`
  with matched-policy metadata; stable `requestId` ties request→decision.
- **Derived roles**: roles computed at request time from `parentRoles` + CEL (e.g. `owner` when
  `resource.attr.owner == principal.id`), imported into resource policies — delegation-shaped
  roles without a separate identity system.
- Fail-closed: no match → `EFFECT_DENY`; same `(resource kind, version)` twice is a **compile
  error**, not a silent override (no shadow semantics).
- Audit block: decision logs (`log.kind=="decision"`, `log.logger=="cerbos.audit"`) as
  NDJSON — requestId, principal, resource, action, effect, matched policy — directly chainable
  into an HMAC audit log. Backends `local`/`file`/`hub`. Note: audit is **opt-in** (disabled by
  default); `excludeMetadataKeys: ['authorization']` exists to keep secrets out of logs.

**License.** Apache-2.0 from LICENSE bytes (verified live on main).
**Traps:** (1) open-core — Hub (managed audit streaming, policy CI) is commercial; designs must
not depend on it. (2) anonymous telemetry collected by default — evaluate with
`CERBOS_NO_TELEMETRY=1`.

**Verdict: ADAPT.**
1. The CheckResources request/response contract → a cleaner stdlib decision-packet interface
   (principal/resource+attrs/actions → per-action effect + matched policy + requestId); matched-policy
   metadata is the provenance evidence bundles want.
2. The decision-log NDJSON record schema → canonical record the HMAC audit chain consumes
   (copy the schema, not the logger).
3. Derived roles as a delegation primitive — port the pattern into our policy layer.
DROP the PDP binary: per-request attribute enrichment is our job anyway (the PIP gap), and a
sidecar binary adds a fail-open seam on PDP-down.

**Gap closed.** Policy engine (YAML+CEL, compile-checked, human-reviewable — the direction our own
DSL is converging on) and audit-log evidence input (decision records as first-class evidence).
Partially approval queues: no pause-for-human semantics, but `requestId` + per-instance effects
make queue approval/denial records uniform. Does NOT close agent identity (PDP trusts caller-supplied
principal).

**Lane shape.** `cerbos-contract-port` — tdd implement-lane: stdlib CheckResources contract
(request/response dataclasses), CEL-subset conditions (or restricted predicate language), derived-role
resolution, compile-time duplicate-kind detection, NDJSON decision-record emitter into the HMAC chain.
Red-first battery: shadow-policy acceptance, missing-policy default-deny, log-tampering
(drop/modify a record → chain verification fails). Success: our engine passes the same adversarial
battery we'd run against the real binary, zero Go in the tree. Explicit non-goal: full CEL compat.

---

## 3. huggingface/smolagents — code-agent framework

**What it is.** HF's minimal agent library (~1k LOC core). `CodeAgent` (LLM writes Python as actions),
`ToolCallingAgent`, `Tool` class/`@tool` decorator, MCP tool consumption, `managed_agents`,
step callbacks, in-process memory.

**Mechanisms that matter.**
- `LocalPythonExecutor`: AST interpreter with import allowlist (`additional_authorized_imports`;
  small safe defaults), **submodule access control** (forbidden by default; `numpy.*`-style
  wildcards), **op-count cap** (infinite loops die), **per-execution timeout**. Undefined ops raise.
- **Honest non-boundary:** the README states the local executor "is **not a security sandbox** …
  can be bypassed and must not be used as a security boundary" (huntr-graded, docstring-clarified).
- Real isolation is remote: `executor_type="e2b" | "modal" | "blaxel" | "docker"` (+ WASM
  Pyodide+Deno). Docker guidance: `security_opt=["no-new-privileges"]`, `cap_drop=["ALL"]`,
  `mem_limit`, `pids_limit`, run as `nobody` — independently validates our jail direction.
- Tool authorization: allowlist at construction; but an over-broad `additional_authorized_imports`
  (e.g. `requests`) is itself a capability grant ("do not add any unsafe imports!").
- **No per-tool-call approval gate.** HITL is plan-level only: `agent.interrupt()` mid-run, edit
  plan, `run(reset=False)`; step callbacks; final-answer validation.

**License.** Apache-2.0 from LICENSE bytes (verified live on main). Cleanest of the three.
**Trap:** *technical*, not legal — the non-boundary disclaimer must be repeated verbatim in any
future lane's docs.

**Verdict: ADAPT (patterns); DROP as a dependency.**
1. Import-allowlist + submodule-wildcard shape as the *soft* in-process pre-jail layer
   (fast reject before heavyweight containment); the graduation ladder local→Docker→VM.
2. Op-cap + timeout as standard pre-jail resource bounds (adopt their "mitigation, not boundary"
   framing in our docs).
3. `@tool` descriptor shape (name/description/typed inputs-outputs) as the tool-manifest contract
   feeding approval queues — the manifest is what a human approves.
DROP the library: no security boundary, no per-call approval primitive, framework churn is a
supply-chain cost.

**Gap closed.** Sandboxing (soft layer + the remote-executor ladder validating our jail direction)
and tool grant shapes (manifests for approval queues). Does NOT close approval queues.

**Lane shape.** `soft-sandbox-ladder` — spec-then-build: to-spec the three-rung executor interface
(soft AST allowlist for trusted-model dev use, Docker jail default, microVM for untrusted code)
with each rung's explicit security contract; then tdd stdlib soft rung (allowlist, submodule
wildcards, op cap, timeout) with a red-first battery (attribute-access submodule smuggling,
`__import__`/`importlib` re-entry, op-count evasion) where every bypass must fail at the soft layer
or be documented as out-of-scope-and-contained-by-the-jail. Success: zero ambiguity between
soft-layer rejections and jail containment in the docs — no "safer" language readable as "safe".

---

## 4. promptfoo/promptfoo — LLM red-teaming / eval harness

**What it is.** TypeScript CLI + library for evaluating and red-teaming LLM apps/agents/RAGs.
Declarative YAML, CI/CD integration, used by OpenAI and Anthropic. ~25k stars.

**Mechanisms that matter.**
- **Plugin × strategy × grader taxonomy**: plugins = *what* to attack (`harmful:hate`,
  `pii:direct`, `prompt-injection`, `jailbreak`, `excessive-agency`, `rbac`, …); strategies =
  *how* to deliver it (`basic`, `jailbreak:hydra`, `crescendo`, `goat`, `best-of-n`,
  `multilingual`, `leetspeak`/`base64`/`rot13`, `composite`, `retry`); graders = *how to score*
  (deterministic assertions + `llm-rubric` judge + cosine `similar`).
- Declarative `redteam:` config: plugin registry with per-plugin `{id, numTests, config}`
  overrides, strategy list, `purpose`-driven generation, `injectVar`, compliance presets
  (`owasp:llm`, `owasp:agentic`, MITRE ATLAS mapping), `redteam discover` (probe the app's
  surface before generating attacks).
- **Generation separated from evaluation**: `redteam generate` (expensive, nondeterministic)
  emits a committed YAML suite; `redteam eval` replays deterministically; `redteam run` =
  generate + eval; `retry` replays past failures as regression seeds. The suite is a pinned,
  reviewable artifact (like a lockfile).
- Evidence rows: `-o results.json` carries `response.output`, `gradingResult`,
  `metadata.pluginId`, `metadata.strategyId`, `results.stats` (successes/failures/errors/tokenUsage);
  `redteam report` renders severity × remediation HTML; code-scan emits `-f sarif`.

**License.** MIT from LICENSE bytes (standard MIT grant).
**Traps:** now part of OpenAI — OSS core stays MIT, Enterprise tier is commercial. Steal core
patterns only; keep runs local (`PROMPTFOO_DISABLE_SHARING=true`,
`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`).

**Verdict: STEAL.**
Steal the three-way taxonomy + declarative `redteam:` schema (plugin `id` registry, per-plugin
overrides, purpose-driven generation, compliance presets) and the `generate → commit → eval`
phase split with `retry`-style replay as regression-seed mechanism. stdlib-friendly: YAML schema
+ JSON rows, nothing TypeScript-specific.

**Gap closed.** Our batteries are hand-rolled per wave with bespoke probes and ad-hoc reporting —
the missing **adversarial battery language**: one shared attack vocabulary across waves, the
generate/eval replay split (a wave-279 suite still replays at wave-300), and machine-readable
evidence rows (pluginId/strategyId/gradingResult) that feed directly into evidence bundles —
*"sell evidence, not the engine."*

**Lane shape.** `battery-schema` lane: define a `battery:` config schema mirroring `redteam:`;
split break batteries into `generate` (AI-assisted probe synthesis, committed) and `eval`
(deterministic replay); emit JSON rows with `metadata.{pluginId,strategyId}` + stats; ship a
`report` renderer (severity × remediation). First acceptance: re-express one existing wave battery
in the schema and show eval-only replay is byte-identical across two runs with no model calls.
$0: stdlib-only, YAML + JSONL.

---

## 5. humanlayer/humanlayer — human-in-the-loop for AI agents

**What it is.** YC F24 "Human-in-the-Loop API for AI systems": SDK decorators forcing high-stakes
function calls through human approval over Slack/email/SMS/dashboard. ~11.6k stars.

**Mechanisms that matter.**
- **Declaration site:** `@hl.require_approval(channel="slack")` on the function itself —
  approval is baked into the tool, so the LLM cannot route around it (deterministic guarantee,
  not a prompt plea).
- Request fields: function name + args/kwargs → backend → human sees plain-language ask, exact
  args, risk tier, time remaining. Channels: Slack, email, Discord, dashboard; SMS/Teams announced.
- Semantics: approved → executes; denied → refusal value returned to the agent (agent continues);
  human may **edit the request**; timeout expires server-side (pending expires; SDK blocks).
- **Auditability:** complete audit trail of approvals (who, what, when, decision).
- Second primitive: `human_as_tool` — generic "ask a human a question" tool (approval-shaped
  flow generalized to free-text consultation).
- **Stakes taxonomy:** low = read-only public data / notify author; medium = read private data /
  communicate under strict templates; high = communicate on behalf of the human/company, write
  access to private data — the taxonomy deciding which functions get the decorator.

**License.** Apache-2.0 from LICENSE bytes (short Apache header form, grant unambiguous).
**Traps:** the monorepo is **deprecated** (README says so; SDKs removed in PR #646) — steal from
the legacy repo only; the humanlayer.com rebuild is proprietary (closed signed DMGs). Don't
confuse with unrelated `humanlayerlabs/*` crypto org.

**Verdict: ADAPT.**
1. The **outer-loop framing** — approval is agent-initiated (agent asks, waits on a pending
   record), not human-initiated polling; our queues should treat pending approvals as first-class
   records the agent waits on.
2. The **decorator-at-the-function-layer pattern** — the gate lives in tool dispatch, prompt-
   injection-proof, not in a system prompt.
3. The **4-tier function-stakes taxonomy** as the risk driver for which tools need approval, plus
   a `human_as_tool`-style generic consultation primitive.

**Gap closed.** Wave-278 built the queue; humanlayer closes the **UX/contract half**: multi-channel
delivery, approve/deny/edit/timeout semantics with durable pending state, and an audit-trail
contract for human decisions — so the chain covers human-in-the-loop governance end to end
(our log records what the engine did; this records what the human decided).

**Lane shape.** `approval-request-record` lane: an `ApprovalRequest` record (id, tool name,
args digest + full args, requester identity, stakes tier, channel, expiry, decision
{approved, denied, edited-args, timeout}) persisted *before* dispatch; timeout default
fail-closed; edit-args as a first-class decision (human rewrites the dangerous arg; agent
proceeds with edited call); every terminal decision appended to the hash-chained audit log.
Acceptance (break-first): (a) denied call never executes under prompt-injected re-request,
(b) timeout expires fail-closed, (c) edited args re-validated before dispatch, (d) audit chain
covers all four terminal states. $0: stdlib-only; channels as notification adapters.

---

## 6. meta-llama/llama-stack → ogx-ai/ogx — Meta's agent stack

**What it is.** Meta's standardized agent-stack server (inference, safety, memory, agents, evals,
telemetry as one REST surface). Now **ogx-ai/ogx** ("model-agnostic, multi-SDK, production-grade").

**Mechanisms that matter.**
- **Shield registry:** `shields register --shield-id --params`; attach per agent as
  `input_shields`/`output_shields` wrapping both the inbound turn and outbound response inside
  the agent loop. The loop emits `shield_call` step events with a `violation` field — shield
  verdicts as observable telemetry. Standalone `run_shields` API outside the loop. Providers:
  llama-guard, prompt-guard, code-scanner.
- **Eval framework:** eval tasks = dataset + scoring functions, both registered resources;
  built-ins MMLU, SimpleQA, RAG metrics; scores as registered artifacts (eval-task × dataset ×
  scoring functions) with JSON/HTML reports via the Files API — the "benchmark as evidence" pattern.
- **Provider trust split:** `inline::` providers run in-process (dev), `remote::` providers call
  external services (URL + api_token in `run.yaml`). Server auth: Bearer/JWT via OAuth2/JWKS.
- Tool execution: agent runtime invokes tools server-side (`POST /v1/tool-runtime/invoke`;
  toolgroups incl. MCP servers); shields run **in-process at the agent-runtime layer** while tool
  calls fan out — the guard layer sits *inside* the trust boundary, tools outside it.

**License.** MIT from LICENSE bytes (fetched from ogx-ai/ogx main).
**Traps:** (1) org path moved twice — pin `ogx-ai/ogx`, not the old Meta path. (2) Stack code
is MIT but Llama *weights* are under the **Meta Community License** — don't bundle weights
assuming MIT coverage. (3) `meta-reference` provider branding is residue, not a license issue.

**Verdict: ADAPT.**
1. The **shield registry** — named, parameterized shields attached per-agent at two seams, verdicts
   as loop events — the cleanest existing shape for "guards that attach to inference *and* tool calls."
2. The **eval-task-as-evidence** triple (eval-task-id × dataset-id × scoring-functions) as the
   unit of benchmark evidence — directly informs our evidence-bundle schema.
3. The **inline-vs-remote provider split** as an explicit trust boundary: guards in-process,
   tools/credentials across the boundary.

**Gap closed.** (i) Our policy engine decides, but we lack a standardized attach surface for
guards at both the inference turn and the tool-invocation — `input_shields`/`output_shields`
is that surface. (ii) Our batteries emit ad-hoc scores; the eval framework makes a benchmark
run a **registered, reproducible evidence artifact** (dataset + scoring functions pinned) — the
currency evidence bundles need.

**Lane shape.** `shield-registry` lane: a `Shield` registry (named shields, JSON params) attached
per policy-binding at inbound (request/prompt) and outbound (response/tool-call args) seams, each
emitting a chained audit event with the verdict; plus an `EvalTask` record binding a dataset id
to scoring-function ids, runnable headless, output (score, dataset digest, scoring-function
digests) packaged as an evidence bundle. Acceptance: (a) a shield fails *closed* on error at both
seams (break-first vs the fail-open default seen in the wild — one downstream project chose
fail-open), (b) an eval task's evidence bundle verifies standalone via the offline verifier,
(c) shield logic in-process, remote calls across a declared trust boundary. $0: stdlib-only.

---

## Verdict table

| Target | License (bytes) | Trap | Verdict | Mechanism to steal | Gap closed |
|---|---|---|---|---|---|
| openfga/openfga | Apache-2.0 (© 2022 Okta) | GitHub API may say NOASSERTION — read bytes | STEAL (pattern) | Contextual tuples per-request; CEL conditions; BatchCheck; Expand trees | Agent identity, policy engine, evidence provenance |
| cerbos/cerbos | Apache-2.0 | Open-core: Hub commercial; telemetry opt-out `CERBOS_NO_TELEMETRY=1` | ADAPT | CheckResources contract; NDJSON decision records; derived roles | Policy engine interface, audit-log evidence input |
| huggingface/smolagents | Apache-2.0 | None legal — technical: local executor NOT a security boundary | ADAPT patterns; DROP dep | Import allowlist + `pkg.*` wildcards; op-cap/timeout; `@tool` manifests; graduation ladder | Sandboxing soft layer, tool grant shapes |
| promptfoo/promptfoo | MIT | Now part of OpenAI; Enterprise tier commercial | STEAL | Plugin×strategy×grader taxonomy; `redteam:` schema; generate→commit→eval | Adversarial battery language, evidence rows |
| humanlayer/humanlayer | Apache-2.0 (short header) | Repo deprecated; humanlayer.com rebuild proprietary | ADAPT | Approval-request contract; decorator-at-function; stakes taxonomy; edit-args | Approval UX/contract, human-decision audit trail |
| meta-llama/llama-stack → ogx-ai/ogx | MIT | Repo moved twice (pin ogx-ai/ogx); weights ≠ MIT | ADAPT | Shield registry; eval-task-as-evidence; inline/remote trust split | Guard attach surface, benchmark-as-evidence |

## Cross-cutting note

All six targets converge on the same architecture our governance layer is building:
**declare the attack/approval/guard as data, run it through a registry, emit the verdict as
evidence.** OpenFGA declares grants as tuples; Cerbos declares policies as YAML; smolagents
declares tool manifests; promptfoo declares adversarial tests; humanlayer declares approvals;
llama-stack declares shields and eval tasks. The steal is the *registry + declared-attachment +
evidence* pattern, never the implementation.
