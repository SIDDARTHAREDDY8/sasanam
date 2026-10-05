# Wave-338 Lane 6 — Framework governance-adapter watch (research scout E)

**Date:** 2026-10-05 | **Spend:** $0 | **Method:** primary sources only (repo code, official docs, PyPI metadata, GitHub API). All citations accessed 2026-10-05.

## 0. Tree-check: F426 shape confirmed as described

`gov/adapters/openai_agents.py` (agent-governance-demo-main):

- `make_tool_input_guardrail(binding, framework_tool, *, ..., name=None, expect_sdk_tool_name=None)` (line ~189) closes over `framework_tool`; `expect_sdk_tool_name` gives a **runtime-only**, **opt-in** misattachment check (`misconfigured_guardrail_attachment` tripwire) — it is *not* a declared attribute of the issued guardrail.
- `audit_agent_coverage(agent, ...)` (line ~341) certifies each FunctionTool carrying `any(_is_issued_guardrail(g) for g in guardrails)` — **presence only**. It never compares the guardrail's closure-captured `framework_tool` / `expect_sdk_tool_name` against the tool it is attached to. A guardrail issued for tool A attached to tool B passes the audit. **F426 stands exactly as filed.**

---

## 1. New OSS governance shims for our four frameworks since the 2026-10-05 pass

**Verdict: NONE.** No new third-party governance shims for CrewAI / AG2 / OpenAI Agents SDK / LangGraph were found. acp-governance remains at 0.2.0.

### 1a. Repos created in the last 7 days (GitHub API, query `agent governance guardrail created:>2026-09-28`, accessed 2026-10-05)

| Repo | Created | What it is | Verdict |
|---|---|---|---|
| `a5557/dsh-agent-guard` | 2026-10-03 | Guardrail plugin for **DSH** (a specific agent harness): evidence-first inspection, write governance, per-turn rollback points. MIT (`license: MIT` per GitHub API). Zero runtime deps, no network. | **SKIP** — not a shim for any of our four frameworks; DSH-specific plugin architecture (`dsh plugin add`, `dsh.bundle.patch`). |
| `vibhanshu-agarwal/on-prem-ai-agent-governance` | 2026-09-30 | On-prem governance + cost control: LiteLLM gateway + budget guard. | **SKIP** — proxy/budget model, no framework tool-boundary shims. |
| `vrrgithub1/agent-guardrail-validation-engine` | 2026-09-30 | "Adversarial AI Agent Safety, Real-Time Guardrails, and Model Validation Engine" — demo repo. | **SKIP** — no fail-closed engine, no framework adapters found in tree skim. |
| `AadyaAgarwal01/agentic-governance-guardrail` | 2026-09-29 | No description; experiment repo. | **SKIP** |
| `favioCesarJuan/STNG-framework` | 2026-09-29 | "Hierarchical Multi-Agent Governance Engine inspired by Star Trek: TNG. Deterministic…" — experiment repo. | **SKIP** |

- https://api.github.com/repos/a5557/dsh-agent-guard (accessed 2026-10-05)
- https://github.com/a5557/dsh-agent-guard/blob/main/README.md (accessed 2026-10-05)

### 1b. PyPI governance-adjacent packages — current versions and license status

| Package | Version | License (PyPI metadata) | What it is | Verdict |
|---|---|---|---|---|
| `acp-governance` | 0.2.0 | MIT | Scope-narrowed subagent SDKs; spend-proxy + decorator model for CrewAI/LangChain/Anthropic-Node. No fail-closed engine, no offline evidence. | **SKIP** (unchanged since pass) |
| `agent-guardian` | 1.0.0rc41 | Apache-2.0 | **Red-teaming** toolkit (scan/adversarial probes incl. a CrewAI `CrewAIAdapter` for kickoff-loop scans). | **SKIP** — scan-time, not a runtime fail-closed shim. Its CrewAI adapter only feeds adversarial prompts through `Crew.kickoff_async`. |
| `ai-safety-guardrails` | 1.0.0 | MIT | Generic LLM safety: `ToolPolicyGuard(policies={...}, max_tool_calls_per_session=...)`, `LLMToolFilter` with `high_risk_fail_closed` list. | **SKIP** — LLM-judge-based, no fail-closed mediation engine, no offline evidence. |
| `asqav` | 0.10.10 | **Proprietary** (`License :: Other/Proprietary License` classifier, no license text) | Post-quantum (ML-DSA-65) signed audit trails; supports LangChain, CrewAI, OpenAI Agents, Haystack, LiteLLM. | **SKIP for stealing** (proprietary). **WATCH** — signed-receipt evidence direction overlaps our evidence bundle work; no adapter to reuse. |
| `agentshield` | 0.1.2 | MIT | Offline Rust SAST scanner + MCP runtime reverse proxy (secret redaction). Normalizes CrewAI/LangChain/LangGraph/AutoGen into one IR for *scanning*. | **SKIP** — static scanning + MCP proxy; no framework-native fail-closed tool shim. |
| `guardrails-ai` | 0.11.0 | Apache-2.0 | Output validation / structural guarantees for LLM responses. | **SKIP** (different focus, known) |

- https://pypi.org/pypi/acp-governance/json, https://pypi.org/pypi/asqav/json, https://pypi.org/pypi/agent-guardian/json, https://pypi.org/pypi/ai-safety-guardrails/json, https://pypi.org/pypi/agentshield/json (all accessed 2026-10-05)
- https://github.com/rolflobo/agent-guardian/blob/HEAD/docs/try/scan-crewai.mdx (accessed 2026-10-05)
- https://github.com/ai-safe-earth/ai-safety-guardrails (accessed 2026-10-05)

**Bottom line for §1:** The four-framework fail-closed adapter niche remains ours alone. No steals; nothing to adapt. `asqav` (signed receipts) is the only WATCH candidate, and only for evidence-format ideas — and it is proprietary, so ideas only, no code.

---

## 2. Does anyone address the guardrail↔tool misattachment class (F426)?

**Verdict: NO — not in agent governance, and not in the adjacent domains surveyed. The closest existing patterns are post-hoc static audits (absence detection) and certificate-style scope binding in unrelated PKI domains. The F426 close-when (issued guardrail exposes `framework_tool` + declared name; audit raises on missing/mismatched name) appears novel for agent tool-guardrail binding.**

### 2a. OpenAI Agents SDK guardrail docs themselves — NO

The official docs (https://openai.github.io/openai-agents-python/guardrails/, accessed 2026-10-05) define the binding model:

- "Tool guardrails wrap **`FunctionTool` instances** … They are configured on the tool itself … You can attach them directly to a custom tool created with `tool` or `function_tool`." via the `tool_input_guardrails` list parameter.
- The guardrail function receives `data` and returns `ToolGuardrailFunctionOutput` (`.allow()` / `.reject_content()` / `.raise_exception()`).
- **No declared target tool name exists on a guardrail.** A guardrail is an anonymous function in a list; the SDK performs no issuance-time or audit-time check that a guardrail was authored for the tool it is attached to. Misattachment is silently legal.

The SDK does run input tool guardrails after approval and immediately before execution (`RunConfig.tool_execution` → `ToolExecutionConfig(pre_approval_tool_input_guardrails=True)`), and explicitly documents the coverage gaps our shim's audit already encodes (handoffs bypass, hosted/built-in tools bypass the pipeline, `Agent.as_tool()` has no guardrail options). No miswiring detection anywhere in the page.

- https://openai.github.io/openai-agents-python/guardrails/ (accessed 2026-10-05)

### 2b. Kubernetes admission controllers — absence audits only, no binding

- ValidatingAdmissionPolicy + ValidatingAdmissionPolicyBinding: the binding references the policy **by name**; nothing verifies the policy was authored for the matched resource kinds. A policy written for Pods can be bound to Deployments and the API server accepts it.
- `istioctl analyze` performs static analysis that flags *misconfigurations* (e.g. AuthorizationPolicies whose `selector` matches no workload — an unselected policy), but it verifies **coverage/absence**, not policy↔target identity binding. A policy selecting the *wrong* (but existent) workload is not flagged as miswired.
- Gatekeeper / Policy Controller (GKE Enterprise) validate and audit policy *configurations* — again coverage and constraint-violation detection, not issuance binding.
- https://docs.cloud.google.com/service-mesh/v1.26/docs/security/authorization-policy-overview (accessed 2026-10-05)

### 2c. AWS WAF rule-binding — absence detection only

- Rule groups attach to web ACLs by ARN (`wafv2 associate-web-acl`). AWS Firewall Manager emits findings for **missing** associations ("Resource is missing Firewall Manager managed web ACL") and **misconfigured rule groups** (web ACL "missing the rule groups that the policy requires") — i.e. required-groups-absent, not wrong-group-attached.
- Security Hub controls WAF.7 / WAF.8 (`waf-global-rulegroup-not-empty`, `waf-global-webacl-not-empty`) check that rule groups and web ACLs are **non-empty** — emptiness, not misattachment.
- Community verification practice is also absence/coverage-based ("Web ACL created but never associated protects nothing" — `aws wafv2 get-web-acl-for-resource`).
- https://docs.aws.amazon.com/securityhub/latest/userguide/waf-controls.html (accessed 2026-10-05)
- https://repost.aws/knowledge-center/waf-web-acl-association-behavior (accessed 2026-10-05)

### 2d. AWS IAM policy attachment — content-scoped, no intended-target check

- Managed/inline policies attach to users, groups, roles by ARN reference. IAM Access Analyzer detects *unused* access and *external* access; there is **no** "policy was written for role A but attached to role B" detection — a policy's scope lives in its content (Resource/Action), not in a declared binding. A wrongly-attached policy is evaluated exactly as written.
- (Standing AWS IAM semantics; verified consistent with IAM Access Analyzer documented finding types. No counter-evidence found in this pass.)

### 2e. OPA / Styra — the binding gap is explicitly documented by third parties

- Styra DAS binds policy bundles to **systems by system ID**; OPA's decision logs record which bundle revision produced a decision. There is no check that a policy package was authored for the system it is deployed to.
- A third-party analysis states the gap plainly: *"The policy is not cryptographically bound"* to operations — OPA returns a decision as a data structure; a misconfigured enforcement point can skip or misapply it, and the evaluation is "structurally advisory." (https://qu3ry.net/articles/cryptographic-governance-open-policy-agent.pdf, accessed 2026-10-05)
- Styra's own docs cover fail-open mitigation (bundle pull failures, OPA/version incompatibility) — operational health, not policy↔target binding. (https://docs.styra.com/das/observability-and-audit/monitoring/fail-open-mitigation, accessed 2026-10-05)

### 2f. Adjacent positive patterns (ideas, not steals)

- **openshell** (`stars1233/openshell`, `architecture/security-policy.md`, accessed 2026-10-05): every policy evaluation re-derives credential bindings from scratch; a malformed binding (empty provider, missing host, port outside 1..=65535) **fails the evaluation** rather than contributing a scope. This is the fail-closed-binding-validation reflex — the closest adjacent-domain behavior to what the F426 close-when demands — but it validates binding *syntax*, not policy↔target *identity*.
- **Certificate/PKI pattern (TUF, Sigstore):** the issued artifact carries its scope/identity (TUF targets metadata binds hashes to roles; Sigstore certs bind identity to keys) and the verifier checks scope == request. This is the right *shape* for the F426 fix, but nobody applies it to agent tool-guardrail attachment.

### 2g. Conclusion for F426

Nobody in the agent-governance space or the adjacent policy-binding domains does "issued guardrail declares its intended tool + audit raises on mismatch." The industry standard is **presence/coverage auditing** (our `audit_agent_coverage` already does the strongest version of this among peers: handoffs, nested tools, hosted tools are all uncovered surfaces). The F426 close-when — adding `framework_tool` + declared-name attributes to the issued guardrail and raising on missing/mismatch in the audit — would be a **novel, steal-worthy-in-reverse** control for this domain. **ADAPT** the certificate-pattern framing (scope-carrying credential) when writing the closure spec, but there is no external code to reuse.

---

## 3. Framework API drift affecting our shims

Current PyPI versions (metadata accessed 2026-10-05): `crewai 1.15.23` (released 2026-09-28), `ag2 1.1.2` (2026-10-03), `openai-agents 0.23.1` (2026-10-02), `langgraph 1.2.12` (2026-09-21).

### 3a. CrewAI 1.15.23 — no tool-funnel changes. Verdict: no action.

Release notes (https://api.github.com/repos/crewAIInc/crewAI/releases/tags/1.15.23, accessed 2026-10-05): native Gemini 3.8 Flash support, `crewai eval` tracing UX, LLM retry/whitespace fixes, Selenium/S3/SQLite cleanups. Nothing touches `BaseTool` / tool execution. Our `crewai_tools.py` BaseTool wrapper is unaffected.

### 3b. AG2 v1.1.2 — invocation-scoped plugins (PR #3335, merged 2026-10-02). Verdict: WATCH, no bypass found, audit surface changed.

Release notes (https://github.com/ag2ai/ag2/releases/tag/v1.1.2 → PR https://github.com/ag2ai/ag2/pull/3335, accessed 2026-10-05): adds `plugins=` to `Agent.ask`, `run`, `resume`, `AgentReply.ask/run`. Invocation plugins contribute **prompts, tools, middleware, observers, HITL** for one call. Key semantics from the PR body:

- "Later plugins override earlier defaults and **same-named tools**; explicit call tools override plugin tools."
- "plugin policies preserve existing middleware order."
- HITL precedence: explicit call hook → agent hook → first invocation plugin hook.

Impact on our `ag2_hooks.py` middleware shim (`GovernedToolMiddleware.on_tool_execution`):

1. **No bypass by shadowing:** agent-level middleware still runs and order is preserved, so `on_tool_execution` still mediates tool-execution events. A same-named plugin tool is still gated **by name** through `binding.call(framework_tool)`; a *new* tool name introduced per-invocation hits `UnregisteredToolError` → our shim fails closed (denied/queued/unregistered all map to refusal per the module docstring). Fail-closed posture survives.
2. **Audit surface changed:** per-invocation tools cannot be pre-registered at agent construction. An operator who passes `plugins=[SkillPlugin(...)]` with tools our binding doesn't know gets a loud fail-closed denial — safe, but operationally a new trip hazard worth documenting in the adapter README.
3. **Recommended closure-lane follow-up (not this lane):** add a battery probe — invocation-scoped plugin contributing (a) a new tool name → expect `UnregisteredToolError` fail-closed; (b) a same-named tool with different behavior → expect governance still mediated by binding name. This is a test gap, not a product gap.

### 3c. openai-agents 0.23.1 (2026-10-02) — no guardrail/tool pipeline changes. Verdict: no action.

Release notes (https://github.com/openai/openai-agents-python/releases/tag/v0.23.1 and v0.23.0, accessed 2026-10-05): 0.23.0 adds MCP listing page limits, Docker sandbox removal protection, memory-consolidation config, encrypted history scan budget; 0.23.1 is release-automation + test fixtures only. Nothing touches `tool_input_guardrails`, `FunctionTool`, or the guardrail pipeline. Our shim's docstring already states `_is_function_tool` was "Verified against openai-agents 0.23.1" — the installed-version duck-typing (`hasattr(tool, "tool_input_guardrails")`) remains valid.

### 3d. langgraph 1.2.12 (2026-09-21) — additive interrupt change. Verdict: no action.

Release notes (https://api.github.com/repos/langchain-ai/langgraph/releases/tags/1.2.12, accessed 2026-10-05): `feat(langgraph): add response_schema to interrupt() (#8886)` — an **optional** kwarg on `interrupt()`. Our `langgraph_hitl.py` interrupt→ApprovalQueue recipe passes through `interrupt()`; an optional additive parameter does not break the recipe and could later be ADAPTed for typed approval payloads. No drift.

---

## 4. Verdict table

| Item | Verdict | Notes |
|---|---|---|
| New OSS shims (CrewAI/AG2/OpenAI Agents/LangGraph) since 2026-10-05 pass | **SKIP** (none exist) | Niche remains ours alone |
| `a5557/dsh-agent-guard` (2026-10-03, MIT) | **SKIP** | DSH-specific plugin, not a framework shim. License read (MIT) — nothing to steal anyway |
| `agent-guardian` 1.0.0rc41 (Apache-2.0) | **SKIP** | Red-team scanning, not runtime enforcement |
| `ai-safety-guardrails` 1.0.0 (MIT) | **SKIP** | LLM-judge safety, no fail-closed engine |
| `asqav` 0.10.10 (**proprietary**) | **WATCH** (ideas only, no code) | ML-DSA-65 signed receipts; evidence-format direction only |
| `agentshield` 0.1.2 (MIT) | **SKIP** | SAST + MCP proxy, no framework-native shim |
| acp-governance 0.2.0 | **SKIP** (unchanged) | Spend-proxy + decorator model, no fail-closed engine |
| F426 misattachment class — anyone address it? | **NO** | SDK, K8s, WAF, IAM, OPA/Styra: presence/coverage audits only. Our close-when is novel for this domain — **ADAPT** the certificate-pattern framing, no code to reuse |
| CrewAI 1.15.23 drift | none | No action |
| AG2 v1.1.2 invocation-scoped plugins | **WATCH** | Fail-closed survives; add battery probes for per-invocation plugin tools (closure-lane follow-up) |
| openai-agents 0.23.1 drift | none | Shim already verified against 0.23.1; no action |
| langgraph 1.2.12 drift | none | Additive `response_schema` on `interrupt()`; no action |

**F426 stands as filed.** The tree-check confirms `audit_agent_coverage` certifies on guardrail *presence* alone; `expect_sdk_tool_name` is runtime-only and opt-in. No external project implements the close-when.
