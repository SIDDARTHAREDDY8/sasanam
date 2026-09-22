# Competitive Deep Dive: Microsoft Agent Governance Toolkit + AWS Bedrock AgentCore
**Workstream:** market | **Role:** Competitive Strategy Researcher | **Date:** 2026-09-21
**Method:** web search + page fetches only. $0 spend, no signups, no paid reports, no vendor contact. Every factual claim carries a verbatim URL from tool output (see SOURCES). Claims marked **[verified]** come from the vendor's own repo/docs or AWS pages; **[inferred]** are reasoned from evidence; **[unverified]** could not be confirmed.

Prior market research: `research/market-research.md` (+ `market-research-sources.md`). This document pressure-tests the two claimed wedges (approval queue + web UX; adversarial eval battery) and issues BUILD/STOP/CHANGE verdicts per roadmap area.

> **CORRECTION — 2026-09-22 (overnight sweep):** the sandboxing claims in this document went stale. Microsoft AGT **v5.0.0 (2026-06-25)** added `NonoSandboxProvider` — kernel-enforced sandboxing via Landlock/Seatbelt **with filtered egress**. The "AGT sandboxing is application-layer middleware" / "neither side has a real isolation story" framing below is outdated and must not be cited externally. The strategic verdict is unchanged (they are ahead on sandbox breadth; our STOP stands — we do not race them on isolation), but the reference implementation for kernel-enforced filtered egress now exists in their tree, and it is directly relevant to finding F81 (our sandbox has no filtered-egress / destination-allowlist mode). Entra JWT verification also shipped in v4.0.0 — the Entra gap is partially closed; the TEE keystore abstraction narrows our D4 key-lifecycle niche. Still no durable approval queue (`ApprovalResolution.reason` only deepens the interruption ceremony), and AGT's own BENCHMARKS.md explicitly disclaims an enforcement-layer ASR benchmark — wedge-2 uniqueness is stronger, not weaker. Details: `research/overnight-learnings-2026-09-22.md` §1–2.

---

## 0. Headline verdicts (read first)

1. **Microsoft AGT's single biggest verified gap: approvals stop at synchronous pause/resume.** It has `require_approval` with quorum, fatigue auto-deny, and webhook/console/callback handlers — but no persistent queue, no delegation, no web UI, no durable record across restarts. Its `agt red-team` is a *static system-prompt audit*, not an enforcement-layer attack battery. Its own README admits sandboxing is application-layer middleware and recommends containers for real isolation.
2. **AWS AgentCore's single biggest verified gap: no human-approval primitive at all.** Policy + Guardrails is a strong perimeter (deny-all Cedar, forbid-wins, prompt-injection/PII screening on every gateway action), but approvals are explicitly DIY (community doc: "composed via HumanLayer or similar"; AWS's own temporal-policies feature gates on an approval *event* someone else must produce). No queue, no UX, no delegation.
3. **Wedge 1 (approval queue + web UX): SURVIVES, narrowly.** Both competitors lack it; both could build it; neither has it on a roadmap. It is a feature-lead with ~12–18 months of runway, not a moat. Our honest limits (localhost console, no SSO, no TLS) mean it is a *developer-grade* queue today, not an enterprise one.
4. **Wedge 2 (adversarial eval battery): SURVIVES as a technical differentiator, fails as a standalone product.** Nobody's standard tooling attacks the *enforcement layer itself* — AGT's red-team audits prompt text, promptfoo/Mindgard attack the model. But nobody pays for a battery alone; it is evidence infrastructure, not a product.
5. **We cannot differentiate on: policy engine, audit crypto, sandboxing, framework adapters, or compliance mappings.** Say so plainly — those are table stakes occupied by Microsoft/AWS. The viable shape is: **the approval queue + enforcement-testing layer that plugs into AGT and AgentCore, not a replacement for them.**

---

## 1. Microsoft Agent Governance Toolkit — teardown

### 1.1 What it is, and its maturity
- Repo: `microsoft/agent-governance-toolkit`, MIT license, ~6,257 stars (star count as printed in a June 2026 commit message). **[verified]** (https://github.com/microsoft/agent-governance-toolkit)
- Status: **Public Preview** — "production-quality public preview releases. May have breaking changes before GA." **[verified]** (https://github.com/microsoft/agent-governance-toolkit, README)
- Microsoft-led with community scaffolding: GOVERNANCE.md, CHARTER.md (LF Projects format), MAINTAINERS.md, Discord, ADOPTERS.md, 29 Architecture Decision Records. Many community forks exist (a1k7, tomjwxf, nabbey88, snapkittywest, r-behera, xaviermp14). **[verified]**
- 10 formal RFC 2119 specifications with **992 conformance tests**; roadmap claims **13,000+ tests** and 10/10 OWASP Agentic Top 10 coverage. (Treat 13,000+ as vendor-claimed; 992 is spec-linked.) **[verified]** (https://github.com/microsoft/agent-governance-toolkit, README specs table; https://github.com/a1k7/agent-governance-toolkit/blob/HEAD/docs/ROADMAP.md)

### 1.2 Architecture: 7 packages — what actually exists vs marketing
The "7 packages" framing is **stale marketing**. As of v4.1.0, "45 packages have been consolidated into **5 top-level distributions**": `agent-governance-toolkit-core` (policy engine, capability model, audit, MCP gateway, identity, trust scoring, A2A/MCP/IATP bridges), `-runtime` (privilege rings, saga orchestration, termination control, execution plan validation, command denylist), `-sre` (SLOs, error budgets, chaos, circuit breakers), `-cli` (`agt` CLI, OWASP verification, integrity checks, policy linting), and the `[full]` meta-package. Old names (`agent-os-kernel`, `agentmesh-platform`, …) are stub packages. **[verified]** (https://github.com/microsoft/agent-governance-toolkit, README install section)

The conceptual packages map to real code, with caveats:
| Package (marketing) | Actual state |
|---|---|
| Agent OS (policy engine) | Real. Now the **Agent Control Specification (ACS)**: "stateless, deterministic, fail-closed policy decision runtime" with a **Rust core**; host supplies a snapshot, gets a normalized verdict (allow, warn, deny, escalate, transform). The old `agent_os.policies` rule model was removed in v5 (BREAKING_CHANGES.md). **[verified]** |
| Agent Mesh (identity/trust) | Real: Ed25519 agent identities, DID format `did:agentmesh:{agentId}:{fingerprint}`, trust scoring 0–1000, SPIFFE/SVID claimed. **[verified]** (README; SOC2 mapping) |
| Agent Runtime / Hypervisor (sandboxing) | Real but **application-layer**: privilege rings, saga orchestration, kill switch with real `os.kill(SIGKILL)`/TerminateProcess (PR #90), VFS delta engine with hash chains, command denylist. **The README's own Security section: "AGT enforces governance at the application middleware layer, not at the OS kernel level. The policy engine and agents share the same process boundary. Production recommendation: Run each agent in a separate container for OS-level isolation."** Their sandboxing is process-control + rings, not isolation. **[verified]** |
| Agent SRE | Real: SLOs, error budgets, chaos engineering, circuit breakers, replay debugging. 111 conformance tests on the SRE spec. **[verified]** |
| Agent Compliance | Real: `agt verify` (OWASP check), `agt lint-policy`, integrity checks; compliance mappings (see §1.6). **[verified]** |
| Agent Marketplace | Exists (Ed25519 plugin signing, trust-tiered capability gating). Depth unverified. **[verified-exists, depth unverified]** |
| Agent Lightning | "RL training governance with violation penalties" / "Lightweight fast-path policy evaluation." 100 conformance tests. Niche; depth unverified. |
| + MCP Security Gateway | Real: tool-poisoning detection, drift monitoring, typosquatting, hidden-instruction scanning; 127 conformance tests. **[verified]** |
| + Shadow AI Discovery | Exists ("find unregistered agents across processes, configs, repos"); roadmap lists **"production support" as near-term TODO** → not production-ready today. **[verified]** (roadmap) |
| + Governance Dashboard | Streamlit demo: "real-time fleet visibility — health, trust, compliance, audit events." A dashboard, not an approval console. **[verified]** |

### 1.3 Policy model
- Languages: YAML, OPA/Rego, Cedar — but the roadmap lists **"Cedar policy language production support"** and **"OPA/Rego integration hardening"** as near-term TODOs, i.e. **Cedar/Rego are not production-hardened in AGT today**; YAML is the working language. **[verified]** (README + roadmap)
- Expressiveness (YAML): `default_action` (allow/deny), rules with `condition` strings (`tool_name == 'x'`, `in`, `and`/`or`, numeric comparisons, dot-notation nested keys), `priority`, actions: `allow / deny / warn / log / require_approval / rate_limit`. Conflict strategy: MostSpecificWins. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/tutorials/19-dotnet-sdk.md)
- Fail-closed: ACS is specified as fail-closed; `require_approval` timeouts default to deny; callback errors default to deny. **[verified]**
- Performance: their own BENCHMARKS.md — **single-rule eval p99 0.037 ms; 100-rule policy p99 0.108 ms; full kernel execute (allow) p99 0.347 ms**; ~47K ops/sec at 1,000 concurrent agents. The headline "<0.1ms p99" refers to **policy evaluation only**; the full enforcement path (policy + audit + context) is ~0.35 ms p99. The FAQ's "Sub-millisecond (<0.1ms p99)" is the eval-path number. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/BENCHMARKS.md, https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/FAQ.md)
- **No policy hot-reload**: "Policy hot-reload without agent restart" is a near-term roadmap TODO. No versioning/rollback story found in docs. **[verified]** (roadmap)

### 1.4 Audit / attestation — Ed25519 chain verified shipped, with honest partials
- `SignedAuditEntry` with **Ed25519 signatures** + `HashChainVerifier` + `FileAuditSink` for append-only external storage shipped in PR #90 (CHANGELOG "Governance Enhancements"). **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/CHANGELOG.md)
- `MerkleAuditChain` with SHA-256 hash chaining and inclusion proofs (SOC 2 mapping: ✅ Covered), 157 conformance tests on the "Audit and Compliance" spec, "Decision BOM" concept. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/compliance/soc2-mapping.md; README specs table)
- **Honest partials in their own SOC 2 mapping**: "Signed audit: HMAC-SHA256 signatures on audit entries — ⚠️ Partial"; "PII detection: 2 regex patterns — ⚠️ Partial"; "`retention_days` field in policy schema (default 90) — ❌ Declaration only." **[verified]** (SOC 2 mapping doc; note the fork snapshot at a1k7 carried the same content — treat as ~3 weeks old, directionally current)
- Verification story: `agt verify` / `agt verify --evidence ./agt-evidence.json --strict`; HashChainVerifier for tamper detection. Key-management/rotation story for the Ed25519 signing keys: **not found in docs** — no rotation procedure evidenced. **[inferred gap]**
- Bottom line: their audit crypto is ahead of ours (shipped Ed25519 + Merkle; ours is HMAC with Ed25519-threshold in progress). Their retention story is weaker than it looks (declaration-only).

### 1.5 Sandboxing — what isolation it actually provides
Application-layer only: privilege rings, session isolation, saga compensation, kill switch (real SIGKILL), VFS delta capture, command denylist, 80 conformance tests. **No container/VM boundary; their own docs recommend separate containers for OS-level isolation.** ~~This is the same class as our sandbox prototype — neither side has a real isolation story, and Microsoft says so openly.~~ **STALE as of 2026-09-22: AGT v5.0.0 (2026-06-25) shipped `NonoSandboxProvider` — kernel-enforced Landlock/Seatbelt sandboxing with filtered egress. They now have a real isolation story; we do not. See the 2026-09-22 CORRECTION banner at the top of this document.** **[verified]** (README Security section)

### 1.6 Languages — the "5 SDK" claim, verified with a caveat
Install table lists all five: Python (`agent-governance-toolkit` PyPI), TypeScript (`@microsoft/agent-governance-sdk` npm), .NET (`Microsoft.AgentGovernance` NuGet), Rust (`agent-governance` crates.io), Go (`agent-governance-golang`). **README caveat: "All five language SDKs implement core governance (policy, identity, trust, audit). Python has the full stack."** The TypeScript README example shows only `PolicyEngine.evaluate` — thin client. So: 5 SDKs real, depth concentrated in Python. **[verified]** (https://github.com/microsoft/agent-governance-toolkit, README install section)

### 1.7 Framework integrations — the "20+" claim does not survive
- README's own table names ~14 rows: Microsoft Agent Framework (native middleware), Semantic Kernel (native), AutoGen (adapter), LangGraph/LangChain (adapter), CrewAI (adapter), OpenAI Agents SDK (middleware), Claude Code (plugin), Google ADK (adapter), LlamaIndex (middleware), Haystack (pipeline), Mastra (adapter), Dify (plugin), Azure AI Foundry (**deployment guide** — not an integration), GitHub Copilot CLI (**governance installer** — not an integration). **[verified]** (README)
- The deep-adapter comparison table lists **6 stable Python adapters** (LangChain, OpenAI Assistants, AutoGen **sync-only**, Semantic Kernel, CrewAI **sync-only**, OpenAI Agents SDK). **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/packages/agent-os.md)
- An older snapshot claimed "12 Framework Integrations" with merged PRs into Dify (65K⭐), LlamaIndex (47K⭐), LangGraph-trust (PyPI), OpenAI Agents, OpenClaw; the v3.7.0 roadmap claims "20+ framework integrations" listing protocols (MCP, A2A) and proposals as integrations. **[verified]** (a1k7 snapshot docs; roadmap)
- **Verdict: "20+" counts docs pages, plugins, installers, protocols, and proposals. Real deep adapters: ~6–12, two of them sync-only.** Still far ahead of our 3–4, but the number is inflated.

### 1.8 Approvals — deep on primitives, absent on queue/UX
- `require_approval` policy action; PR #1383 (Apr 23, 2026) added human-in-the-loop: execution **pauses**, approval requested, resumes or denies. Handlers: **AutoRejectApproval** (fail-safe default), **CallbackApproval** (custom fn + timeout), **ConsoleApproval** (stdin), **WebhookApproval** (Slack/Teams/PagerDuty). Timeout 5 min, deny-on-timeout; callback errors deny; deny rules bypass approval. 15 tests. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/commit/f67c22973e0e94eae6427e2908a61e074265c977)
- `EscalationHandler`: approval backends, **M-of-N quorum** (e.g. 2-of-3), **fatigue detection** (auto-deny when an agent floods the escalation queue, e.g. 5/min), risk classification critical/high/medium/low, expiration tracking. SOC 2 mapping marks escalation ✅ Covered. **[verified]** (SOC 2 mapping; agent-os docs)
- ASI-09 mitigation lists approval workflows + quorum + expiration; component: `extensions/mcp-server/src/services/approval-workflow.ts`. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md)
- **What is NOT there: no persistent queue, no queue-across-restart, no delegation/reassignment, no web UI, no batch-decide, no approval analytics.** The dashboard is fleet visibility (health/trust/compliance/audit), not an approval console. The model is synchronous pause/resume inside the governed call (5-min timeout), not a durable queue. **[inferred from absence in docs; searched specifically]**
- Net: AGT's approval story is *interruption-based*; ours is *queue-based*. They have better primitives (quorum, fatigue auto-deny); we have the durable queue + web console. These are complementary shapes, and theirs does not obsolete ours.

### 1.9 CLI and eval tooling
`agt doctor`, `agt verify` (OWASP compliance check, `--evidence --strict` for CI), `agt red-team scan ./prompts/ --min-grade B`, `agt lint-policy`. **[verified]** (README)
**`agt red-team` is PromptDefenseEvaluator: it "statically audits an agent's system prompt for missing defensive language before deployment"** — 12 vectors (now 17 with the ASI additions: cross-agent-auth, transaction-guardrails, skill-provenance, least-agency, encoding-injection), mapped to OWASP. It grades *prompt text*; it does not execute attacks against the enforcement engine. **[verified]** (https://github.com/microsoft/agent-governance-toolkit/pull/3028)
There is **no AGT equivalent of an adversarial battery aimed at its own policy engine/DLP/audit/approval ceremony.** **[inferred from docs]**

### 1.10 Compliance mappings — real mappings, incomplete automation
EU AI Act ("compliance mapping with automated evidence"), SOC 2 ("control mapping with audit trail export"), NIST AI RMF 1.0 ("full GOVERN/MAP/MEASURE/MANAGE alignment"), OWASP Agentic 10/10, AARM Extended R1–R9 ("verified Jun 14, 2026"), ATF five elements. **[verified]** (README Standards Compliance)
But their own near-term roadmap: **ISO 42001 mapping completion (pending), EU AI Act Annex IV automated evidence generation (pending), SOC 2 audit trail export tooling (pending).** The mappings exist as documents with honest partial-coverage annotations; the *automation* is unfinished. Checkbox-adjacent on evidence generation; real on mapping. **[verified]** (roadmap)

### 1.11 Gaps and limitations (verified unless noted)
1. **Public Preview, not GA** — breaking changes allowed. Enterprise procurement will hesitate. **[verified]**
2. **Non-Azure identity is a stated gap**: "Entra ID agent identity bridge" and "SPIFFE/SVID production deployment guide" are roadmap TODOs. **[verified]**
3. **No policy hot-reload; no versioning/rollback story.** **[verified]**
4. **Cedar/Rego not production-hardened** in AGT (roadmap TODOs). **[verified]**
5. **Audit retention is declaration-only** (`retention_days` ❌); signing-key rotation story not documented. **[verified / inferred]**
6. **Sandboxing is app-layer**; real isolation deferred to containers (their own recommendation). **[verified]**
7. **Approvals are synchronous** (5-min pause) — no durable queue, no delegation, no web UI. **[inferred from absence]**
8. **Compliance evidence automation unfinished** (Annex IV, SOC 2 export pending). **[verified]**
9. **Operational maturity**: Microsoft-driven (ESRP release pipelines, Microsoft CoC); community exists (Discord, forks, ADRs, issue #720 community benchmark) but direction is Microsoft's. Issue-tracker sentiment not quantified — could not verify beyond structure. **[partially verified]**
10. **Stateful long-running agents**: saga orchestration exists, but approvals time out at 5 min and there is no persistent queue — long-running human-gated workflows are not evidenced. **[inferred]**

---

## 2. AWS Bedrock AgentCore — teardown

### 2.1 What it is
AgentCore Policy (GA **Mar 3, 2026**, 13 regions incl. Tokyo) + **Guardrails in Policy** (GA **Jun 17, 2026**). **[verified]** (https://shinyaz.com/en/blog/2026/03/15/bedrock-agentcore-policy-cedar-authorization; https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-bedrock-agentcore-policy-guardrails-generally-available/)
Positioning: the budget-owner's choice — sits inside existing AWS commit, IAM-native, GA with enterprise support.

### 2.2 What Policy actually enforces
- **Gateway-perimeter authorization on every agent action**: policies attach to the AgentCore Gateway in ENFORCE mode; "every tool call passing through the Gateway gets evaluated against policies." Independent of agent code ("security lives outside the agent"). **[verified]** (shinyaz; AWS announcements)
- **Cedar-compiled policies, NL-authored**: "Teams can create policies using natural language that automatically convert to **Cedar—the AWS open-source policy language**." Policy Engine is a container for Cedar policies. **[verified]** (https://aws.amazon.com/about-aws/whats-new/2025/12/amazon-bedrock-agentcore-policy-evaluations-preview/)
- Semantics: **default deny-all**; explicit `permit` required; a single matching `forbid` overrides permits (**forbid-wins**). Community verification: `tools/list` doesn't even show tools lacking a permit policy. **[verified]** (shinyaz)
- Effects beyond permit/forbid: `suppressOutput` (block responses after tool execution if PII detected). **[verified]** (https://github.com/hardikthakkar94/amazon-bedrock-agentcore-samples/blob/HEAD/02-use-cases/data-analyst-conversational-assistant/cdk-data-analyst-assistant-agentcore-strands/README.md)
- **Temporal policies** (newer): trajectory-aware authorization — "given the recent trajectory observed at the AgentCore Gateway, is this specific request authorized?" Bounded sequences of actions by principal + session; can **require a human approval event recorded in the trajectory** before privileged actions. Deny-by-default, forbid-wins. **[verified]** (https://aws.amazon.com/blogs/machine-learning/securing-ai-agents-with-temporal-policies-in-amazon-bedrock-agentcore/)

### 2.3 What Guardrails evaluates
Guardrails in Policy evaluates **the outputs of every authorized agent action and the inputs of every call to a gateway target (tools, agents, models), in real time, at the gateway perimeter** — prompt injection attacks, harmful content, sensitive information exposure — "outside the agent's code," so the agent "cannot reason around them." All evaluations logged via AgentCore observability. **[verified]** (AWS GA announcement)
Cedar surface: `BedrockGuardrails::PromptAttack`, `::ContentFilter`, `::SensitiveInformation` functions. **[verified]** (aws-samples)
Availability at GA: **5 regions only** — us-east-1, eu-west-2 (London), eu-north-1 (Stockholm), ap-southeast-2 (Sydney), ap-northeast-1 (Tokyo). Policy itself: 13 regions at GA; current regional table shows Policy in 19 of 20 listed regions — **GovCloud cell is blank** (GovCloud support for Policy not confirmed in the current table). **[verified]** (AWS announcement; https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html)

### 2.4 Observability / audit story
"All policy evaluations are logged via AgentCore observability for optimization and auditing purposes." Identity model: per-agent verified tokens; Gateway enforces per-agent policies; "All actions flow through Observability, creating a **tamper-evident audit trail**"; CloudWatch Transaction Search enables forensic replay. (Tamper-evident claim is from a community doc, not AWS's own page — treat as asserted, not proven.) **[verified]** (AWS announcement; https://github.com/haoruilee/awesome-agent-native-services/blob/HEAD/services/agent-runtime-and-infrastructure/amazon-bedrock-agentcore.md)

### 2.5 Identity
AgentCore Identity: per-agent-instance verified tokens, IAM-backed, **custom claims** for multi-tenant auth rules, integrates with the customer's identity providers. Billed per token/key request for non-AWS resources. **[verified]** (AWS preview announcement; https://github.com/aws-samples/sample-claude-code-plugins-for-startups/blob/HEAD/plugins/aws-dev-toolkit/skills/agentcore/SKILL.md)

### 2.6 Pricing (itemized, from the official AWS Bedrock pricing page)
Guardrails (per 1,000 text units; 1 text unit ≈ 1,000 chars), from AWS's own worked examples:
- Content filters: **$0.15** / 1k text units
- Denied topics: **$0.15** / 1k text units
- Sensitive-information filters: **$0.10** / 1k text units
- Contextual grounding: **$0.10** / 1k text units
- Automated Reasoning checks: **$0.17** / 1k text units
- Worked example: 1,000 queries/hr (200-char in + 1,500-char out) with content filters + denied topics = 3,000 units × ($0.15+$0.15)/1,000 = **$0.90/hr ≈ $650/mo** for one modest chatbot's two filters. **[verified]** (http://aws.amazon.com/bedrock/pricing/)
- Note: prices were cut ~80–85% in early 2026 (community); one older article shows $0.75/$1.00 — stale. Use the pricing-page numbers.
- **Policy evaluations: consumption-based, per authorization request** — one request per tool call through the Gateway; LOG_ONLY billed same as ENFORCE; policies cached ~5 min. **The official per-request price could not be verified in public sources**; a community estimate from the preview era was $0.008/authorization request (marked by its author as "verify current pricing"). Treat as indicative only. **[partially verified]** (AWS announcement; https://dev.to/aws-builders/agentcore-policy-when-your-devops-agent-almost-deleted-production-and-how-to-prevent-it-12j0)
- The full stack also meters: Gateway API calls, Runtime CPU/memory-seconds, Memory storage + retrievals, Identity token requests, Observability telemetry (CloudWatch-like), Evaluations per-evaluation. **[verified]** (aws-samples SKILL.md pricing table)
- **Latency tax**: community report of **~50–150 ms added per Policy evaluation** (unverified beyond one community source; AWS publishes no number). If true, sub-10ms agent loops can't use it. **[unverified — single community source]**

### 2.7 Human-approval UX: the confirmed gap
- **No built-in approval primitive**: "AgentCore does not include a built-in approval primitive (that would be composed via HumanLayer or similar)." Post-hoc review via observability only. **[verified]** (https://github.com/haoruilee/awesome-agent-native-services/blob/HEAD/services/agent-runtime-and-infrastructure/amazon-bedrock-agentcore.md)
- Temporal policies can gate on "an explicit human approval event recorded in the trajectory" — but **AWS provides the gate, not the queue**: the event must be produced by something else. **[verified]** (AWS temporal-policies blog)
- In practice teams DIY it: the aws-samples governed FinOps agent implements HITL as **email approval** built by the sample author. **[verified]** (https://github.com/aws-samples/sample-governed-finops-agent-bedrock-agentcore/blob/HEAD/README.md)
- AWS's Bedrock Agents HITL guidance distinguishes "confirmation" (show function + params) from "return of control" (modify before send) — guidance, not a product. **[verified]** (community summary citing AWS docs: https://github.com/lvtd-llc/rowset/blob/HEAD/apps/pages/content/blog/human-in-the-loop-ai-agents.md)

### 2.8 Lock-in mechanics
- **What ports**: Cedar is open-source; the policy *logic* is portable as code. Guardrails work "across any foundation model" via ApplyGuardrail, and AgentCore is model-agnostic (OpenAI, Gemini, Claude, Nova, Llama, Mistral) and framework-agnostic (CrewAI, LangGraph, LlamaIndex, Google ADK, OpenAI Agents SDK, Strands). **[verified]** (AWS FAQ: https://aws.amazon.com/bedrock/agentcore/faqs/)
- **What doesn't**: the enforcement point is the AgentCore **Gateway** (AWS-managed); `BedrockGuardrails::*` Cedar functions are AWS-only; audit/observability is CloudWatch-native; NL-authoring pipeline is AWS. Leaving means re-implementing the perimeter, swapping every guardrail function, and rebuilding the audit pipeline — plus unwinding Memory/Runtime/Gateway integration. **Policy-as-code ports; the enforcement plane does not.** NL-authored policies add soft lock-in (the NL→Cedar translation is opaque and non-reproducible outside AWS). **[inferred]**
- Cost lock-in: per-request metering on every layer makes the governance tax scale with agent activity — the more agents act, the more leaving hurts (sunk integration) and the more staying costs. **[inferred]**

### 2.9 AWS gaps summary
1. **No human-approval queue/UX/delegation** — the single biggest functional gap vs our wedge. **[verified]**
2. **Guardrails-in-Policy only in 5 regions**; Policy absent from GovCloud in the current table. **[verified]**
3. **Cost stacks at scale**: per-auth-request + per-gateway-call + Guardrails per text unit on *both* inputs and outputs. **[verified pricing; inference on scale]**
4. **AWS-only enforcement plane**; cross-cloud story is "bring your model, keep our perimeter." **[verified]**
5. **DX friction**: guardrail-in-policy deployment via raw `CfnResource` with `when guardrails` Cedar syntax (per aws-samples); official per-request Policy price not published. **[verified]**
6. **No adversarial-eval story for the enforcement layer**: AgentCore Evaluations targets agent *quality* (helpfulness, tool selection, accuracy) — not attacks on the governor. **[verified]** (AWS announcement)

---

## 3. Differentiation strategy

### 3.1 Pressure-test: approval queue + web UX

**What we have** (honest): `gov/approval_web.py` — localhost operator console, stdlib only, no JS. Canonical decision path through `ApprovalQueue.decide()` under lock; web decisions labeled `web/human-operator`; CSRF + same-origin checks; fail-closed on corrupt queue; **26/26 adversarial battery** (unauthenticated/CSRF/cross-origin/replay/tampered-form/corrupt-queue/corrupt-lock/XSS) per the module docstring — note: the task brief said 28/28; the module docstring (authoritative) says 26/26. **Honest limits, from the docstring itself**: in-memory sessions (no SSO/OIDC/mTLS, no persistence, no cross-process sharing), single-process server, no TLS (127.0.0.1 default), break-glass/batch/auto-approve are CLI-only, web offers single approve/deny on non-break-glass records only.

**How hard is it for Microsoft to close?** AGT already has the harder primitives: quorum (M-of-N), fatigue auto-deny, risk scoring, webhook delivery to Slack/Teams/PagerDuty, 15 tests on the approval path. A durable queue + web UI is, technically, a quarter of work for their team — they have a Streamlit dashboard to extend and an `approval-workflow.ts` service. **BUT**: their architecture is *interruption-based* (pause the governed call, 5-min timeout, resume) — a durable, delegable, restart-surviving queue is a different model, and **their roadmap contains no queue item**. Their fatigue answer is auto-deny, not queue management. Evidence they'd bother is weak; evidence they could is strong. **Could they ship a better one in a quarter? Yes — if they decided to. Nothing in their roadmap says they will.**

**How hard is it for AWS to close?** AWS would have to build a product they have explicitly chosen not to build: their own docs say the approval primitive "would be composed via HumanLayer or similar," and temporal policies deliberately define only the *gate* (approval event in the trajectory), leaving the queue/UX to third parties. AWS builds primitives, not operator consoles. **Unlikely to close in 18 months; if they do, it will be via acquisition or a partner (HumanLayer), not a native queue.**

**Is the 26/26 battery a moat or a feature?** A feature — but a *load-bearing* one. The battery doesn't make the queue uncopyable; it makes the queue *credible*: our FINDINGS.md documents real ceremony attacks we caught in our own queue (F11 ANSI-spoofed previews, F21 batch bulk-approving a stopped exfil fragment, F18 benign-poller false positives). AGT demonstrates no equivalent adversarial testing of its approval path. The battery is replicable; the *habit* it evidences is the actual edge.

**Verdict: WEDGE SURVIVES, narrowly.** It is the thinnest spot in both competitors' armor, confirmed by their own docs. But it is a feature-lead (~12–18 months), not a moat — and ours is currently a *developer-grade* console (no SSO, no TLS, no persistence), so the lead is in design + adversarial testing, not enterprise readiness.

### 3.2 Pressure-test: adversarial eval battery

**What we have**: a multi-wave adversarial gate (latest wave 816/816 green; earlier waves 144/144, 288/288, 408/408; ~95 situations and growing) that attacks **our own enforcement layer**: DLP evasion (hex/base64/base32/chunked/reversed/substitution — F2/F8/F16), exfil correlation and its defeats (F1/F9/F10/F13/F14/F15/F17/F20), ledger tampering (F17b), approval-ceremony attacks (F11/F12/F21), policy-simulator fidelity (F7), key-rotation verify path (F19), queue-fatigue/false-positive dynamics (F4/F18). Every defeat is filed with reproduction, severity, and explicit residuals.

**Is "we attack our own governor" unusual?**
- **AGT's red-team**: verified — a *static audit of system-prompt text* for defensive language. It never executes an attack against the policy engine. Not the same thing. ✅ unusual vs AGT
- **promptfoo** (OSS, MIT; acquired by OpenAI Mar 2026): generates adversarial *prompts*, runs them against the *LLM endpoint*, grades responses. Target = the model/app, not the governor. ✅ unusual vs promptfoo ([verified](https://github.com/promptfoo/promptfoo))
- **Mindgard / Lakera / Haize-style labs**: same class — they attack the model/prompt layer. ✅
- **rein-ai** (small OSS): the *closest analog* — runtime governor + NL policy compiler + "adversarial red-team simulator." Exists, tiny community, AGPL + commercial. ⚠️ partially covered
- **AWS AgentCore Evaluations**: tests agent *quality*, not governor robustness. ✅

**Is it a product or a dev tool?** A dev tool. Nobody has a budget line for "adversarial battery for my policy engine." What people (and auditors) pay for is *evidence that controls were tested* — the battery is evidence infrastructure. Its commercial shape is: (a) the proof behind a platform/queue product, (b) a neutral benchmark that other governors get measured against, (c) services/assurance work. As a standalone SKU it has no buyer.

**Who pays, really**: platform teams that build their own governors (they'd run it, not buy it — it's $0 OSS-shaped); auditors/regulators who need control-effectiveness evidence (they buy *reports*, i.e. services); us, as the credibility engine for the queue. **Verdict: WEDGE SURVIVES technically; commercially it is an asset, not a product.** The winning move is to make it the *neutral* benchmark — including running it against AGT's own engine.

### 3.3 BUILD / STOP / CHANGE verdicts per roadmap area

| Roadmap area | Verdict | Reasoning |
|---|---|---|
| Policy engine | **STOP** racing; **CHANGE** role | AGT's ACS (Rust core, fail-closed, 0.037 ms p99 eval) and AWS Cedar both exceed ours. Keep our engine minimal as the *harness's system-under-test*, not a product. CHANGE: add Cedar-compatible policy export so our policies can run on AgentCore — turns AWS lock-in into our portability argument. |
| Audit log crypto | **STOP** racing signatures | AGT shipped Ed25519 + Merkle + 157 conformance tests. Our HMAC→Ed25519-threshold is behind. Do not claim "better crypto." |
| Audit key lifecycle + retention | **BUILD** (narrow) | Their gaps are real and verified: AGT retention is *declaration-only*; signing-key rotation story undocumented; AWS rotation story unverified. Our F19 (rotation-safe verify) and KMS envelope keyring with fail-closed dev-key handling (F73) are a genuine operational niche: "keys you can actually operate." Small, but real. |
| Approval queue + web UX | **BUILD** | The confirmed thinnest spot in both competitors (§3.1). Scope to durable queue + delegation + quorum + fatigue/anomaly + audit binding. Do NOT chase SSO/TLS/multi-tenancy yet — stay honest about localhost-grade. |
| Adversarial eval battery | **BUILD** as method; **CHANGE** framing | Keep growing it; reframe from product to *evidence infrastructure*. Publish the method; run it against AGT's engine and AgentCore policies to establish neutrality. |
| Sandboxing | **STOP** | AGT's own README says app-layer middleware ≠ isolation and recommends containers. We cannot out-sandbox "use containers," and neither can they. Keep the prototype honest; never claim it as a differentiator. |
| Framework adapters | **STOP** at current scope | AGT has 6 deep + ~14 named (2 sync-only); AWS is framework-agnostic at the gateway. Our 3–4 adapters suffice for the harness. No parity chase. |
| MCP security | **CHANGE** | AGT has the scanner (MCP Security Gateway, 127 conformance tests). Don't duplicate the scanner; keep our StruQ/instruction-hierarchy *controls* (different layer: prevention vs detection). |
| Compliance mappings | **STOP** | AGT has mappings (even with automation pending); we can't out-paper Microsoft. Reference theirs; spend zero effort here. |
| Identity | **STOP** racing | SPIFFE/DID/Entra (theirs, Entra bridge pending) vs our PrincipalRegistry. Keep the registry minimal — it's harness infrastructure, and F17 proved identity continuity is the hard part, which favors deployment-controlled registries over crypto theater. |
| DLP / exfil controls | **BUILD** (as battery fuel) | Our encoding-aware DLP + read-correlation + taint + egress ledger is *deeper than anything evidenced* in AGT (whose content story is regex-partial per their own SOC 2 doc) or AWS (whose PII story is priced per-unit). But its value is as the thing the battery attacks, not as a standalone claim. |

**The plain-English version**: we cannot differentiate on policy engine, audit signatures, sandboxing, adapters, or compliance paper. Say it outright: those fights are lost — to Microsoft on OSS depth, to AWS on enterprise distribution. What survives is the *human gate* (queue) and the *proof the gate works* (battery). Everything else is table stakes we maintain at minimum viable quality.

### 3.4 Product decisions (the 3–5 concrete bets)

**D1. Build the durable approval queue as the flagship — and make it pluggable into the competitors.** Durable (restart-surviving), delegable, quorum-capable, fatigue-aware (our F4/F18 work is ahead of AGT's auto-deny-only story), with every decision audit-bound. Ship adapters that let AGT's `require_approval` webhook and AWS's temporal-policy approval *event* flow into our queue. Rationale: neither competitor has a queue or intends to build one (verified: AGT roadmap silent; AWS explicitly defers to third parties like HumanLayer). If you can't beat the platform, be the missing piece that plugs into it. Expected persistence: ≥18 months — AWS builds primitives not consoles; AGT's interruption model would need re-architecting.

**D2. Productize the battery as the neutral enforcement-layer benchmark, not as a SKU.** Publish the methodology; run the gate against AGT's ACS engine and against AgentCore Cedar policies and publish the results either way. Rationale: verified unusual (AGT red-team = prompt-text audit; promptfoo/Mindgard = model attacks; only tiny rein-ai is adjacent). A neutral benchmark that Microsoft/AWS can't dismiss — because it runs against their governors too — is the cheapest credible marketing in this space, and it's the evidence artifact auditors actually want.

**D3. Stop racing engines; sell portability.** Freeze the policy engine at "good enough to be the harness SUT"; add Cedar-compatible export. Rationale: AWS's lock-in is the enforcement plane, not the policy language. A $0, self-hosted authoring-and-testing layer whose policies deploy to AgentCore is a coherent anti-lock-in story — and it's the one thing AWS's own NL-authoring (opaque, non-reproducible) can't offer.

**D4. Narrow the audit story to key lifecycle and retention — the two things both competitors fumble.** Rotation-safe verification (our F19 fix), fail-closed dev-key handling (F73), KMS envelope keyring, and *enforced* retention (theirs is declaration-only). Rationale: don't claim better signatures (lost); claim operable keys. This is unglamorous, auditor-visible, and genuinely thin in both competitors' docs.

**D5. Stay a component, not a platform — and say so.** No managed cloud, no SSO promises, no compliance-paper chase. The honest position from market research stands: reference implementation + eval harness + the approval queue. Concretely: keep the repo's honest-limits discipline (it is our best marketing — no competitor documents residuals like FINDINGS.md does), and treat "contribute the queue upstream to AGT" as a live strategic option, not a failure mode. If Microsoft ever ships a durable queue, our queue becomes a PR, and our battery becomes the reason they take it.

---

## 4. What could change this analysis
- AGT ships a durable approval queue or web console (watch their roadmap/CHANGELOG).
- AWS announces a native HITL/approval product or acquires HumanLayer-equivalent.
- AGT completes Cedar production support + Entra bridge + Annex IV evidence automation (closes three of their verified gaps).
- Policy per-request pricing publishes and undercuts the self-hosted cost argument, or Guardrails-in-Policy expands beyond 5 regions.
- A competitor publishes an enforcement-layer adversarial battery (watch rein-ai, Mindgard).

## SOURCES
Verbatim URLs from tool output. "Carried forward" items were captured as tool output in the prior market-research session and recorded in `research/market-research-sources.md`.

**Microsoft AGT**
- https://github.com/microsoft/agent-governance-toolkit
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/FAQ.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/.github/copilot-instructions.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/tutorials/19-dotnet-sdk.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/TESTING_GUIDE.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/GLOSSARY.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/CHANGELOG.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/BENCHMARKS.md
- https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/packages/agent-os.md
- https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/compliance/soc2-mapping.md
- https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/OWASP-COMPLIANCE.md
- https://github.com/microsoft/agent-governance-toolkit/commit/f67c22973e0e94eae6427e2908a61e074265c977
- https://github.com/microsoft/agent-governance-toolkit/pull/3028
- https://github.com/microsoft/agent-governance-toolkit/commit/517d6fcf2b44aae4e7c5821029afb48cf86f79a3
- https://github.com/a1k7/agent-governance-toolkit/blob/HEAD/docs/packages/agent-os.md
- https://github.com/a1k7/agent-governance-toolkit/blob/HEAD/docs/ROADMAP.md
- https://github.com/nabbey88/agent-governance-toolkit

**AWS**
- https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-bedrock-agentcore-policy-guardrails-generally-available/
- https://aws.amazon.com/about-aws/whats-new/2025/12/amazon-bedrock-agentcore-policy-evaluations-preview/
- https://aws.amazon.com/blogs/machine-learning/securing-ai-agents-with-temporal-policies-in-amazon-bedrock-agentcore/
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html
- https://aws.amazon.com/bedrock/agentcore/faqs/
- http://aws.amazon.com/bedrock/pricing/
- https://shinyaz.com/en/blog/2026/03/15/bedrock-agentcore-policy-cedar-authorization
- https://github.com/aws-samples/sample-claude-code-plugins-for-startups/blob/HEAD/plugins/aws-dev-toolkit/skills/agentcore/SKILL.md
- https://github.com/aws-samples/sample-governed-finops-agent-bedrock-agentcore/blob/HEAD/README.md
- https://github.com/hardikthakkar94/amazon-bedrock-agentcore-samples/blob/HEAD/02-use-cases/data-analyst-conversational-assistant/cdk-data-analyst-assistant-agentcore-strands/README.md
- https://github.com/haoruilee/awesome-agent-native-services/blob/HEAD/services/agent-runtime-and-infrastructure/amazon-bedrock-agentcore.md
- https://dev.to/aws-builders/agentcore-policy-when-your-devops-agent-almost-deleted-production-and-how-to-prevent-it-12j0
- https://gerardo.dev/en/bedrock-policy.html
- https://triotechsystems.com/amazon-bedrock-guardrails-vs-azure-ai-content-safety-vs-google-model-armor/
- https://github.com/lvtd-llc/rowset/blob/HEAD/apps/pages/content/blog/human-in-the-loop-ai-agents.md

**Eval-battery comparables**
- https://github.com/promptfoo/promptfoo
- https://github.com/promptfoo/promptfoo/blob/HEAD/site/docs/faq.md
- https://medium.com/@krohit0389/promptfoo-is-the-tool-qa-engineers-should-be-using-to-red-team-ai-features-c1d4944227c
- https://github.com/owasp/aisvs/blob/HEAD/1.0/research/chapters/C09-Orchestration-and-Agents/C09-04-Agent-Identity-and-Audit.md

**Carried forward from market-research-sources.md (prior session tool output)**
- https://github.com/dinpd/agentaction/blob/HEAD/docs/agent-governance-landscape.md
- https://github.com/rahmanazhar/rein-ai
- https://aws.amazon.com/blogs/machine-learning/a-shared-agentic-platform-for-wood-mackenzie-on-amazon-bedrock-agentcore/
- https://tech-insider.org/aws-bedrock-agentcore-vs-azure-ai-foundry-vs-vertex-ai-agent-builder-2026/
