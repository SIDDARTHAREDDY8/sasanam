# Founder Strategy Memo — 2026-09-22

**To:** the founder (only reader that matters)
**From:** Krishna, in founder mode
**Method:** $0, public sources only, everything cited. No marketing claims. Honest grades throughout.
**Standing context:** repo private; product is a mid-journey prototype (enforcement core + adversarial battery + 311-scenario registry + 100+ finding corpus); B1 12/14; open findings F70 (MEDIUM, recovery countdown replay), F81 (LOW accepted gap — filtered egress deliberately not shipped), F110 (MEDIUM, open); wedges graded W1=C / W2=B-as-method; 11-item stop-duplicating list; zero kill-triggers fired.

---

## 0. The one-paragraph version

Open source in this space makes money exactly one way: **the open core is the funnel, the money is in the managed compliance wrapper.** LangSmith ($39/seat + per-trace, ~$100K+ enterprise), Langfuse (MIT core, monetizes the $29→$199 jump which is just 3-year retention + SOC 2 reports), Portkey ($49/mo gateway), Bedrock Guardrails ($0.15/1K text units) — every one of them gives away the engine and charges for hosting, retention, auditability, and the compliance checkbox. Our three gaps all have solved patterns in the wild (proxy-enforced egress, Temporal-style replay journals, HumanLayer-style approval routing) — steal the mechanisms, not the products. The "something different" bet: **don't sell governance; sell the evidence that governance happened.** Nobody has a budget line for "agent governance," but Vanta/Drata proved there is a $10–25K/yr budget line for "evidence my controls operated" — and runtime evidence for agent behavior is a greenfield. I kill the ratings-agency darling in §3: it's our best technical asset and our worst business.

---

## 1. How open source makes money here

### 1a. LangChain / LangGraph / LangSmith — the reference pattern

**Funding (public):** $260M total raised. $10M seed (Benchmark, Apr 2023) → $25M Series A (Sequoia, Feb 2024, $200M valuation) → $100M Series B (IVP, Jul 2025, $1.1B) → $125M Series B extension (IVP, Oct 2025, **$1.25B valuation**), with Sequoia, Benchmark, CapitalG, Sapphire, Datadog, Databricks participating.
— https://sacra-pdfs.s3.us-east-2.amazonaws.com/langchain.pdf

**The monetization engine is LangSmith, not the framework.** Pricing (public, Sep 2026):
- Developer: $0 — 5K traces/mo, 1 seat, 14-day retention
- Plus: **$39/seat/mo** — 10K traces/mo included, then per-trace overage (~$0.50/1K base traces, $5.00/1K extended-retention traces)
- Enterprise: custom, ~$100K+/yr — self-hosting, SSO, RBAC, HIPAA/SOC 2

Plus metered deployment: Agent Builder runs $0.05/run, production deployment uptime $0.0036/min.
— https://github.com/ucsandman/dashclaw/blob/HEAD/docs/research/competitor-pricing-landscape-2026.md · https://langfuse.com/compare/langsmith

**What converts free→paid:** (1) the framework is a zero-friction funnel — LangSmith works with one line of env config inside the ecosystem you already run; (2) the seat+trace hybrid meter grows with the customer's success (more agents → more traces → more seats); (3) the enterprise tier sells **data sovereignty + compliance** (self-hosting is Enterprise-only — there is no open-source LangSmith server, unlike Langfuse). The open-source framework creates the traces; the traces create the billing event. The framework is the top of funnel; the meter is on observability.

**The founder lesson:** LangChain never tried to sell LangGraph. They sold what running LangGraph *produces* (traces, evals, deployments) once you can't live without it. **Nobody pays for the engine. Everybody pays for what the engine's exhaust proves.**

### 1b. The pattern across adjacents

| Player | Open-source piece (funnel) | What they charge for | Public price points | Who pays and why |
|---|---|---|---|---|
| **Langfuse** | Entire core MIT (24k+ stars; June 2025 moved everything to MIT) | The compliance wrapper | Hobby $0 (50k units) → Core $29/mo → **Pro $199/mo** → Enterprise $2,499/mo | Teams that want to stop operating ClickHouse. The Core→Pro jump ($29→$199, same usage) is literally 3-year retention + SOC 2/ISO reports + rate limits — **the compliance checkbox is the product** |
| **Portkey** | OSS gateway (routing, retries, guardrails, load balancing) | Managed gateway, logged requests | Developer $0 → Production $49/mo (100K logs) → Enterprise custom; overage $9/100K req | Teams that want the gateway without operating it; sits in the request path so the meter is natural |
| **Guardrails AI** | Full framework Apache 2.0, 50+ validators | Hosted validation + observability | Pro/Enterprise custom, opaque | Regulated teams; AWS Marketplace distribution |
| **Helicone / Braintrust / PromptLayer / Laminar** | OSS or free-tier proxies/SDKs | Per-event observability + evals | Helicone-style: free tier → usage tiers; Laminar: data-volume pricing | Same motion: proxy the traffic, meter the exhaust |
| **AWS Bedrock Guardrails** | None (closed) | Per-request governance API | **$0.15/1K text units** content filters & denied topics; $0.10/1K PII & grounding checks | AWS-native teams; governance as a metered API call — the purest "governance is a utility bill" model |
| **Azure AI Content Safety** | None (closed) | Per-1K-token screening | ~$0.0004/1K tokens (third-party baseline) | Same utility-bill motion inside Azure |
| **Palo Alto Prisma AIRS** | None | Platform/security suite | Enterprise contracts (undisclosed) | Security buyers who already buy Palo Alto; governance rides the existing security budget, not a new AI budget |
| **OpenAI AgentKit** | None (closed platform) | Model tokens + storage when workflows run; design canvas free | Agent Builder free to design, pay on run; ChatKit storage $0.10/GB-day; billing since Nov 2025 | Developers inside OpenAI's gravity well. Note: **Agent Builder is being wound down** (announced June 2026, unavailable after Nov 30, 2026) — even OpenAI kills builder tooling that doesn't earn its keep; the platform consolidates to API + evals |

— Langfuse: https://dev.to/beton/langfuse-pricing-teardown-2026-2pi9 · Guardrails/pricing landscape: https://github.com/ucsandman/dashclaw/blob/HEAD/docs/research/competitor-pricing-landscape-2026.md · Bedrock pricing: https://triotechsystems.com/amazon-bedrock-guardrails-vs-azure-ai-content-safety-vs-google-model-armor/ · AgentKit: https://binaryverseai.com/agentkit-guide-pricing-access-build-setup/ · https://aibusiness.com/agentic-ai/openai-agentkit-enables-agentic-integration-in-chat

**The unified money pattern, stated bluntly:**

1. **Give away the thing developers touch** (framework, gateway, validators). It must be genuinely free and genuinely good — it's the funnel, not the product.
2. **Meter the exhaust, not the engine.** Nobody buys "policy evaluation." They buy traces, logged requests, text units screened, seats around the data. The billable event is always *downstream of usage*.
3. **The compliance wrapper is the highest-margin tier.** Langfuse's $170/mo Core→Pro cliff is retention + SOC 2 reports. LangSmith gates self-hosting (data sovereignty) at Enterprise. Vanta/Drata (§3) sell nothing but the wrapper. **The checkbox is the product.**
4. **Ride an existing budget.** Prisma AIRS doesn't create an "AI governance budget" — it rides the security budget. Vanta rides the audit budget. Every standalone-governance SKU dies at procurement; every governance feature attached to an existing budget line lives.
5. **HumanLayer's corollary:** the one pure-play approval company (YC F24) sells "ask in Slack before dropping tables" as a **credits-based API** — they productized the *channel*, not the policy. Nobody pays for the rule; they pay for the reliable delivery of the human moment.
   — https://github.com/wfl36/ai-knowledge-base/blob/HEAD/knowledge/2026-07-17/Launch-HN--Human-Layer--YC-F24----Human-in-the-Loop-API-for-AI-Systems_8.2_2026-07-17.md

**What this means for us:** our current posture (metered nothing, sell nothing, $0) is correct for now — but the day we charge, the meter goes on **governed decisions and retained evidence**, not on the policy engine. The engine stays $0 forever. That is the LangChain lesson applied to us.

---

## 2. Gap research — how others solve what we can't

### 2a. Filtered egress (F81) — the proxy pattern wins, and there's a recipe

We ship strict deny-all because our in-namespace iptables design couldn't express an allowlist without fail-open risk. The industry solved this; the answer is **don't filter packets, proxy requests**:

- **OpenSandbox (open-source, current):** egress as a **sidecar** sharing the sandbox's network namespace. Two layers: (1) a DNS proxy on 127.0.0.1:15353 with iptables redirecting all port-53 traffic to it — allowlist enforced on *names*, denied names get NXDOMAIN; (2) optional `dns+nft` mode where resolved IPs for allowed domains are added to nftables with TTL (dynamic DNS — no launch-time pin, no rotation failure). Privilege (`CAP_NET_ADMIN`) isolated to the sidecar; the app container stays unprivileged.
  — https://github.com/pangjiping/opensandbox/blob/HEAD/components/egress/README.md
- **The ADR worth stealing verbatim** (woditschka/agentic-coding-reference, 2026-07-29 "proxy-enforced egress"): the allowlist is expressed as **hostnames the proxy resolves per request**; a `dst` deny *above* the allow rules refuses any name resolving into loopback, RFC1918, carrier-NAT, or link-local space — this single ordering closes the DNS-rebind, LAN-probing, and cloud-metadata gaps; the access log records attempts **with verdicts outside the container**; proxy-readiness failure means "no network" (denied, never exposed) — the ordering race disappears because there is no route to race. Bonus measured finding: enabling bubblewrap costs seccomp for *every* process in the container — evidence for keeping our namespace+seccomp design and adding the proxy rather than switching sandboxes.
  — https://github.com/woditschka/agentic-coding-reference/blob/HEAD/docs/adr/2026-07-29-proxy-enforced-egress.md
- **wirken:** three modes (none/allowlist/open), default none, enforced at the container boundary per-channel, provider host deliberately *exempted* from the agent allowlist (enforced at operator network config instead) — a clean answer to "the allowlist must not break the agent's own lifeline."
  — https://github.com/gebruder/wirken/blob/HEAD/docs/egress.md
- **kubernetes-sigs/agent-sandbox (cautionary):** their "secure default" *allows* 0.0.0.0/0 and only blocks RFC1918/metadata/DNS — i.e., default-open to the public internet. This is what a checkbox-driven default looks like; don't copy the posture, copy the mechanism (NetworkPolicy at L3/L4 + the honesty about what L7 they don't do).
  — https://github.com/kubernetes-sigs/agent-sandbox/blob/HEAD/examples/policy/network-policy-management/README.md
- **Northflank's design principles** (vendor blog, but the principles are sound): default-deny egress, explicit allowlists, DNS controls, per-tenant policies; proxy for hostname-level control, firewall for IP/port; **the agent must not be able to modify its own network permissions.**
  — https://northflank.com/blog/how-to-design-networking-for-secure-ai-agent-sandboxes

**Implementable takeaways for F81 (no new research needed):** (1) move the enforcement point from in-namespace iptables to a **loopback-bound egress proxy sidecar** with per-request hostname resolution; (2) put the private-range deny *above* the allow rules (kills DNS-rebind + metadata + loopback in one ordering); (3) log attempts-with-verdicts outside the container; (4) exempt the provider/lifeline host at the operator layer, not the agent layer; (5) proxy-not-ready = no network, never fail-open. This is a design doc + prototype, not a sandbox rewrite — and it keeps the F81 "accepted gap" honest until the proxy exists.

### 2b. Execution recovery / checkpoint-replay integrity (F70) — Temporal's split is the answer

F70's wound: our recovery draft MAC'd the countdown content but not its freshness, so a replayed countdown silently defeated F45's interrupted-execution recovery. **A MAC covers content, not freshness** — our own FINDINGS.md says it. Temporal solved this a decade ago:

- **The pattern (Temporal, verified):** event-sourcing + deterministic replay. Every step is recorded into an append-only history; on failure the worker *re-executes the deterministic control-flow code against that history*, fast-forwarding over completed effects. The two load-bearing rules: (1) **workflow/control-flow code must be deterministic** — all non-determinism (and Temporal's docs name **"LLM/AI invocations"** explicitly) moves into Activities/steps that run *outside* the replay path, with results journaled; (2) the history is the source of truth, and replay never re-executes a recorded side effect (exactly-once workflow semantics, at-least-once activity semantics).
  — https://github.com/temporalio/temporal/blob/HEAD/docs/architecture/README.md · https://github.com/konstantinmirin/neograph/blob/HEAD/docs/design/durable-execution-replay-research-2026-07-02.md
- **LangGraph's version** (the funnel-relevant one): checkpoint at superstep boundaries keyed by `(thread_id, checkpoint_ns, checkpoint_id)`; `interrupt()` persists state and returns — the pause is durable, not a held thread; resume replays from the interrupted node, and **node implementations must be idempotent or guarded** because replay re-executes up to the interrupt. Same split, coarser granularity.
  — https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/ · https://github.com/dbrowneup/linus/blob/HEAD/docs/repo-notes/langgraph.md
- **Restate** (noted for completeness): journal-based durable execution with exactly-once semantics via the journal — same family.

**Implementable takeaway for F70:** our recovery journal needs Temporal's two properties, not a stronger MAC: (1) **bind a monotonic sequence number + epoch into every MAC'd journal entry** — freshness becomes content, and the MAC covers it (this is the one-line class fix for countdown replay); (2) **split the recovery controller (deterministic, replayable) from the effectful steps (journaled, never re-executed)** — the countdown is control flow and must be deterministic given the journal; the actions it guards are effects and must be idempotent-or-journaled. AGT's ADR-0030 (action binding to digest + policy version, replay protection, execution-time revalidation) is the same idea in their interrupt-hardening — import the mechanism, per the strategy doc's "watch and learn."

### 2c. Approval-queue UX at production scale — HumanLayer owns the channel, LangGraph owns the primitive

- **HumanLayer (YC F24):** "ask in Slack before dropping tables" as an API. SDK exposes `human_as_tool` / approval calls at the tool-calling layer; they handle routing to the right human across Slack/email (SMS/Teams roadmap), async state while waiting, and the audit trail. Pricing: free tier + **credits-based usage pricing**; whitelabeling for customer-facing agents. Framework-agnostic (CrewAI, LangChain, raw tool loops). The insight they sell: *the communication itself needs guardrails* (their buyers wanted to approve the "ask for approval" action — approval-fatigue and misrouting are the real problems, which is exactly our F4 detector's territory).
  — https://github.com/wfl36/ai-knowledge-base/blob/HEAD/knowledge/2026-07-17/Launch-HN--Human-Layer--YC-F24----Human-in-the-Loop-API-for-AI-Systems_8.2_2026-07-17.md
- **LangGraph `interrupt()`:** the durable primitive — `interrupt(payload)` checkpoints state and returns; hours later `Command(resume=value)` continues from exactly there; **the graph never blocks on a human** (no held thread, no held connection). Static (`interrupt_before=["tools"]`) and dynamic (in-node) forms. This is the correct primitive shape and it's why our durable queue (restart-surviving, no held connections) is architecturally right.
  — https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/
- **What production approval UX actually looks like** (synthesized): per-action tiers (auto / require_review / require_two_person), diff/trace preview in the approval surface, approve / edit-and-approve / redirect / deny, timeout-with-deny default, latency telemetry per agent, and progressive auto-removal of checkpoints when an agent's pass rate justifies it. Nobody we found does quorum-with-one-deny-veto or fatigue-anomaly surfacing — those remain ours.

**Implementable takeaways:** (1) our queue should speak HumanLayer's *interface shape* (approval request as a routable event with payload + timeout + audit) so we're interoperable with the ecosystem instead of building our own Slack app — **build the queue, rent the channel**; (2) adopt the tiered-checkpoint vocabulary (per-action tiers, edit-and-approve) — it's what buyers already understand; (3) keep the two differentiators (one-deny veto, fatigue surfacing) — they're the only parts nobody else has.

---

## 3. The "something different" bets

The founder's challenge: if incumbents build what we build, change the way of business. Three bets, one killed.

### Bet 1 (lead bet): Governance Evidence as a Service — sell the proof, not the policy

**The mechanism.** Nobody has a budget line for "agent governance" (market research §5). But Vanta/Drata proved a $10–25K/yr budget line for **"evidence my controls operated"** — their own customers say the platform doesn't make you compliant, it automates evidence collection for the auditor (Vanta ~$10K/yr entry, $8–30K under 200 employees, per Vendr transaction data).
— https://underdefense.com/blog/compliance-automation-pricing/ · https://www.cloudanix.com/learn/what-is-soc2-compliance

The greenfield: **Vanta collects evidence that controls *exist*; nobody collects evidence that an agent *behaved*.** EU AI Act logging obligations, SOC 2's "evidence of operation across the period" (not existence at period start), ISO 42001 — all demand runtime proof. Our hash-chained audit log + approval queue + 311-scenario battery *is* period-wide operational evidence. The product: an **auditor-readable evidence artifact** — signed, timestamped, retention-managed export of what the agent did, what policy decided, who approved what, and what the battery proved the governor stops. Open-source the enforcement core ($0, funnel); sell the evidence pipeline (export formats auditors accept, retention management, attestation reports, auditor workspace).

**Who pays:** AI startups that need SOC 2 / ISO 42001 to close enterprise deals — the exact Vanta buyer, one desk over. GRC teams second.

**Why incumbents can't or won't copy it quickly:** Microsoft and AWS sell the *runtime* — a vendor grading its own homework is not credible to an auditor. Neutrality is the product, and we're the only ones with (a) a MAC-chained (not plain-SHA-256 — their own README admits it) tamper-evidence story, (b) an adversarial battery that proves what the governor stops, and (c) no cloud to defend. AGT would have to argue "trust our logs about our enforcement" — auditors discount self-attestation.

**What we'd need to build first:** one export format (signed JSON bundle: decision log + approvals + retention manifest), one auditor partnership to validate the artifact shape, enforced retention (already planned, `gov/retain.py`). That's a 90-day build, not a platform.

**Why it might fail:** auditors are conservative — "evidence format" needs either a standards body or a big-4 blessing, and we have neither; chicken-and-egg on the first auditor who accepts the artifact. Also: Vanta could add an "agent runtime evidence" connector faster than we can get auditor mindshare. Mitigation: don't fight Vanta — **be their evidence source** (connector/integration, not competitor).

### Bet 2: Neutral enforcement benchmark as ratings agency — killed in writing

**The mechanism.** D2 as a service: run the 311-scenario battery against *any* governor (open or commercial), publish scored reports; vendors pay for certification runs + the badge; enterprises pay for comparison data before procurement. "UL for agent governors."

**Why I'm killing my own darling:** this is our best technical asset and our worst business. (1) Market research §5 is explicit: *no buyer has a budget line for this.* Ratings agencies monetize institutional trust that takes 5+ years to build; we have months of runway on wedge 1. (2) RAMPART just commoditized the framework layer with Microsoft's distribution — the method is free now; only the corpus + neutrality remain, and neutrality doesn't invoice. (3) The incentive structure rots: the moment vendors pay for the badge, the rating is marketing, and the neutrality — the only asset — is gone. Every ratings business in history faces this; none solve it in year one. **Keep D2 as method and credibility engine behind Bet 1 (the battery is what makes our evidence *believable*). Never as the business.** Killing it as a SKU is already STOP S9 — this memo kills it as a company.

### Bet 3 (long-horizon): the metered enforcement sidecar — ride the harness explosion

**The mechanism.** The Portkey/Bedrock pattern applied to governance: a $0 self-hosted sidecar that sits in the agent's tool-call path and **meters governed decisions** — free under a threshold, then per-1K-decisions, with the managed control plane (queue UI, evidence export from Bet 1, retention) as the upsell. The distribution insight: open-source harnesses are exploding (DeepSeek Harness hit 225K stars in weeks *and* shipped CVE-2026-82533 — a sandbox escape through its own control-plane API). The harness authors have distribution and no governance team. **Be the drop-in governance sidecar for the harnesses the stars can't secure** — one-line integration, $0 core, paid evidence/queue cloud.

**Who pays:** harness maintainers (via their users' usage) and teams running agents in production who won't self-operate the queue UI.

**Why incumbents won't copy quickly:** AWS meters at the gateway but explicitly won't build the operator console; Microsoft won't build metered SaaS around an open toolkit; neither will chase a sidecar for *third-party* harnesses. The anti-incumbent shape is the point.

**What we'd need first:** the sidecar packaging (our adapters already exist — this is repackaging, not research), one flagship harness integration (the DeepSeek-Harness-shaped hole is the pitch), usage metering infra.

**Why it might fail:** metering requires being in the request path — that's latency and reliability liability we don't have the ops muscle for today; it needs the managed offering we explicitly decided not to build (the strategy doc's NOT NOW on console enterprise readiness). **Verdict: park until Bet 1 funds the ops.** It's the year-two business, not the year-one business. The 90-day version is just: package the sidecar, integrate one harness, meter nothing — distribution first, monetization later.

---

## 4. What to stop / start / keep — 90-day founder implications

### Stop (extend the list)
- **Stop discussing the battery as anything but method.** RAMPART ended the debate; STOP S9 now reads "validated by Microsoft."
- **Stop any new enforcement primitive AGT/AWS meters.** Add to §10: *metered governance APIs* (Bedrock Guardrails, Azure Content Safety) — we don't build a competing meter; we build what their meter can't produce (evidence, queue).
- **Stop building our own human channel** (no Slack app, no mobile app). HumanLayer proved the channel is a separate product. **Build the queue, rent the channel** — emit approval events in their interface shape.

### Start (in priority order)
1. **The evidence artifact (highest leverage, §3 Bet 1).** One signed, timestamped, auditor-readable export bundle from our audit chain: decisions + approvals + retention manifest. Smallest build that opens a budget line. Everything else is preparation for this.
2. **Proxy-enforced egress design (§2a).** Design doc + prototype: loopback-bound egress proxy, per-request hostname resolution, private-range deny above allow rules, verdict logging outside the container, not-ready = no network. Unblocks F81 without shipping theater. Do not touch the namespace/seccomp core.
3. **Freshness-bound recovery journal (§2b).** Monotonic sequence + epoch inside every MAC'd journal entry; split deterministic recovery control flow from journaled effects. Kills the F70 class with Temporal's pattern, not a stronger MAC.
4. **HumanLayer-shaped approval events (§2c).** Our queue emits/consumes the ecosystem's approval-event shape (payload + tier + timeout + audit) instead of inventing a parallel one. Interop is distribution.

### Keep
- The build→test→break→repeat battery habit and D2 neutral runs — the corpus must keep growing; it's the credibility behind Bet 1 and the only part of wedge 2 that compounds.
- The durable queue flagship (wedge 1) with its two differentiators (one-deny veto, fatigue surfacing) — still a C, still the best feature lead we have, still expiring.
- Cedar export (D3) — it's the portability story that makes the $0 core safe to adopt.

### The single highest-leverage next build
**The evidence artifact.** Rationale: it's the only item on this list that converts technical assets we already own (HMAC audit chain, approval queue, battery corpus) into something a buyer already pays for (Vanta's $10–25K/yr evidence budget). It doesn't require the managed service (it's an export), doesn't require auditor permission to *build* (only to bless), and it makes every future neutral D2 run a sales asset instead of a lab exercise. If it fails, we've lost 90 days and gained an export format. If it works, it funds Bet 3.

---

## Sources (all public, all $0)

- LangChain funding/valuation: https://sacra-pdfs.s3.us-east-2.amazonaws.com/langchain.pdf
- LangSmith/Langfuse/Portkey pricing landscape: https://github.com/ucsandman/dashclaw/blob/HEAD/docs/research/competitor-pricing-landscape-2026.md
- Langfuse pricing teardown (MIT move, $29→$199 compliance cliff): https://dev.to/beton/langfuse-pricing-teardown-2026-2pi9
- Langfuse vs LangSmith (official comparison): https://langfuse.com/compare/langsmith
- Laminar vs Langfuse vs LangSmith (deployment models): https://github.com/lmnr-ai/lmnr/blob/HEAD/frontend/assets/blog/2026-01-29-laminar-vs-langfuse-vs-langsmith-llm-observability-compared.mdx
- Bedrock Guardrails vs Azure vs Model Armor (pricing): https://triotechsystems.com/amazon-bedrock-guardrails-vs-azure-ai-content-safety-vs-google-model-armor/
- OpenAI AgentKit launch: https://aibusiness.com/agentic-ai/openai-agentkit-enables-agentic-integration-in-chat
- OpenAI AgentKit pricing + Agent Builder wind-down: https://binaryverseai.com/agentkit-guide-pricing-access-build-setup/
- HumanLayer (YC F24) launch + model: https://github.com/wfl36/ai-knowledge-base/blob/HEAD/knowledge/2026-07-17/Launch-HN--Human-Layer--YC-F24----Human-in-the-Loop-API-for-AI-Systems_8.2_2026-07-17.md
- Temporal architecture (event sourcing + deterministic replay): https://github.com/temporalio/temporal/blob/HEAD/docs/architecture/README.md
- Durable-execution replay research (Temporal/Restate/LangGraph compared): https://github.com/konstantinmirin/neograph/blob/HEAD/docs/design/durable-execution-replay-research-2026-07-02.md
- LangGraph interrupts / HITL: https://langchain-ai.github.io/langgraph/concepts/human_in_the_loop/
- LangGraph checkpointing deep-dive: https://github.com/harut8/system-design/blob/HEAD/ai-rag/21-langgraph-deep-dive.md
- OpenSandbox egress sidecar (DNS proxy + nftables): https://github.com/pangjiping/opensandbox/blob/HEAD/components/egress/README.md
- Proxy-enforced egress ADR (steal this): https://github.com/woditschka/agentic-coding-reference/blob/HEAD/docs/adr/2026-07-29-proxy-enforced-egress.md
- wirken egress modes: https://github.com/gebruder/wirken/blob/HEAD/docs/egress.md
- kubernetes-sigs agent-sandbox network policy (cautionary): https://github.com/kubernetes-sigs/agent-sandbox/blob/HEAD/examples/policy/network-policy-management/README.md
- Northflank sandbox networking principles: https://northflank.com/blog/how-to-design-networking-for-secure-ai-agent-sandboxes
- DeepSeek Harness sandbox escape (CVE-2026-82533): https://dennysentinel.com/blog/2026-09-15-deepseek-harness-sandbox-escape/ · http://thehackernews.com/2026/09/deepseek-harness-flaw-let-ai-agents.html
- Vanta/Drata pricing (Vendr data): https://underdefense.com/blog/compliance-automation-pricing/
- SOC 2 automation landscape: https://www.cloudanix.com/learn/what-is-soc2-compliance
- Prior strategy docs (this repo): research/differentiation-strategy.md, research/teardown-wave47-2026-09-22.md, workstreams/architect/REALWORLD_BAR.md

*Built without touching gov/, evals/, or tests/. The build loop runs separately.*
