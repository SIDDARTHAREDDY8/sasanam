# Wave-338 Lane 6 — Research Scout F: Tier-1 Competitor Delta
Date: 2026-10-05. All citations accessed 2026-10-05.
Method: primary sources only (official announcements, product pages, vendor docs, blog posts, patent-search via Google Patents/USPTO queries).
A "threat delta" = a technical fact that changes the competitive picture, not a marketing claim.

## 1. Algedonic — HIGH (unchanged, but accelerating on go-to-market)

### 1.1 New since 2026-10-05 pass: nothing
- Latest item remains the Sept 30, 2026 press release: "Algedonic Demonstrates Runtime Enforcement for Enterprise AI Agents, Opens Early Access" (first public demo, The AI Conference 2026, Pier 48, table 19, Sept 30–Oct 1), plus early access for orgs running agents in production.
  - https://world.einnews.com/pr_news/945899633/algedonic-demonstrates-runtime-enforcement-for-enterprise-ai-agents-opens-early-access
- A Sept 30 APN summary adds an eligibility detail not in the base PR: early access is open to organizations with 1,000+ employees, in production or multi-platform pilots, in multi-cloud/hybrid environments with established platform engineering practices. Same capability claim otherwise (agent discovery + policy enforcement at the point of action, works without changing agent source code).
  - https://www.appliedtechnologynews.com/agp-article/945911524-algedonic-opens-early-access-after-first-public-demo-of-runtime-ai-agent-enforcement

### 1.2 Patent filings: not found
- Query: "Algedonic OR Gopisetty" against Google Patents/USPTO indexing (2026-10-05) — zero patent records surfaced. The "patent filings" item in our tracking is likely provisionals (not yet published) or internal claims.
- Delta: our "patent claims unverified" note stands. We cannot verify ANY Algedonic patent application as filed. Note the strategic consequence: if they file publicly and publish, their mechanism claims become readable — patent publication is a technical source we gain automatically. Watch Espacenet/USPTO monthly.

### 1.3 Weak points — still open
- No human-in-the-loop: the demo PR and demo copy mention "stop an unauthorized action before it executes" with zero mention of human approval/escalation. Their model is policy-before-execution with the agent blocked autonomously.
- No offline evidence: nothing in the demo or site copy mentions signed, offline-verifiable evidence per decision. Their evidence story (if any) is unannounced.
- No technical whitepaper or docs surfaced since the pass — only press syndication of the Sept 30 release.

### Threat delta: NONE. Direction of travel is acceleration (first public demo + open early access at ≥1,000-employee shops), but no new technical fact changes the picture. WATCH: weekly cadence; their early-access customer announcements will be the next signal.

## 2. EVE AI Core — HIGH (unchanged)

### 2.1 New since 2026-10-05 pass: nothing
- Latest blog post remains the Medium piece dated Aug 31, 2026: "Open at the Edges, Sovereign at the Core: What's New in EVE AI Core" (already recorded in the prior pass). It describes accepting external stack signals, binding them into a certificate two independent verifiers agree on, and appearing in "login flows and marketplaces enterprises use." No new posts in September or October.
  - https://medium.com/@jamauriceholt.com/open-at-the-edges-sovereign-at-the-core-whats-new-in-eve-ai-core-992cdbda92be
- eveaicore.com / evecore.com blogs show the July 2026 content batch as latest (governance model, deterministic governance, CoreGuard hardware-attestation readiness packet dated 2026-06-20).
  - https://evecore.com/blog
- No new commits visible via web search; the "hardware-attested CoreGuard" packet still labels enclave attestation, FPGA veto core, and HSM key ceremony as roadmap, not done (honest, and unchanged since June 20).
  - http://evecore.ai/static/downloads/EVE-Hardware-Attested-CoreGuard-Readiness-Packet.pdf?v=4

### 2.2 Human-in-the-loop: still absent
- EVE's own blog language mentions "human escalation" as a design concept (e.g. the July 8 "Trust in AI Governance Has to Be Enforced" post), but there is no HITL approval product or per-action human-gate in any announced material. Their invariant is "CoreGuard is the single deterministic authority. No model sits in the decision path." Our opening (fail-closed pre-execution WITH human approval queues) remains the only announced HITL among the Tier-1 set.

### 2.3 Patent portfolio
- Their March 2026 provisional ("Asynchronous Multi-Stage AI Governance Pipeline with Token Speculative Buffering and Deterministic Kill Switch," Prov. App. No., filed March 27, 2026) was already tracked; nothing new published or granted that surfaced.

### Threat delta: NONE. Stale is itself data: repos quiet 108–139d at the prior pass and nothing since. Either they're heads-down on a release (watch Medium blog + evecore.ai downloads) or stalled. WATCH: bi-weekly.

## 3. Omada + EmpowerID — HIGH (consolidating; threat up since acquisition but no new technical disclosure)

### 3.1 No new technical detail since the 2026-10-05 pass
- The acquisition (announced Sept 24, 2026; Patrick Parker joins as CIO; terms undisclosed; Stephens advised) was recorded in the prior pass. No product integration update, docs, or release has followed in the 11 days since.
  - https://www.morningstar.com/news/pr-newswire/20260924la55226/omada-acquires-empowerid-to-close-the-ai-agent-security-gap
  - https://www.kuppingercole.com/blog/deshpande/omada-gains-runtime-agent-governance
- KuppingerCole's analyst note (Sept 2026) is the most honest technical read: Omada "will need to show customers quickly that the acquisition closes the gaps they have raised, especially on agents and AI-assisted governance, ideally with committed delivery dates." I.e., even the analyst take treats the runtime-enforcement capability as promised-not-yet-integrated.
  - https://www.kuppingercole.com/blog/deshpande/omada-gains-runtime-agent-governance
- The ID Tech digest confirms the technical direction: in-line policy evaluation against live risk metrics at the moment of the access request (not just delayed audit cycles), bridging scheduled reviews with runtime authorization.
  - https://idtechwire.com/id-tech-digest-september-24-2026/

### 3.2 Threat assessment
- Their model remains identity-driven runtime authorization: decide "what each agent may do" in real time, with the IGA system of record behind it. Still no fail-closed pre-execution refusal primitive, no human-in-the-loop approval queue per action, and (per our code review of EmpowerID) weak enforcement under the hood. The acquisition gives them the DISTRIBUTION of a top-tier IGA vendor (Copenhagen, enterprise installed base) + a runtime-enforcement claim that hasn't yet been productized.
- Delta: the threat rating moves up slightly on distribution alone, but the enforcement weakness (their technical gap) persists unchanged. The opening is: they sell "governance from identity," we sell "enforcement at the action with human approval and offline evidence."

### Threat delta: NONE new this week. WATCH: watch for the first integrated Omada+EmpowerID product announcement or the promised "committed delivery dates" — that is when weak-enforcement claims become verifiable (or exposed).

## 4. Identity incumbents — converging, but still identity-first (no enforcement breakout)

### 4.1 CrowdStrike / SGNL
- Fal.Con 2026 (Sept 2026): CrowdStrike unveiled its Agentic Identity Provider — cryptographically verifiable identities for agents found by Falcon Guardian, brokering task-scoped tokens bound to the human or workload each agent acts for. Builds on the $740M SGNL acquisition.
  - https://www.snsinsider.com/reports/ai-agent-identity-and-access-management-market-11181
- This is IDENTITY issuance + token brokering, not runtime enforcement at the action. Notably, CrowdStrike's own Falcon Fund co-invested in Rig Security's $12M seed (see §6) — the market is splitting "identity" and "enforcement" into separate bets even inside one ecosystem.
- Delta: nothing that changes the enforcement picture. WATCH: whether Falcon Fusion SOAR's CAEP-driven enforcement evolves toward per-action veto.

### 4.2 Okta
- Aug 2026: Agent SSO went GA — Cross App Access embedded in core Okta SSO plans at no added cost, prebuilt support for Claude, Atlassian, Slack, Notion; the separately-licensed "Okta for AI Agents" covers discovery/governance.
  - https://www.snsinsider.com/reports/ai-agent-identity-and-access-management-market-11181
- No new runtime-enforcement capability announced since; the "deactivate rogue agent" kill switch is manual (April 2026 datasheet), not automatic pre-execution refusal.

### 4.3 Palo Alto Idira
- Launched May 2026, built on CyberArk post-$25B acquisition; zero-standing-privilege extended to machine identities and AI agents. Nothing new since.
  - https://www.snsinsider.com/reports/ai-agent-identity-and-access-management-market-11181

### 4.4 Ping Identity — closest incumbent move toward enforcement
- Sept 1, 2026: Ping launched Enterprise Personal Agent Access (PingOne Privilege) — discovers personal agents (incl. shadow AI), ties each session to user+device, and "governs access and actions at runtime within supported environments." Named use cases: Claude desktop assistants and Claude Code. Administrators can allow/deny/log individual actions, REQUIRE HUMAN APPROVAL for sensitive tasks, and revoke access in real time. Controls apply when agents hit MCP servers, repos, APIs, K8s, databases, cloud infra.
  - https://www.helpnetsecurity.com/2026/09/01/ping-identity-enterprise-personal-agent-access/
  - https://idtechwire.com/ping-identity-adds-runtime-access-controls-for-claude-personal-agents/
- March 2026 baseline: Identity for AI (GA) with Agent IAM Core + Agent Gateway (runtime enforcement layer for agent-to-system interactions, fine-grained authorization, MCP support) + Agent Detection.
  - https://www.kcau9.com/business/press-releases/cision/20260324LA17431/ping-identity-defines-the-runtime-identity-standard-for-autonomous-ai/
- Threat read: Ping is the only incumbent now shipping per-action runtime allow/deny with a HUMAN APPROVAL option — the closest to our HITL opening among incumbents. BUT it is still identity-anchored (delegated tokens, session-attributed), no fail-closed pre-execution refusal primitive, no offline/signed evidence per decision. Their primitive is "the agent acts with scoped delegated identity and we check each action"; ours is "the agent may not act at all until governance (and optionally a human) approves, and every decision is signed evidence."
- The Sept 1 launch predates the Oct 5 pass but its enforcement implications were likely underweighted. Delta: raise Ping to the top of the incumbent watch list.

### 4.5 Microsoft Agent 365
- GA May 2026 at $15/user/mo ($99 in M365 E7); Microsoft Entra Agent ID as identity foundation; Conditional Access extended to agents. Nothing new since.

### Threat delta: Ping's Sept-1 Enterprise Personal Agent Access is the notable incumbent move (runtime allow/deny/log + human approval per action, already piloted in global enterprises). It narrows — but does not close — the enforcement gap. No other incumbent broke out. WATCH: Ping monthly (they're the fastest-moving incumbent on enforcement); others bi-weekly.

## 5. Bifrost / Maxim AI — MED (gateway-only, unchanged; name collision noted)

- Bifrost v2.2.1 shipped Sept 18, 2026 (open-source Go gateway, Apache 2.0, OpenAI-compatible, 1000+ models): virtual-key budgets/rate limits, guardrail rules (PII/secrets redaction, block/redact/flag), tool-argument inspection, audit logging across model+tool calls. Enterprise tier adds in-VPC/air-gap.
  - https://www.getmaxim.ai/articles/enterprise-ai-guardrails-for-company-policy-and-compliance/
  - http://dev.to/sebuzdugan/top-5-enterprise-ai-gateways-2026-bifrost-vs-kong-vs-litellm-vs-cloudflare-vs-vercel-3i10
- "Bifrost Edge" (early access, free for existing enterprise customers): lightweight laptop service routing desktop AI traffic (Claude Code, ChatGPT, Copilot) through the Bifrost Gateway for shadow-AI visibility.
  - https://www.getmaxim.ai/edge
- Threat read: remains a throughput/routing gateway with policy overlays, not an agent-governance enforcement product. DeepInspect's own comparison concedes Maxim's advantage is speed; governance is virtual-key budgets + console SSO. No per-action authority model, no HITL, no signed evidence.
- ⚠️ Name collision: Rig Security's endpoint sensor is ALSO named "Bifrost" (§6). Different company, different product, different layer. Track carefully to avoid conflation.

### Threat delta: NONE. WATCH: quarterly (gateway, not governance).

## 6. New entrants (last ~week) — two found

### 6.1 Rig Security — $12M seed, emerged from stealth ~Sept 29, 2026 — WATCH-LIST #1
- Launched with $12M seed led by Ten Eleven Ventures + Brightmind Partners; CrowdStrike Falcon Fund participated; Wiz co-founder Ami Luttwak among investors. Founded early 2025 by Guy Kozliner (Wiz alum). 20 employees; claims Fortune 200 customers in production across financial services, insurance, healthcare, technology; available on AWS Marketplace and CrowdStrike Marketplace.
  - https://thejoai.com/ai-news/rig-security-raises-12m-to-track-ai-agents/
  - https://www.securityweek.com/rig-security-emerges-from-stealth-with-12m-to-tackle-agentic-ai-identity-risks/
- Product: two components. (a) RICE (Rig Identity Correlation Engine): ML/math identity correlation across IdPs, cloud, on-prem, network, endpoints at claimed >96% accuracy; builds an identity-dependency graph of how identities connect and can be abused. (b) "Bifrost" endpoint sensor: lightweight, watches identity behavior at origin, distinguishes an AI agent's session from the human user's own, and ENFORCES POLICY — "blocks a rogue or misused agent's risky action without disrupting the person whose identity the agent borrowed."
- Threat read: this is a genuine new entrant in RUNTIME AGENT ENFORCEMENT, and a credible one (seed funded by Ten Eleven, CrowdStrike Falcon Fund, Wiz lineage; claimed production Fortune-200 traction). Their technical angle differs from ours: agent-vs-human session attribution at the endpoint, enforced by blocking risky actions. Weak points to probe if they matter: (i) enforcement point is the endpoint/sensor, not a fail-closed pre-execution gate in the tool path; (ii) no evidence story announced (no signed/offline evidence); (iii) no human-in-the-loop approvals; (iv) name collision with Maxim's Bifrost creates market confusion they will have to fix.
- Delta: NEW. Recommend promoting to WATCH-HIGH and assigning a scout to track Rig's product detail drops (docs, demos) — their endpoint-enforcement angle overlaps our sandbox-adjacent tool-call surface.
- Verdict: NEW THREAT (low-mid for now — early, unproven enforcement depth), fast-track tracking.

### 6.2 DeepInspect — new-ish stateless proxy vendor — WATCH-LIST #2
- deepinspect.ai: a stateless inline proxy at the AI request boundary (deploys inside the customer's environment, in front of any HTTP LLM endpoint incl. OpenRouter). Claims: identity-bound per-request policy (per-route, per-role), prompt-level classification (PII/PHI/MNPI/source code/jurisdiction), pass/block/modify before the request leaves the environment, and a signed per-decision audit record committed outside the application's write path (fields: identity, role, classification, model+version, policy version, outcome, cryptographic signature). Explicitly "deterministic, fail-closed, model-agnostic," <50ms overhead claimed in internal testing. Blog active through Sept 2026 (latest ~Sept 18).
  - https://www.deepinspect.ai/blog/deepinspect-vs-bedrock-guardrails
  - https://www.deepinspect.ai/blog/ai-gateway-for-regulated-industries
- Threat read: their primitives overlap our public-facing design language — fail-closed + signed per-decision evidence — but their enforcement point is the MODEL-CALL boundary (prompt in / output out), not the AGENT-ACTION boundary (tool execution, approvals, delegation chains). They explicitly scope OUT tool authorization, STDIO MCP, and credential storage ("mark them rather than shade the whole diagram"). Funding, customer traction, and launch date could not be verified from public sources — treat all claims as vendor self-description, not established fact.
- Delta: NEW NAME, but unknown standing. WATCH-LOW until funding/traction verifiable; their comparison-blog pattern (vs OpenRouter, Bifrost, Bedrock, Vercel) suggests they're positioning against gateways, i.e., a gateway-class competitor, not a governance-layer one.

### 6.3 False positives cleared this week
- "Eve Security" (Austin, EveGuard, $3M seed) — is a SEPT 2025 company, not new; already >1 year old. Not a new entrant.
  - https://pulse2.com/eve-security-3-million-seed-funding-raised-for-helping-keep-ai-agents-safe/
- Vercel "eve" framework — June 2026 launch, an agent framework (with HITL approvals as a framework feature), not a governance product. Not a new entrant in our category.

## 7. Net threat delta for this pass

| Competitor | Delta since 2026-10-05 pass | Verdict |
|---|---|---|
| Algedonic | Demo PR only; no patents found; early-access ≥1k-employee orgs | NO CHANGE (HIGH, accel) |
| EVE AI Core | No new posts/commits; still no HITL; roadmap honest-but-stale | NO CHANGE (HIGH, quiet) |
| Omada+EmpowerID | No post-acquisition product update; analyst still waiting on "committed delivery dates" | NO CHANGE (HIGH, integrating) |
| CrowdStrike/SGNL | Agentic Identity Provider (Sept, identity not enforcement) | NO CHANGE |
| Okta | Agent SSO GA (Aug) — identity, not enforcement | NO CHANGE |
| Palo Alto Idira | Nothing new | NO CHANGE |
| Ping Identity | Enterprise Personal Agent Access (Sept 1): runtime allow/deny/log + HITL approval option + MCP controls, piloted in global enterprises | INCUMBENT WATCH-UP (closest to our HITL opening) |
| Microsoft Agent 365 | Nothing new | NO CHANGE |
| Bifrost/Maxim | v2.2.1 + Bifrost Edge early access (shadow-AI visibility); still gateway | NO CHANGE (MED) |
| Rig Security | NEW: $12M seed, endpoint sensor enforcing agent-vs-human attribution + real-time action blocking | NEW — WATCH-HIGH |
| DeepInspect | NEW NAME: fail-closed signed-evidence proxy at model boundary; unverified traction | NEW — WATCH-LOW |

## 8. Recommended watch cadence going forward
- Algedonic: weekly (early-access customer announcements expected; USPTO/Espacenet monthly for their filings).
- Rig Security: weekly (docs/demos; verify their enforcement claims break-first if they gain real traction).
- Ping Identity: monthly (fastest-moving incumbent toward enforcement).
- EVE AI Core: bi-weekly (silence is data; a blog/drops resumption signals a release push).
- Omada+EmpowerID: bi-weekly (wait for integrated product or "committed delivery dates").
- CrowdStrike/Okta/Palo Alto/Microsoft: monthly.
- DeepInspect: monthly until funding/traction verified, then re-evaluate.
- Maxim AI Bifrost: quarterly.

## 9. Gaps in this pass
- Could not verify Rig Security's $12M claims beyond press coverage (no official launch blog found on their own domain this pass) — recommend a scout pull their docs/pricing when tracked.
- Could not verify DeepInspect's funding, team, or customer status — all claims are from their own blog.
- Algedonic patent search limited to indexed public records; provisionals are not published, so "no patents found" ≠ "no patents filed."
