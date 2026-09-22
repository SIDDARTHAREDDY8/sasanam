# Competitive Teardown Update — 2026-09-22 (wave-47)

**Lane:** competitive teardown (user-committed, standing). **Method:** $0,
public sources only, crawled 2026-09-22. Builds on
`research/differentiation-strategy.md` (wave-27) and
`research/teardown-update-2026-09-22.md` (wave-36) — read both first
for the base verdicts and the stop-duplicating list. This update
records only what CHANGED since the wave-36 sweep and what it does to
the wedge verdicts and kill triggers.

**Headline:** wedge-1 (durable approval queue) gets its first
clean roadmap read — AGT's public roadmap (crawled this wave) has
**no durable approval queue, no operator console, no approval UX
anywhere on it**; trigger 1 NOT fired. Wedge-2 (adversarial battery)
takes its first real method-level pressure: **Microsoft open-sourced
RAMPART (May 20, 2026)** — a pytest-native, CI/CD-integrated
agentic red-teaming framework on PyRIT. AWS moves are all GA
milestones of already-known shapes (AgentCore Policy GA, Guardrails
GA in AgentCore) — no queue, no native HITL; trigger 2 NOT fired.
Zero triggers fired; one watch list addition.

## 1. Microsoft — RAMPART + Clarity (new since wave-36)

**What they are** (announced 2026-05-20, Microsoft Security blog;
Ram Shankar Siva Kumar, founder of Microsoft's AI red team):

- **RAMPART** (Risk Assessment and Measurement Platform for Agentic
  Red Teaming): pytest-native framework for writing and executing
  safety/security tests on AI agents, adversarial and benign, built
  on PyRIT. Statistical trials ("this action must be safe in at
  least 80 percent of runs" — accounts for model probabilisticity).
  CI/CD-integrated (runs like other integration tests). Explicitly
  designed to **turn one-off red-team findings into reusable
  regression tests**. Needs only a thin adapter connecting an agent
  to the test suite. Used internally by Microsoft's red team before
  release (an external researcher's vector was expanded to ~100
  variants, tested ~300 times incl. multi-turn).
- **Clarity:** pre-code "structured sounding board" / AI thinking
  partner — problem clarification, solution exploration, failure
  analysis, decision tracking; records decisions as markdown in the
  repo; multiple AI evaluators (security, human factors,
  operational reliability perspectives).

Sources:
https://thehackernews.com/2026/05/microsoft-open-sources-rampart-and.html ·
https://www.theregister.com/security/2026/05/21/microsoft-open-sources-agentic-ai-safety-tools/5243822 ·
https://campustechnology.com/articles/2026/05/20/microsoft-releases-open-source-ai-safety-tools-for-agent-development.aspx ·
https://winbuzzer.com/2026/05/21/microsoft-open-sources-rampart-clarity-for-ai-safety-xcxwbn/ ·
https://www.microsoft.com/en-us/security/blog/2026/05/20/introducing-rampart-and-clarity-open-source-tools-to-bring-safety-into-agent-development-workflow/ ·
https://dailyaibrief.com/news/microsoft-open-source-rampart-clarity-ai-safety-tools-DzP39OMP

**Honest assessment — wedge-2 pressure, not a kill:**

- RAMPART tests the **agent** (model/tool behavior), not the
  **enforcement layer**. It is PyRIT-as-pytest aimed at black-box
  agent discovery, not "attack our own governor." AGT's own
  BENCHMARKS.md **still disclaims an enforcement-layer ASR
  benchmark** — that wedge-2 line from wave-27 holds.
- BUT: the *habit* moat just lost exclusivity at the agent level.
  "Findings → reusable regression tests → CI/CD" is now a polished,
  Microsoft-distributed, pytest-native tool with distribution we
  will never match. Our wedge-2 B-as-method grade rested partly on
  "we attack our own governor is genuinely unusual." The *method*
  (battery habit) is now table stakes for agent testing; what
  remains genuinely unusual is the **target** (our own enforcement
  layer, not the model) plus the **corpus** (FINDINGS.md, 100+
  filed with reproductions/residuals) plus **neutral runs against
  competitors' governors** (D2: ours 14/18, AGT v5.0.0 3/18).
- Caveat worth keeping (winbuzzer): "Independent testing has not
  yet established the stronger speed or coverage claims." Don't
  grant them more than the evidence.
- Clarity is no overlap at all — design-stage tooling, not
  enforcement. Taxonomy input at most (failure-analysis structure).
- **Watch item (new, wedge-2-adjacent):** does Microsoft ever point
  RAMPART at the enforcement layer (AGT's own ACS/governor, or an
  "enforcement regression" profile)? If RAMPART gains an
  enforcement-layer profile, our technical lead shrinks to the
  corpus + D2 habit — and the corpus is only defensible while it
  keeps growing. **Not a trigger** (no enforcement target exists
  today); the kill triggers (competitor publishes an
  enforcement-layer battery; AGT adds adversarial eval to their
  benchmarks page) remain not fired.
- Action: RAMPART joins the probe-import candidate list alongside
  OpenART (wave-27 §8 trigger 4) — import shapes, never duplicate
  the framework. STOP S9 (never a standalone battery SKU) is
  *validated* by RAMPART: Microsoft gives the framework away; the
  asset was never going to be the harness.

## 2. Microsoft AGT — roadmap read (new since wave-36)

Public roadmap crawled this wave (last_reviewed 2026-05-19,
https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/docs/ROADMAP.md):

- **Current release: v3.7.0 (Public Preview).** Shipped: 14 Python
  core packages + 20+ framework integrations, 5 SDK languages,
  20+ integrations, 10 RFC 2119 specs / 992 conformance tests,
  25 ADRs, 13,000+ tests, unified CLI
  (`agt verify`, `agt red-team`, `agt doctor`, `agt lint-policy`),
  PromptDefense 12-vector evaluator, GHCR container images,
  GovernanceEventSink SPI, OTel-native audit backends.
- **Near-term:** policy hot-reload, **Cedar production support**,
  OPA/Rego hardening, multi-tenant isolation; Entra ID agent
  identity bridge, SPIFFE/SVID production guide, **ML-DSA-65
  (post-quantum) signing** production support; Helm v1.0, Grafana
  SRE dashboard, shadow AI discovery scanner; ISO 42001, EU AI Act
  Annex IV automation, SOC 2 export tooling.
- **Medium-term:** multi-agent delegation chain verification,
  economic scope limits (budget governance), constitutional
  constraint layer (community extension), behavior anomaly
  detection via trust scoring.
- **Long-term:** federated trust, formal verification, TPM/SGX
  hardware identity.

**What this means for us:**

- **Trigger 1 (durable queue / console) NOT FIRED — and now we
  know the whole roadmap.** No durable approval queue, no operator
  console, no delegation UX, no batch decide, no human-approval UX
  appears anywhere in near/medium/long-term. Their "approval" work
  is ADR-0030 hardening of the *synchronous interrupt* (action
  binding, restart-fail-closed) — still an interruption, not a
  queue. The wave-36 watch item (do the governed CLI packages add
  approval UX?) — re-checked: Claude Code installs via
  `/plugin marketplace add microsoft/agent-governance-toolkit` +
  `agt-governance@agent-governance-toolkit` plugin; the policy
  shape is `action: require_approval` (synchronous interrupt).
  **No approval UX found in the CLI packages.** Watch item stays
  open, trigger not fired.
- Cedar production support on their near-term roadmap is the D3
  watch closing: when it ships, three of our verified gaps close —
  already inside trigger 1's surface, no separate trigger needed.
- ML-DSA-65 + SPIFFE guide + hardware identity further narrow D4
  — but change nothing: the D4 niche was already "keys you can
  actually operate" (boring operational gaps: rotation-safe
  verification F19, fail-closed dev-key F73, enforced retention).
  STOP on signature racing stands (A15).
- "Constitutional constraint layer (community extension)"
  medium-term: watch, not a trigger; not ours to chase.
- Version-narrative note (honesty): NuGet/npm sit at 5.0.0
  (v5 monorepo alignment, 2026-06-25) while the roadmap names v3.7.0
  as current release and PyPI meta is still 4.1.0
  (third-party baseline, corroborating not primary). The ecosystem
  is sprawling across 5 languages and 3+ registries — their
  distribution advantage is real, but so is the version sprawl;
  our $0 story stays "one tree, one suite."
- CHANGELOG@HEAD is materially the wave-36 snapshot (TEE
  keystore, governed CLIs, sandbox scanner, Entra JWT, wire facets,
  credential injection, LangGraph v1.0 adapter, replay engine,
  ADR-0029) — no new wave-47-relevant items found on re-crawl.
- Repo: ~5.9k stars (up from ~4k wave-27 baseline — third-party
  baseline; direction only, not precision).

## 3. AWS — GA milestones, no new shapes (new since wave-36)

- **AgentCore Policy: GA since 2026-03-03 (8 regions).** Was
  "preview" in the wave-36 writeup — corrected. Third-party
  corroboration (not AWS-primary, treat as indicative):
  $0.000025/request pricing line. Still Cedar, still gateway-bound
  deterministic tool-call policy authored in natural language,
  still an **interruption, not a queue**: no durable pending
  state, no delegation, no operator console. **Trigger 2 NOT
  fired** — AWS still ships no approval product; AgentCore HITL
  remains "composed via HumanLayer or similar" per public docs.
- **Bedrock Guardrails GA inside AgentCore (2026-06-17, 5
  regions)** with itemized per-safeguard pricing ($0.15/1K text
  units content filters; $0.10 PII / contextual grounding). This is
  the *content* layer (prompt-attack detection, PII, denied
  topics), not action authorization — no wedge pressure. It does
  validate the shape our P1/P4 content close-outs would take as a
  managed API.
- **AgentCore Policy now supports Bedrock Guardrails in policy**
  (June 2026 release notes): outputs from authorized actions and
  gateway-target inputs evaluated for prompt injection, harmful
  content, sensitive data exposure — at the gateway, outside agent
  code. Still enforcement, not approval. D3 note: Cedar stays the
  policy surface — our fail-closed Cedar export remains the
  coherent portability story.
- Quality-loop GA (orthogonal to wedge-2): AgentCore Harness GA
  (define/run with no orchestration code), Batch Evaluations GA,
  Recommendations GA (production-trace-driven system-prompt
  suggestions) — agent *quality* eval, same orthogonality as
  wave-36's AgentCore Evaluations.
- Compliance-tier rollout as first-class: AgentCore in GovCloud
  (US-West) 2026-05-05; Gemma 4 in GovCloud 2026-07-30. Reinforces
  STOP S6 (compliance mappings belong to GRC vendors) — AWS treats
  compliance-tier availability as a rollout target, exactly the
  game we don't play.
- **Agent Toolkit for AWS** (GA 2026-05-06, free, build-time
  accelerator inside Claude Code): build-time, not runtime —
  adjacent to the governed-CLI line, not a queue.

Sources:
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/release-notes.html ·
https://tech-insider.org/aws-bedrock-agentcore-vs-azure-ai-foundry-vs-vertex-ai-agent-builder-2026/ ·
https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/03/CSA_research_note_bedrock_agentcore_enterprise_attack_surface_20260309-csa-styled.pdf ·
https://github.com/rishabhcli/zoovision/blob/HEAD/docs/sponsors/aws-bedrock-services.md (pricing line, third-party)

## 4. Wedge verdicts, updated (wave-47)

- **Wedge 1 (durable approval queue + web UX): still C — thin
  feature lead, not a moat.** Strengthened one notch by the clean
  roadmap read: AGT's *entire public roadmap* (near/medium/long)
  contains no queue or console; AWS has GA'd everything *except*
  an approval product. The one-deny-veto quorum and
  fatigue-anomaly console surfacing remain the sharpest
  in-wedge differentiators (design decisions a copyist leaves
  out). Runway still ~12–18 months, expiring not owned.
  Kill triggers: refined fire conditions stand (persistent store
  backend OR operator-facing queue UI; AWS native HITL product or
  HumanLayer acquisition). **Zero fired.**
- **Wedge 2 (adversarial eval battery): still B as method, D as
  standalone product — but pressure increased.** RAMPART is the
  first serious method-level adjacent artifact with real
  distribution. Honest re-grade of the moat: the *habit* (battery
  as CI/CD regression) is no longer unusual at the agent level;
  what stays unusual is (a) the enforcement-layer target (we
  attack our governor — RAMPART tests agents, AGT's benchmarks
  disclaim enforcement ASR), (b) the corpus (FINDINGS.md growth
  must not stall), (c) neutral D2 runs against competitors'
  governors. New watch: RAMPART gaining an enforcement-layer
  profile (not a trigger). RAMPART *validates* STOP S9: the
  framework is free from Microsoft — the battery was never going
  to be the product.

## 5. Stop-duplicating list, updated (wave-47)

| Area | Change since wave-36 |
|---|---|
| Pytest-native red-team framework | **New: DON'T build.** RAMPART exists (pytest + PyRIT + CI/CD). Import shapes as probe candidates; never duplicate the harness. Validates STOP S9. |
| Approval queue / console | Unchanged: BUILD (wedge 1, flagship). Clean roadmap read = no new threat. |
| Key management / TEE / PQ signing | Stays STOP (AGT roadmap adds ML-DSA-65 — narrows D4 further, no action change). Minimum: kill the dev-key fallback (F75 plan). |
| Sandbox filtered egress | Stays STOP (F81 accepted). |
| MCP scanner / constitutional layer | Stays DON'T duplicate; AGT's medium-term "constitutional constraint layer (community extension)" is watch-only. |
| Policy bundles / signed trust | Stays DON'T duplicate (ADR-0029). |
| Compliance mappings | Stays STOP — AWS's GovCloud-first rollout sequencing reinforces. |
| Policy engine / audit signatures / adapters / console enterprise hardening / battery SKU | All STOPs stand unchanged. |

## 6. What to build that they don't (wave-47 delta)

Unchanged: durable queue + delegation + quorum + fatigue UX
(flagship), battery-as-method, Cedar export, narrow key-lifecycle,
git-hygiene invariant probe (wave-36 addition). **One addition:**
RAMPART gives us an import source — adversarial *scenario shapes*
(PyRIT-converter-derived agent attacks) adapted as enforcement-layer
probes. Not a product, not a framework: probe import, the same lane
OpenART occupies. Recorded in the watch list, not on the build list.

**Bottom line for the user:** no triggers fired. AGT's full public
roadmap has no approval queue — wedge 1's C holds and the runway
read got cleaner. RAMPART is the first genuine pressure on the
battery-as-method story — it does agent-level red-teaming as CI/CD
regression better than we ever will, so the wedge-2 moat is now
explicitly the enforcement-layer target + the corpus + D2 neutral
runs, and the corpus must keep growing. Nothing in this wave changes
what to build or stop, only how honestly we describe the moat.

**Kill-trigger tally 2026-09-22 (wave-47): zero fired.** Trigger 1
refined (persistent store or queue UI — now roadmap-verified
absent); trigger 2 unchanged (AWS native HITL); trigger 3
(demand) tailwind, unchanged; trigger 4 (battery adjacency)
updated — RAMPART added as watch (enforcement-layer profile would
be the fire condition), OpenART/rein-ai/Mindgard unchanged.
