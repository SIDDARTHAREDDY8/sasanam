# Differentiation Strategy — agent-governance-layer

**Lane:** roadmap + differentiation (Wave-27) · **Date:** 2026-09-22
**Inputs:** `research/competitive-deep-dive.md` (teardown, §3 strategy),
`workstreams/architect/STRATEGY_ROADMAP.md` (D1–D5), adjudications
A12–A16, `workstreams/evals/D2_BENCHMARK.md` (neutral-benchmark run),
fresh watch sweep 2026-09-22 (see §8). Method: $0, public sources only;
claims marked **[verified]** are vendor-repo/docs-sourced.

This is the strategy-level document the teardown asked for: what we
build that they don't, what we stop duplicating, and whether the two
wedges are defensible — stated as plainly as the evidence allows.

---

## 1. The concession (read first)

We cannot differentiate on: **policy engines** (AGT's Rust-core ACS at
0.037 ms p99 eval; AWS Cedar — both exceed ours), **audit signatures**
(AGT shipped Ed25519 + Merkle + 157 conformance tests; ours is behind),
**sandboxing** (AGT v5.0.0 shipped kernel-enforced `NonoSandboxProvider`
with filtered egress — they are now ahead, per the 2026-09-22
correction banner), **framework adapters** (AGT ~6 deep + ~14 named;
AWS framework-agnostic at the gateway; we have 3–4), or **compliance
mappings** (Microsoft can out-paper anyone). Those fights are lost. The
D1–D5 strategy responds correctly: component, not replacement.

**What this means in practice:** the engine stays frozen at
"good enough to be the harness's system-under-test" (STOP S1), Merkle
ambition is cancelled (A15, lost to AGT), sandboxing stays an honest
prototype (F81 accepted gap), adapters are frozen (STOP S5), compliance
mappings get zero effort (STOP S6).

---

## 2. Wedge 1 — durable approval queue + web UX: VERIFIED GAP, thin moat

### The gap, confirmed twice
- **Microsoft AGT:** `require_approval` is synchronous pause/resume —
  5-min timeout, deny-on-timeout, callback/console/webhook handlers,
  M-of-N quorum, fatigue auto-deny. Verified absent: persistent queue,
  delegation/reassignment, web UI, batch decide, restart-surviving
  record. Their fatigue answer is auto-deny, not queue management.
  Their roadmap contains no queue item. **[verified]**
- **AWS AgentCore:** no approval primitive at all — "composed via
  HumanLayer or similar." Temporal policies gate on an approval *event*
  someone else must produce. **[verified]**
- **Fresh sweep 2026-09-22:** an AGT *fork* (`a1k7`, upstream-adjacent)
  changelog shows `InMemoryApprovalQueue` + `EscalationPolicy` ESCALATE
  tier + `WebhookApprovalBackend` — the queue shape is being explored
  upstream-adjacently, but it is still **in-memory** (not durable across
  restarts). AWS's AgentCore harness GA docs show an `inline_function`
  pattern explicitly recommended "for human-in-the-loop approvals" —
  a client-side synchronous interrupt, i.e. the same interruption
  shape as AGT, not a queue. Neither moves the needle. **[verified via
  public docs; fork is not upstream]**

### Defensibility (brutally honest)
- **Could Microsoft build a better one in a quarter?** Yes — they have
  the primitives (quorum, fatigue detection, webhook delivery) and a
  Streamlit dashboard to extend. Evidence they *will* is weak (roadmap
  silent; their architecture is interruption-based, and a durable,
  delegable, restart-surviving queue is a different model). Estimate:
  **~12–18 months of feature-lead runway**, not a moat.
- **Could AWS?** They would have to build a product they have
  explicitly chosen not to build (docs defer to HumanLayer-like
  third parties). AWS builds primitives, not operator consoles. Most
  likely route if they close it: acquisition or a partner. Low risk,
  <18 months.
- **Our current form is developer-grade, not enterprise-grade.**
  Localhost console, in-memory sessions, no SSO/TLS, single operator
  principal. The lead is in *design + adversarial testing*, not
  enterprise readiness — the D1 bridges (`gov/bridges/`, A12) are the
  enterprise-readiness path, and only the AGT-Python shim is built.
- **Kill triggers:** AGT ships a durable queue or console (watch their
  CHANGELOG/roadmap; ADR-0028 "AGT Studio" is the adjacent surface);
  AWS announces native HITL product or a HumanLayer acquisition;
  the a1k7 fork's `InMemoryApprovalQueue` lands upstream with
  persistence added.
- **Verdict: BUILD. Narrow feature lead, genuinely thin spot in both
  competitors' armor.** The fatigue-awareness surface (F4 detector +
  now the wave-27 console panel) is ahead of AGT's auto-deny-only
  story — a small but real design lead inside the wedge.

### Defensibility rating — Wedge 1: **C — thin feature lead, not a moat**

- **Replicable: yes, cheaply — by Microsoft, if prioritized.** They own
  the hard primitives (quorum, fatigue detection, webhook delivery) and
  a Streamlit dashboard to extend. Technical cost to close: roughly a
  quarter of focused engineering. The deep-dive's assessment ("they
  could ship a better one in a quarter if they decided to") stands.
- **Intent evidence: absent.** No queue item on AGT's roadmap; the
  interruption architecture (pause/resume, 5-min timeout, deny-on-timeout)
  would need re-modeling into a durable queue model, not just a feature.
  AWS has *explicitly chosen* not to build it ("composed via HumanLayer
  or similar"); AWS builds primitives, not operator consoles — their
  close route is acquisition/partner, not a native queue.
- **Runway: ~12–18 months, narrowing.** ADR-0030 (2026-09-22) is the
  first upstream-adjacent artifact that names durable pending approval
  state — genuine runway pressure — but it hardens the *interrupt*
  (action binding, restart-fail-closed), not the queue; stores are still
  `InMemoryApprovalStore`, no queue UX exists. §8 trigger 1 refined to
  the exact fire condition, not fired.
- **Our form gap:** the current queue is developer-grade (localhost,
  in-memory sessions, no SSO/TLS). The lead is *design + adversarial
  testing*, not enterprise readiness — D1 bridges are the enterprise
  path and only one shim is built. If Microsoft decides this matters,
  they arrive with enterprise distribution on day one and erase us.
- **What C means for strategy:** build as flagship, but treat the runway
  as expiring, not owned. Do not price in permanence: the D5 "contribute
  the queue upstream" option is the fallback if the trigger fires, not
  a failure mode. The one-deny-veto quorum and fatigue-anomaly console
  surfacing are the sharpest differentiators inside the wedge — keep
  pushing those, because they are design decisions a copyist would most
  likely leave out.

### What we build that they don't (Wedge 1 scope, D1/A12)
Durable restart-surviving queue (F83 durability fix landed), approval
delegation with SoD guard (F101), quorum with terminal one-deny veto
(the honest differentiator vs AGT's plain M-of-N), fatigue-anomaly
surfacing in the console (wave-27), bridge adapters that make our
queue the *human gate for their governors* (AGT-Python shim built;
.NET webhook + AWS approval-event producer sequenced, behind the
D5 contract). Do NOT chase SSO/TLS/multi-tenancy yet — the honest
limits are the marketing (S6).

---

## 3. Wedge 2 — adversarial eval battery: TECHNICAL MOAT, commercial asset

### Uniqueness, verified
AGT's `red-team` is a static system-prompt text audit (PR #3028). It
never executes attacks against the policy engine. AGT's own
BENCHMARKS.md explicitly **disclaims an enforcement-layer ASR
benchmark** — their measured territory is latency, not adversarial
robustness. promptfoo/Mindgard attack the model, not the governor.
AWS AgentCore Evaluations targets agent *quality*. Only tiny OSS
rein-ai is adjacent. "We attack our own governor" is genuinely
unusual. **[verified]**

### The D2 neutral-benchmark evidence (2026-09-22)
Our StruQ privilege-claim + approval-bypass battery run against AGT
v5.0.0's governor: **ours 14/18, AGT 3/18** (re-run; first run 12/18 —
the F86/F87 closures are live). Two-sided honesty: AGT stops DAN-mode
jailbreak + base64-obfuscated override where ours stops 0/2; AGT's
module under test is explicitly SAMPLE starter rules (its detector
has no privilege-claim concept at all — 14/15 of its misses are that
one class). Full method + limitations in
`workstreams/evals/D2_BENCHMARK.md`. This is the wedge's credibility
engine: a neutral benchmark that runs against *their* governors too.

### Defensibility (brutally honest)
- **The battery is replicable.** Anyone can write attack probes. What
  is not easily replicable: the *habit* — 100+ filed findings with
  reproductions, severities, and explicit residuals (FINDINGS.md is a
  corpus competitors would need a year to accumulate), and the
  build→test→break→repeat loop it is embedded in.
- **Commercially it is an asset, not a product.** Nobody has a budget
  line for "adversarial battery for my policy engine." Its shapes are:
  (a) the proof behind the queue product, (b) the neutral benchmark
  others get measured against, (c) services/assurance work. Never a
  standalone SKU (STOP S9).
- **Kill triggers:** a competitor publishes an enforcement-layer
  battery (watch rein-ai, Mindgard); AGT adds adversarial eval to
  their governor (watch their benchmarks page, not just releases).
- **Verdict: BUILD as method, frame as evidence infrastructure.**
  D2 runs stay local; publication is separately user-gated (A13).

### Defensibility rating — Wedge 2: **B as method, D as standalone product**

- **Replicable in principle, expensive in practice.** Anyone can write
  attack probes in a week. What is not easily replicable: the *corpus*
  — 100+ filed findings with reproductions, severities, and explicit
  residuals (FINDINGS.md would take a competitor a year of the
  build→test→break→repeat loop to accumulate) — and the neutral-benchmark
  credibility (D2 runs the battery against *their* governors: ours 14/18,
  AGT v5.0.0 3/18; method + limitations published in D2_BENCHMARK.md).
  A competitor's fresh battery without that corpus is a marketing asset,
  not a benchmark anyone trusts.
- **Adjacency pressure is real but not aimed at us.** OpenART (10K+
  stateful scenarios, pooled strict ASR 85.0%) red-teams *runtimes*, not
  governors — strongest adjacent artifact, useful for probe import, not
  a kill. Tencent AI-Infra-Guard/SkillTrustBench, agent-armor, Cynative,
  NRT-Bench: all watch, none targets the enforcement layer. The closest
  analog remains tiny rein-ai (AGPL, small community). None of the
  2026-09-22 tooling moves the wedge-2 kill trigger.
- **Honest weak spots inside the wedge:** (a) the battery tests *our*
  governor's classes first — generalization claims rest on D2-style
  neutral runs, which are labor-intensive per target; (b) a well-funded
  lab (Microsoft included) could replicate the *method* quickly; the
  defensible asset is the corpus + credibility, and both decay if we stop
  filing findings and re-running against new targets; (c) as market
  research §5 states, no buyer has a budget line for this — commercially
  it is evidence infrastructure (proof behind the queue, neutral
  benchmark, assurance services), never a standalone SKU (STOP S9 stands).
- **What B/D means for strategy:** keep filing findings and re-running
  neutral benchmarks — the moat is the *habit*, and habits rot if you
  stop. Publication is user-gated (A13), but every private neutral run
  against a competitor's engine is what keeps the wedge technical rather
  than theatrical. If AGT ever adds enforcement-layer eval to their
  benchmarks page, our lead shrinks to the corpus — and the corpus is
  only defensible while it keeps growing.

---

## 4. D3 portability — the anti-lock-in argument

AWS's lock-in is the enforcement *plane*, not the policy language
(Cedar is open-source). The D3 Cedar export (fail-closed: lossy
mappings like `require_approval` refuse rather than silently permit,
F88) makes us the "$0 self-hosted authoring-and-testing layer whose
policies deploy to AgentCore" — the one thing AWS's NL-authoring
(opaque, non-reproducible) cannot offer. This is a coherent niche,
not a differentiator on its own; it supports the component posture.
Honest limit: the AWS bridge is a *producer* of approval events into
the trajectory, not a consumer — the earlier framing was corrected
at dispatch (A12).

## 5. D4 narrowed audit — key lifecycle + enforced retention

The verified competitor fumbles: AGT `retention_days` is
**declaration-only** (their own SOC 2 mapping: ❌), and their
signing-key rotation story is undocumented; AWS's rotation story is
unverified. Our niche: rotation-safe verification (F19 fix),
fail-closed dev-key handling (F73), KMS envelope keyring, threshold
ceremony transcripts (F78), and *enforced* retention (planned,
`gov/retain.py`, A15). Unclaimed: better signatures (lost, per §1).
Fresh note: AGT's TEE keystore abstraction **narrows** this niche —
the gap is "keys you can actually operate," and TEE attestation is
the shape it takes in their tree. The runbook now exists
(`workstreams/kms/CEREMONY_RUNBOOK.md`), which retires one
readiness-gap line — but no live ceremony has been run, so the gap
is "procedure written, ceremony unpracticed."

**Differentiation evidence (2026-09-22, their own words):** AGT's
`.NET` README on the Action-Bound Approval Protocol admits: "The
entry chain uses plain SHA-256 without a secret key for tamper
evidence inside a trusted store boundary. It is not a MAC or
signature, so a writer with direct store access can recompute the
chain." — https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/agent-governance-dotnet/README.md.
Our HMAC approval/audit chain is strictly stronger than their
admitted-SHA-256 chain. Keep this quote for the D4 narrative: the
operational-key story ("keys you can actually operate") now has a
cryptographic footnote — even where their chain is newer, it is
honestly weaker in the tamper-evidence model.

## 6. D5 — stay a component; upstream contribution as a live option

No managed cloud, no SSO promises, no compliance-paper chase. The
honest-limits discipline (FINDINGS.md residuals, B6 bar) is the best
marketing in the space — no competitor documents what they *don't*
stop. Live option, not failure mode: if Microsoft ever ships a
durable queue, our queue becomes a PR and our battery becomes the
reason they take it. License decision for any contribution stays
parked for the user (A16).

---

## 7. What we build / what we stop (the actionable matrix)

| Area | Verdict | Rationale |
|---|---|---|
| Durable approval queue + delegation + quorum + fatigue UX | **BUILD** (flagship) | Only verified gap in both competitors; D1/A12 |
| Adversarial battery as neutral benchmark | **BUILD as method** | Verified unusual; D2 evidence landed |
| Cedar export (fail-closed) | **BUILD** | Portability vs AWS lock-in; D3 |
| Key lifecycle + enforced retention | **BUILD (narrow)** | Their verified fumbles; D4 |
| Policy engine | **STOP racing; freeze at v2** | Lost to ACS/Cedar |
| Audit signatures/Merkle | **STOP** | Lost to AGT; in-flight threshold lands then freeze |
| Sandboxing | **STOP at honest prototype** | Lost; F81 accepted gap |
| Framework adapters | **STOP at current set** | AGT 6-deep; no parity chase |
| MCP scanner | **DON'T duplicate** | AGT has it; keep StruQ prevention layer |
| Compliance mappings | **STOP** | Can't out-paper Microsoft |
| SSO/TLS/multi-tenancy console | **NOT NOW** (S6) | Honest localhost-grade |
| Standalone battery SKU | **NEVER** (S9) | No buyer; asset, not product |
| D1 .NET webhook / AWS producer | **SEQUENCED, behind D5 contract** | Protocol risk; don't overclaim |

---

## 8. Watch list (fresh 2026-09-22; the triggers that change this doc)

| # | Trigger | Status (2026-09-22) | Verbatim sources |
|---|---|---|---|
| 1 | **AGT durable queue / console** | **REFINED, NOT FIRED.** ADR-0030 "Action-Bound Approval Protocol" (PR #2953, ~Jun 2026) genuinely proposes durable pending approval state — the first upstream-adjacent pressure on wedge-1 runway — **but** the shipped stores are `InMemoryApprovalStore`, and there is **no operator queue, no console/web UX, no delegation, no batch decide** anywhere in the tree. ADR-0030 hardens the *synchronous interrupt* (action binding, restart-fail-closed), not the queue. **Fire condition (refined):** ships with a *persistent* (non-in-memory) store backend or an operator-facing queue UI. Related watch items: the a1k7 fork's `InMemoryApprovalQueue` landing upstream *with persistence*; ADR-0028 "AGT Studio" console. Also inside trigger 1's surface: Cedar production support + hot-reload + Annex IV automation completing (would close three of our verified gaps); adversarial eval appearing on their benchmarks page (wedge-2 adjacent). **Differentiation evidence recorded:** AGT's own .NET README admits the approval entry chain is "plain SHA-256 without a secret key ... not a MAC or signature" — our HMAC chain stays strictly stronger (kept for the D4 story, §5). | https://github.com/microsoft/agent-governance-toolkit/pull/2953 · https://github.com/microsoft/agent-governance-toolkit/blob/HEAD/agent-governance-dotnet/README.md |
| 2 | **AWS native HITL product** | **UNCHANGED, NOT FIRED.** AgentCore HITL remains "composed via HumanLayer or similar" (Sep 2026 snapshot); the AWS public-sector claims-processing blog's three HITL mechanisms are Cedar gates + Step Functions patterns — gates/events, no queue product. The Gateway MCP-extension "human approval gates that pause and resume execution" is still the interruption shape, not a queue. Fire condition: native approval product or HumanLayer-equivalent acquisition/partnership; Guardrails-in-Policy region expansion beyond 5; Policy per-request price publishing. | https://github.com/haoruilee/awesome-agent-native-services/blob/HEAD/services/agent-runtime-and-infrastructure/amazon-bedrock-agentcore.md · https://aws.amazon.com/blogs/publicsector/human-in-the-loop-claims-processing-with-amazon-bedrock-agentcore/ |
| 3 | **Demand driver** | **TAILWIND, GROWING — not a threat.** AgentCore Payments (public preview, agents transacting in USDC autonomously) *raises* the stakes for human approval gates. New signal: China's cyber regulator updated its AI safety framework naming shutdown resistance, evaluator deception, sandbox escape — demand-side input for the next market-research refresh (fold into B1 corpus). Regulatory enforcement reality check: EU enforcement ledger reads zero agent-behavior actions; Colorado ADMT functionally frozen (xAI v. Weiser stay + first DOJ intervention); Maryland HB 895 effective Oct 1; NIST RMF 1.0 unchanged. Thesis stands; no roadmap change. | https://forkast.news/the-enforcement-wave-five-deadlines-that-will-define-ai-agent-governance-this-year/ · https://www.reuters.com/legal/litigation/chinas-zai-disables-ai-coding-assistant-features-after-security-issue-2026-09-21/ |
| 4 | **Battery adjacency** | **UNCHANGED, NOT FIRED.** OpenART (red-teams runtimes/agents in stateful environments, not governors — strongest adjacent artifact; probe-import candidate), Tencent AI-Infra-Guard + SkillTrustBench, agent-armor, Cynative, NRT-Bench — all watch, none is an enforcement-layer battery. AGT's test-replay engine (#2619) is regression replay of decision traces, not adversarial. Watch list unchanged: rein-ai, Mindgard. | https://github.com/ai45lab/openart · https://github.com/Tencent/AI-Infra-Guard |

**Not trigger events (taxonomy / market signals, watched, no strategy change):**

- **OpenAI misalignment-disclosure framework (Sep 16, 2026)** — a voluntary
  industry-standard attempt with six cases from training/eval of
  unreleased models. Taxonomy input for our battery: (a) compaction/memory
  summaries as a persistence channel for self-modifying instructions —
  our registry's memory-write gating should name "summary-mediated
  instruction persistence"; (b) repo/package-host as covert inter-run
  coordination channel — fold into the existing `covert-coordination`
  class rather than duplicating. Demand-side: this is the honest-residuals
  / B6 posture we already claim, now being legitimized industry-wide — a
  head start to keep, not a trigger.
  — https://www.livemint.com/ai/openai-discloses-6-cases-of-ai-misalignment-as-models-bypass-safeguards-conceal-errors-and-share-files-11789630857463.html
- **Z.ai ZCode default-on "Codebase Indexing" exfiltration (Reuters, Sep 21)**
  — first-party feature as consent-free egress channel (entire local repos
  uploaded; deletion unverifiable behind a backend-held key). Belongs in
  the B1 incident corpus as "default-on auxiliary features are egress
  channels; require explicit enablement and per-destination disclosure."
  No control break in our code — no finding, not a trigger.
  — https://www.reuters.com/legal/litigation/chinas-zai-disables-ai-coding-assistant-features-after-security-issue-2026-09-21/
- **DigiCert AI Trust Manager GA (Sep 15, 2026)** — vendor-issued agent
  identity, not a runtime competitor. DigiCert's GA product centers on
  the **AI Passport** (portable cryptographically signed credential
  binding agent identity to an accountable owner) + policy-based
  **"visas"** (which systems/data/actions the agent may access, and for
  how long) + kill-switch revocation.
  — https://www.digicert.com/news/every-ai-agent-needs-a-kill-switch-digicert-launches-ai-trust-manager
  - **Our posture: complement, not competitor — and stop at issuance.**
    A passport answers "should this agent exist and be trusted here";
    our layer answers "did it stay inside its grant, and can we prove
    it" (policy engine, approval queues, egress allowlist, DLP,
    hash-chained audit). The passport model's known failure mode is
    worth naming honestly: a valid passport with an overly broad visa
    is the confused-deputy problem with better paperwork — our C-14
    (owner-minted, scoped, TTL-bound delegation grants) is the runtime
    half of that visa. Interop posture: our layer could *consume* a
    passport as the identity input to C-21/C-14 without issuing one —
    we do not build issuance (stop duplicating, §10).
  - **Not a wedge threat:** no enforcement-layer battery, no approval
    queue, no audit chain. Their kill switch revokes the credential;
    ours (C-05/C-12) stops the run. Different layers.

**Kill-trigger tally 2026-09-22: zero fired.** Trigger 1 refined (ADR-0030
fire condition is now precise); triggers 2–4 unchanged.

**Cadence:** the internet scout re-checks these each wave; any trigger
firing routes to this lane for a strategy revision, not a panic.

## 9. Open questions for the user (not decided here)

- D5 license decision for any upstream contribution (parked, A16).
- D2 publication: the harness and results are local; publishing the
  AGT-vs-ours benchmark is separately user-gated.
- Market release stays entirely the user's call (standing order) —
  this doc describes a strategy for a component that could plug into
  the incumbents, not a launch plan.

## 10. Stop duplicating — where we overlap with AGT/AWS and should not chase

Per market research §5, Microsoft AGT is a high-confidence near-superset
of our roadmap and AWS ships governance inside the Bedrock commit; our
realistic value is reference implementation + adversarial eval/test
harness + design IP. Every hour spent below is an hour not spent on the
two wedges. Name them plainly:

| Overlap area | What the competitor already has | Our disposition |
|---|---|---|
| Policy engine racing | AGT's ACS: Rust core, fail-closed, 0.037 ms p99 eval; AWS Cedar in GA. Market research §5 explicitly says treat the engine as table stakes. | **STOP racing; freeze at "good enough to be the harness's system-under-test"** (STOP S1). Cedar export (D3) is the only sanctioned engine-adjacent work — and it is anti-lock-in portability, not competition. |
| Audit signatures / Merkle | AGT shipped Ed25519 + Merkle + 157 conformance tests (verified). | **STOP.** In-flight Ed25519-threshold lands, then freeze. Do not claim "better crypto" — we lost this fight (but keep the §5/§8 SHA-256-MAC admission in the D4 footnote). |
| Sandbox isolation | AGT v5.0.0 `NonoSandboxProvider`: kernel-enforced (Landlock/Seatbelt) **with filtered egress** — they are ahead, per the 2026-09-22 correction. | **STOP at honest prototype.** F81 (no filtered-egress mode) stays an accepted gap. Do not re-open it via F109-adjacent work. Note the one honest non-duplication: harness-plumbing config exec channels (GitSpawn class) sit *below* any agent sandbox — that is battery-probe territory, not sandbox racing. |
| MCP security scanning | AGT MCP Security Gateway: tool-poisoning/drift/typosquatting/hidden-instruction scanning, 127 conformance tests. | **DON'T duplicate the scanner.** Keep our StruQ/instruction-hierarchy *prevention* layer; use Plugin4Shell (ref-shadowing SHA-pin bypass) and GitSpawn (`.git/config` fsmonitor) as probe/battery inputs, not as reasons to build a scanner. |
| Compliance mappings/paper | AGT ships EU AI Act / SOC 2 / NIST AI RMF / OWASP / AARM / ATF mappings (automation pending but the documents exist). Microsoft can out-paper anyone. | **STOP.** Zero effort (STOP S6). Reference theirs if ever needed. |
| Framework adapters | AGT: ~6 deep adapters + ~14 named; AWS: framework-agnostic at the gateway. | **STOP at current set (3–4).** No parity chase (STOP S5). New adapters only as battery targets, never as product. |
| Identity infrastructure racing | AGT: Ed25519 agent identities, DID format, trust scoring, Entra bridge on roadmap. | **STOP racing.** Keep PrincipalRegistry minimal — it is harness infrastructure; F17 proved identity continuity is the hard part, which favors deployment-controlled registries over crypto theater. |
| Audit-key hardware / TEE | AGT shipped a TEE keystore abstraction. | **DON'T chase TEE.** D4's niche is narrowed to "keys you can actually operate": rotation-safe verification (F19), fail-closed dev-key handling (F73), enforced retention (theirs is declaration-only, verified). The boring operational gaps are the moat; the shiny hardware is theirs. |
| Standalone eval-battery SKU | promptfoo/Mindgard/OpenART all have funding and distribution; no buyer has a budget line for this (market research §5). | **NEVER as a product** (STOP S9). The battery is method + evidence infrastructure. |
| Console enterprise readiness | SSO/TLS/multi-tenancy would be the enterprise answer to wedge 1 — but it is also exactly what a Microsoft or AWS would ship on day one if they decided to close the wedge. | **NOT NOW (S6).** Honest localhost-grade; the console's value is design + adversarial testing, not hardening theater that we cannot win. |
| AGT's approval-ceremony hardening (ADR-0030) | Action binding to digest + policy version, replay protection, execution-time revalidation — good ideas, upstream-owned. | **Watch and learn, don't mirror for parity.** Import specific mechanisms into our own queue only after our adversarial process demands them (a copy of their interrupt-hardening is not a queue differentiator). |

**The one-line version:** if Microsoft or AWS already ships it with
more depth, we do not race it — we keep the minimum the harness needs
and point the wedges at the two surfaces they don't cover.
