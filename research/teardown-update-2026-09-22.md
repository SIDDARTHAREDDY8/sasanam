# Competitive Teardown Update — 2026-09-22 (wave-36)

**Lane:** competitive teardown (user-committed, standing). **Method:** $0,
public sources only, crawled 2026-09-22. Builds on
`research/differentiation-strategy.md` (wave-27) — read that first for
the base verdicts. This update records only what CHANGED since wave-27
and what it does to the wedge verdicts and the stop-duplicating list.

## 1. Microsoft AGT — what's new (CHANGELOG crawled 2026-09-18)

- **Governed CLI packages for OpenCode, Antigravity CLI, and Claude
  Code** (`@microsoft/agent-governance-*`, #2658/#2554/#2457) — AGT is
  shipping governance INTO the coding-agent CLIs themselves. These are
  exactly the tools GitSpawn hit (Sep 1-2). **This is the biggest new
  wedge-1 pressure:** if the governed CLI packages grow their own
  approval UX, the "our queue is the human gate for their governors"
  bridge thesis (D1/A12) loses its best insertion point. Watch item:
  whether these packages stay SDK-level policy enforcement or add
  human-approval UX.
- **TEE keystore abstraction** — `TEEKeyHandle`, `SoftwareKeyHandle`,
  `LocalTEEKeyStore` (ADR-0010 PR 3, #2735). They moved on production
  key management; our F75 (dev-key fallback still live) gap widens.
  Verdict: **the key-management fight is now definitively lost** —
  do the minimum (kill the dev-key fallback), never build TEE.
- **Sandbox subprocess code scanner + OpenShell interception**
  (#2705/#2704) — they now inspect code-execution paths before
  launch. Our F81 (no filtered-egress mode in sandbox) accepted gap
  looks worse by comparison; it stays accepted (sandboxing is a lost
  fight, STOP stands).
- **Entra-signed JWT verification for AgentMesh** (#2659/#2719);
  **wire-protocol-aware policy evaluation** (SQL/K8s facets) across
  TS/Rust/Go/.NET (#2553...); **credential injection/offload** across
  all SDKs (#2481/#2535); **credential redaction expansion** (#2737).
  All engine-hardening in territory we already conceded (STOP S1).
- **LangGraph v1.0 governance adapter + stale-auth fingerprinting**
  (#2694) — adapters we will never chase (STOP S5).
- **AGT test replay engine** (#2619) — policy regression replay of
  captured decision traces. Wedge-2 adjacent but NOT adversarial: it
  replays known decisions, it does not attack the governor. Kill
  trigger for wedge-2 (enforcement-layer adversarial eval) still not
  fired.
- **ADR-0029 policy distribution:** signed `trust.yaml`, policy
  bundles, Ed25519 publisher keys, transparency log, SBOM-in-bundle.
  Their supply-chain story now matches our P7 posture upstream — P7
  stays FULL, no action; we were never differentiated here.
- **MCP plugin governance** (v2.3.0: server allowlist/blocklist,
  trust tiers) — matches our F109 territory; we keep the StruQ
  prevention layer (don't duplicate their scanner), they have no
  listing-churn equivalent — ours stays a small honest edge, not a
  wedge.
- **Still pre-GA:** "Public Preview ... production-quality but may
  have breaking changes before GA." The entire competitive field is
  pre-GA — that is our runway context, not our moat.

## 2. AWS Bedrock — what's new

- **AgentCore Policy (preview):** deterministic, rules-based
  guardrails on tool calls, authored in natural language
  (e.g. "credit > $100 → a human agent steps in"). It sits OUTSIDE
  the agent loop — but it is an *interruption*, not a queue: no
  durable pending state, no delegation, no operator console. Wedge-1
  trigger 1 (durable store or queue UI) **still not fired**.
- **InvokeGuardrailChecks API:** per-step, resourceless, detect-only
  safeguards with numeric severity/confidence scores (content
  filters, prompt-attack detection, PII) callable at any point in
  the agent loop. This is the *content* layer, not action
  authorization — no wedge pressure. It is, however, the shape our
  P1/P4 close-outs would take as a managed API; fine as validation,
  not as competition.
- **Archer Evolv AI Compliance (Sep 15):** GRC obligations compiled
  to Bedrock Guardrails as policy-as-code, deployed in-customer-account,
  every control traced to its obligation. This is compliance-mappings
  **as a product** — and it validates STOP S6: that game belongs to
  GRC vendors with regulatory-intelligence assets (Archer: 492
  purpose-built models since 2017), not to us. Zero effort stays zero.
- **AgentCore Identity:** agent-aware IAM, user-on-behalf-of +
  agent-as-principal. The identity primitive space our F101
  delegation-with-SoD touches at the queue layer only — we do not
  compete on identity. Unchanged.
- **AgentCore Evaluations (preview):** agent *quality* eval —
  orthogonal to wedge-2 (adversarial enforcement eval). No pressure.

## 3. Wedge verdicts, updated

- **Wedge 1 (durable approval queue + web UX): still C — thin
  feature lead, not a moat. Runway pressure increased one notch.**
  The governed-CLI packages are the first AGT artifact aimed at the
  exact insertion point our D1 bridge strategy assumed was empty
  (coding-agent CLIs). Trigger 1 (persistent store or queue UI)
  remains NOT FIRED — nothing in the tree is a durable queue or an
  operator console — but the watch list gains a new line: *do the
  governed CLI packages add human-approval UX?* If yes, wedge-1's
  bridge thesis needs re-scoping to deployments AGT doesn't wrap.
  The fatigue-anomaly console surfacing and one-deny-veto quorum
  remain the sharpest in-wedge differentiators (design decisions a
  copyist leaves out).
- **Wedge 2 (adversarial eval battery): still B as method, D as
  standalone product.** The replay engine is the closest new thing
  and it is not adversarial. The corpus keeps growing (F109 closed
  wave-36 with listing-churn; P13 reference filter pinned; GitSpawn
  invariant probe registered). The decay warning from wave-27
  stands: the wedge is the *habit*, and the habit is healthy this
  wave.

## 4. Stop-duplicating list, updated

| Area | Change since wave-27 |
|---|---|
| Key management / TEE | **New: STOP, definitively.** AGT's TEE keystore ends any ambition here. Minimum viable: kill the dev-key fallback (F75 plan), keep the KMS envelope keyring + ceremony runbook as the "keys you can actually operate" story. |
| Governed coding-agent CLIs | **New: DON'T chase.** AGT ships them; we bridge to them (D1) or cede the surface. Never build our own CLI wrappers. |
| Sandbox filtered egress | Stays STOP (F81 accepted). Their scanner widens the gap; conceding it explicitly is cheaper than a losing chase. |
| MCP scanner | Stays DON'T duplicate (keep StruQ prevention layer + our listing-churn edge). |
| Policy bundles / signed trust | **New: DON'T duplicate.** ADR-0029 covers it upstream; our GovSig acceptance is sufficient. |
| Compliance mappings | Stays STOP — Archer Evolv proves it's a GRC-vendor game. |
| Policy engine / audit signatures / adapters / SSO console / battery SKU | All STOPs from wave-27 stand unchanged. |

## 5. What to build that they don't (unchanged + one addition)

Unchanged: durable queue + delegation + quorum + fatigue UX
(flagship), battery-as-method, Cedar export, narrow key-lifecycle.
**One addition from this sweep:** the GitSpawn class proved the
"trusted-dependency execution path" is where coding-agent governance
is actually failing in the wild — and AGT's governed CLIs are their
answer. Our honest, differentiated answer is the *deployment-side*
invariant: §5.7 git hygiene + the executable repo invariant probe
(`redteam.supplychain.gitspawn_no_git_subprocess_in_repo`, wave-36).
Nobody else pins "your tooling has no unguarded git call sites" as
a gated check. It is small, but it is ours and it is true.

**Bottom line for the user:** both competitors are still pre-GA and
still building the engine layer; neither has a durable approval
queue, an operator console, or an enforcement-layer adversarial
battery. The wedges hold at C and B/D. The new risk is AGT's
governed CLI packages growing approval UX — watch it monthly. The
new concession is key management (TEE) — stop there, do the minimum.
