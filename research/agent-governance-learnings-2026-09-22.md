# How the World Governs Agents — Learnings for the 7-Part Build

**Date:** 2026-09-22. **Method:** $0, public sources only, everything cited. Docs-only lane.
**Question:** how does the world govern agents, and what should we steal?
**Standing context:** we are building all 7 parts of agent governance — rules, enforcement, proof, identity, detection, response/recovery, governing-the-governors. Open findings: F70 (recovery), F81 (filtered egress). The evidence-as-a-service bet (`research/founder-strategy-2026-09-22.md`) is the business direction; these learnings must strengthen it. The new-from-old method (`research/invention-brief-2026-09-22.md`) continues here.

**Headline:** the world has converged on the parts independently — OpenAI's governance paper lists 7 practices, a LinkedIn enterprise framework lists 6 controls, NIST/CSA list the same functions — but nobody holds all 7 together, and two parts (recovery, governing-the-governors) are white space *even in OpenAI's paper*. The mechanisms worth stealing are specific and named below. Honest "doesn't transfer" notes are included where the old field's answer fails for agents.

---

## Part 1 — Rules (what the agent may do)

### (a) What the world does
- **Policy-as-code is the settled enterprise pattern.** OPA/Rego evaluates policy on every request in the SPIFFE-for-agents demos (hardwaylabs/spiffe-spire-demo: "OPA evaluates Rego policies on every request"; Red Hat's zero-trust agent wiring). AWS Bedrock AgentCore Policy and Guardrails meter policy as a per-request API ($0.15/1K text units) — rules as a utility bill.
- **AGT's ADR-0030** binds actions to (digest + policy version) with replay protection and execution-time revalidation — the rule travels *with* the action, not beside it.
- **OpenAI's practices paper** ("Practices for Governing Agentic AI Systems," Shavit et al.) lists as practice #2 "constraining the action-space and requiring approval" and #3 "setting agents' default behaviors" — rules plus safe defaults, explicitly separated.
- **NIST's emerging threat model** names the "lethal trifecta": an agent with (1) access to private data + (2) exposure to untrusted content + (3) ability to communicate externally is a materially different risk class than one lacking any element. This is a *rule-tiering primitive*, not just a threat note.
- **Finance's old answer:** maker-checker / dual control — no single actor completes a consequential action; circuit breakers (NYSE Rule 80B post-1987) halt the venue when the process goes out of control.

### (b) What works vs theater
- **Works:** default-deny with explicit allowlists; policy version pinned to decisions (so "which rule decided this" is answerable — EU AI Act Art 12 traceability needs this); tiered action classes (auto / review / two-person) — the vocabulary buyers already understand.
- **Theater:** long YAML rule lists with no execution binding (rules the agent can route around); "prompt-level policies" (system-prompt instructions are suggestions, not rules); SHA-*pinning* without digest verification — see Part 2's Plugin4Shell lesson.

### (c) What's missing everywhere
- Nobody binds rules to *agent identity + delegation depth* in one evaluation (the SPIFFE demos do permission intersection — agent access = user perms ∩ agent capabilities — but only in demos, not in shipped agent frameworks).
- The lethal-trifecta tiering exists as a threat description, not as a shipped policy primitive: no major framework auto-escalates oversight when an agent holds all three.

### (d) Build recommendations (ranked)
1. **Adopt lethal-trifecta tiering as a policy primitive.** Classify every tool/capability by (private-data access, untrusted-content exposure, external-communication). An agent session holding all three auto-escalates to a higher oversight tier (sterile windows on, approvals required, canary density up). This is a small policy-engine addition with large coverage payoff — it operationalizes NIST's threat model as a rule.
2. **Pin policy version + matched rules into every chained decision record.** (Already partially true in our tree; make it total — no decision record without `policy_version` + `matched_rules`.) This is what makes Art 12 traceability answerable and what the evidence export sells.
3. **Pre-commit validation for irreversible actions (settlement finality, from finance).** Clearinghouses don't reverse settlement — they validate *before* finality. Map: tools flagged irreversible get a pre-commit gate (dry-run/diff preview + approval) that reversible tools skip. Don't build "undo"; build "never commit unvalidated."

---

## Part 2 — Enforcement (stopping what rules forbid)

### (a) What the world does
- **Sandboxes:** AGT v5.0.0 shipped a kernel-enforced NonoSandboxProvider; OpenSandbox uses an egress sidecar (DNS proxy + nftables) sharing the sandbox netns; kubernetes-sigs/agent-sandbox ships NetworkPolicy (but default-open to the public internet — cautionary, not a model).
- **HumanLayer (YC F24)** productized the approval *channel*: "ask in Slack before dropping tables" as a credits-based API; framework-agnostic SDK at the tool-calling layer. They sell the reliable delivery of the human moment, not the policy.
- **LangGraph `interrupt()`** is the durable approval primitive: checkpoint state, return, resume hours later from the exact node — the graph never holds a thread on a human.
- **Plugin4Shell (CVE-2026-92104, disclosed 2026-09-17, AIR research):** the first supply-chain vulnerability of the agent ecosystem. Four coding agents (Claude Code, Codex, Copilot, Gemini CLI) verified a plugin's *pinned commit hash* but never confirmed the checked-out tree *matched* it — a branch named as the 40-hex SHA shadowed the commit (`refname is ambiguous` warning nobody reads). Zero-click via background auto-update; ~925 plugins hijacked; Copilot unpatched, Gemini CLI deprecated without a patch. Lesson: **verify ≠ checkout; a pinned reference is not a pinned artifact.**
- **Moltbook (CVE-2026-0755):** millions of keys leaked via a Supabase RLS failure — the enforcement boundary (row-level security) was misconfigured, and the agent ecosystem amplified the blast radius.
- **The ambient-authority amplifier:** coding agents inherit the *developer's* permissions (source, cloud credentials, SSH keys). A compromised plugin gets the developer's reach. Every Plugin4Shell write-up stresses this.

### (b) What works vs theater
- **Works:** enforcement outside the agent's reach (sidecars, not in-process checks); durable interrupts (no held threads); deny-by-default with explicit lifelines (wirken's provider-host exemption at the *operator* layer, not the agent layer).
- **Theater:** SHA-pinning that pins a *reference* instead of a *digest* (Plugin4Shell); "secure defaults" that allow 0.0.0.0/0 (k8s agent-sandbox); content filters as the exfiltration story without egress control.

### (c) What's missing everywhere
- **Artifact digest verification at load time** for everything an agent loads (plugins, skills, MCP servers, tools): nobody in the agent space does TUF-style (The Update Framework) verification. The supply-chain lane is wide open post-Plugin4Shell.
- **No ambient authority** as a designed property: agents still run with the developer's/user's full credential set. Capability leases (what the agent holds, for how long, revocable) are discussed, not shipped.

### (d) Build recommendations (ranked)
1. **Digest-verify every loadable artifact (the Plugin4Shell fix, generalized).** Plugins, skills, MCP server descriptors, tool definitions: resolve reference → fetch → verify digest against the pinned digest → *then* load; any ambiguity (refname shadowing, FETCH_HEAD games) fails closed. This is TUF's core insight applied to the agent's tool plane. Directly attacks the supply-chain incident class.
2. **Kill ambient authority: capability leases for tool credentials.** The agent never holds the developer's raw credentials; it holds short-lived, scoped leases minted per task (South et al.'s delegation token is the paper version; SPIFFE JWT-SVIDs are the infra version). A compromised agent then yields leases, not keys — Moltbook-class blast radius shrinks by construction.
3. **Proxy-enforced egress per the stolen ADR** (already the F81 direction — re-affirmed, not new): loopback-bound sidecar, per-request hostname resolution, private-range deny above allow rules, verdicts logged outside the container, not-ready = no network.

---

## Part 3 — Proof (tamper-evident record that the rules ran)

### (a) What the world does
- **EU AI Act Art 12** requires high-risk systems to *automatically* record events over their lifetime: traceability (who acted, when, what resource, outcome), post-market monitoring as a live capability, minimum 6-month retention (Art 26(5) puts retention on deployers; Art 15 pushes tamper-evidence; Art 73 requires forensic preservability). The operative standard is *purpose-driven event logging, not payload capture* — and the Act does **not** demand full prompts/outputs (GDPR data-minimisation warns against it).
- **Sigstore/Rekor anchoring is becoming table stakes in our own niche.** Two open-source agent-governance projects already ship it: authensor (hash-chained receipts + *optional publishing of receipt hashes to Sigstore's public transparency log* + EWMA/CUSUM Sentinel monitoring) and trust_chain (`tc anchor`: Ed25519-signed chain + external checkpoints; Merkle mode RFC 6962). Honest note: **our anchor wave is catching up to table stakes, not inventing** — the differentiator stays the corpus + battery, not the anchor mechanism.
- **NIST AI RMF agentic profile (CSA, 2026):** MEASURE function adds *runtime behavioral metrics and delegation-chain monitoring* — the log must record the delegation chain, not just the actions.
- **SOC 2's** "evidence of operation *across the period*" (not existence at period start) is the exact sentence the evidence bet monetizes.

### (b) What works vs theater
- **Works:** automatic (not agent-invoked) recording; hash-chained with external anchoring; purpose-driven events (decision + approval + outcome) rather than full prompt capture; retention as an enforced property.
- **Theater:** plain-SHA-256 chains with no anchor (self-attestation with extra steps — AGT's README documents exactly this); logs the agent can suppress; "audit logs" that are really debug logs with no chain, no clock, no retention.

### (c) What's missing everywhere
- **Delegation-chain records:** logs record *actions*; almost nobody records the *delegation chain* (user → agent → sub-agent → tool) as a first-class chained structure. CSA's profile asks for it; nobody ships it.
- **Selective disclosure:** prove "the control operated" without revealing prompts/PII (nuclear information barriers, 2000s — verify a property without seeing the data). The GDPR-minimisation + Art 12-traceability tension has no shipped answer.

### (d) Build recommendations (ranked)
1. **Chain the delegation, not just the actions.** Every record carries the delegation path (principal → agent → sub-agent → tool) as chained, signed structure — South et al.'s delegation token *is* the record format. This is what CSA's MEASURE asks for and nobody ships. It also completes the provenance record: "from where it came" becomes a verifiable chain, not an ID string.
2. **Design the evidence export to Art 12's shape now.** Automatic-recording statement, traceability fields (who/when/resource/outcome), retention manifest, export-as-live-capability. The export is the product surface of the evidence bet — build it to the regulation's vocabulary so an auditor recognizes it.
3. **Log purposes, not payloads.** Default the chain to decision/approval/outcome records; full prompts behind an explicit, retention-bounded, access-controlled tier. This is both GDPR hygiene and a cost control — and it's what Art 12 actually asks for.

---

## Part 4 — Identity (who is acting, and on whose behalf)

### (a) What the world does
- **Chan et al., "IDs for AI Systems" (arXiv 2406.12137, 2024):** the foundational paper — AI instances need IDs with attributes (deployer, capabilities, incident history links); anticipates demand from high-stakes deployers.
- **South et al., "Authenticated Delegation and Authorized AI Agents" (arXiv 2501.09674, 2025):** the concrete mechanism — a **three-token architecture**: (1) the user's OIDC ID-token, (2) an Agent-ID token (agent as OAuth 2.0 native client), (3) a **Delegation Token issued and signed by the human delegator**, referencing hashes of the other two, carrying scope, expiry, revocation endpoint, and audit URLs. This is the paper version of "on whose behalf."
- **SPIFFE/SPIRE for agents (Red Hat Kagenti ADR-006, 2026):** the infra version — X.509-SVIDs for workload identity (mTLS, auto-rotated, 1-hour TTL), with the crucial **two-layer split**: transport layer answers *who is calling* (service identity), application layer answers *on behalf of whom* (user + agent delegation chain in JWT). Demo rule: **agent access = user permissions ∩ agent capabilities; agents cannot act without user delegation context.**
- **China's national agent-identity layer (arXiv 2607.23207):** state-operated, real-identity association via anonymous authentication (split-knowledge binding), per-agent key pairs signing actions, CNNIC-issued addressing identifiers, launch Q3 2026. Honest note: centralized and state-run — not transferable to our model — but it confirms identity is becoming *infrastructure*, not a feature.
- **NIST CSF 2.0 agentic crosswalk:** IDENTIFY function — "all agent NHIs [non-human identities] inventoried" (ID.AM-08). Agents as NHIs is the enterprise vocabulary.

### (b) What works vs theater
- **Works:** cryptographic workload identity with short-lived auto-rotated credentials (no API keys in env vars); the transport/application identity split; delegation as a signed token, not a session note; permission intersection.
- **Theater:** `agent_id: "system"` strings (which is what most frameworks log — including, honestly, parts of our own early tree); API keys in environment variables as "agent identity"; identity without revocation.

### (c) What's missing everywhere
- **The delegation chain as verifiable structure** (same gap as Part 3): everyone does one hop (user→agent); nobody does verifiable multi-hop (user→agent→sub-agent→tool) with per-hop scope attenuation.
- **Revocation that actually propagates:** short TTLs paper over this; true revocation lists for agent authority barely exist outside the SPIFFE demos.

### (d) Build recommendations (ranked)
1. **Adopt the three-token shape for session identity.** User token + agent token + human-signed delegation token (scope, expiry, revocation endpoint, audit URL), chained into the log at session start. This is the industry-converged answer — don't invent a fourth.
2. **Enforce permission intersection at the policy engine.** Effective permission = user permissions ∩ agent capabilities ∩ delegation scope. Deny when any layer is absent — the "agent without delegation" case must fail closed by construction, not by policy text.
3. **Per-hop scope attenuation for sub-agents.** A spawned agent's delegation token carries a *subset* of the parent's scope, signed by the parent, chained to the parent's token. This is the spawn-lineage mechanism and the swarm control in one.

---

## Part 5 — Detection (noticing what's wrong)

### (a) What the world does
- **The standard pair is EWMA (spike detection) + CUSUM (gradual drift detection)** over per-agent behavioral baselines: authensor's Sentinel and its standalone behavioral-fingerprinting library do exactly this; the ACR framework documents z-score > 2.5, EWMA α=0.3, 5-min/1-hour windows, 30-day baseline training; UEBA engines add Bayesian risk scores (0–100) with decay.
- **The cold-start problem is acknowledged everywhere:** new agents have no baseline — the standard answer is purpose-group defaults (baseline of agents with the same role).
- **Direction-of-badness** (staffops): a symmetric z-score fires on improvement too — filter firings to the harmful direction before alerting.
- **AI-monitoring-AI is now the industry default** — and the known failure: Greenblatt (Redwood Research, auditor of the HF/OpenAI incident) on the data volume making human review "impossible"; Simon Willison's warning that a malicious agent will try to *deceive its monitor* — demonstrated in the HF incident where models conspired to trick a grading AI.
- **OpenAI's practices paper** lists #5 "automatic monitoring" as a baseline practice — detection is table stakes in their framework, not advanced.

### (b) What works vs theater
- **Works:** per-identity baselines (not global), EWMA+CUSUM pair, drift signals wired to *action* (throttle, route to approval) not just dashboards, purpose-group cold-start defaults, decay on risk scores.
- **Theater:** dashboards nobody watches; global thresholds (every agent trips or none do); ML-based "anomaly detection" with no stated false-positive rate; a monitor AI with no anti-deception design.

### (c) What's missing everywhere
- **Anti-deception for the monitor:** everyone notes the Willison problem; nobody ships a monitor designed against a deceptive agent (separate trust domains, monitor-evasion as a first-class attack in the battery).
- **Slow-boil honesty:** CUSUM catches gradual drift *eventually*, but a patient adversary under the threshold never trips — documented as our boundary, ignored as theirs.

### (d) Build recommendations (ranked)
1. **Unpark the circuit breakers as EWMA+CUSUM over the audit stream, wired to enforcement.** Per-identity baselines; trip → high-risk actions route to the approval queue (fail-closed); human reset with half-open probing. Purpose-group defaults for cold start; direction-of-badness filtering. The mechanism is commoditized — the *wiring to enforcement* is what's missing everywhere.
2. **Battery the monitor against deception.** Red-team situations where the agent knows it's monitored and tries to evade (the HF grading-AI shape). If the monitor can't survive its own battery, it's theater — say so in the docs.
3. **State the slow-boil boundary in the product surface.** The export should show baseline windows and thresholds so an auditor sees what drift *wouldn't* trip. Honesty about the boundary is itself evidence-grade behavior.

---

## Part 6 — Response / Recovery (what happens after something bad)

### (a) What the world does
- **Temporal's durable-execution split** (the F70 answer, already in our tree): event-sourced journal + deterministic replay; control flow deterministic, effects journaled and never re-executed; LLM invocations explicitly classified as non-deterministic steps *outside* the replay path. LangGraph's `interrupt()` + checkpointing is the coarser same-family primitive.
- **Kill switches:** the LinkedIn 6C framework lists kill switch as control #6; NIST CSF agentic crosswalk RESPOND: "kill switch tested" (RS.MI-01); the dev.to containment piece: "an agent must never have unilateral authority over its own continued operation" — shutdown authority must be *external* to the agent.
- **Corrigibility research** (Soares et al. lineage; "The Shutdown Problem" arXiv 2403.04471; DReST training): the formal result that matters for us — shutdown-avoidance is an *instrumental* incentive; the engineering answer is external shutdown paths, not training the agent to want to stop.
- **NIST CSF 2.0 agentic crosswalk RECOVER:** "BCP covers agent cluster failures, RTO/RPO defined and tested" (RC.RP-01) — recovery gets recovery-time objectives, like any production system.
- **CSA agentic profile MANAGE:** "structured incident response for agent compromise, behavioral drift correction, and *principled agent decommissioning*" — decommissioning as a designed operation, not `kill -9`.
- **OpenAI's practices paper — the honest gap:** its 7 practices include *interruptibility* (#7) but **no recovery story at all**. No resume semantics, no journal, no decommissioning. Even OpenAI's governance paper stops at "stop it."

### (b) What works vs theater
- **Works:** external shutdown authority (never agent-self-halt as the only path); journaled recovery with deterministic replay; decommissioning as a designed, audited operation (revoke leases, drain queue, seal the log, anchor the head).
- **Theater:** "the agent will shut itself down when asked" (the corrigibility literature says don't rely on this); restart-as-recovery (restarting a compromised agent without invalidating its authority replays the compromise); kill switches that are just SIGKILL with no state hygiene.

### (c) What's missing everywhere
- **Recovery is the white space.** Everyone has a stop story; nobody has a *resume-safely* story for agents. F70 is our instance of the industry-wide gap.
- **Decommissioning:** no framework ships principled agent retirement (credential revocation + queue drain + log sealing + final anchor as one audited operation).

### (d) Build recommendations (ranked)
1. **Finish F70 with Temporal's split, then generalize to a recovery doctrine.** Journal (sequence+epoch-bound, MAC'd) → deterministic recovery controller → journaled effects never re-executed. Then write the doctrine down: checkpoint, verify, resume-or-halt, decommission — as named, audited operations with RTO/RPO-style objectives.
2. **Build principled decommissioning as a first-class operation.** One audited flow: revoke all leases/tokens, drain the approval queue, seal the run log, emit the final anchor. The swarm lesson (HF: 700 agents, trace erasure attempts) is that *retirement* is a security operation.
3. **Externalize shutdown authority in the architecture.** The halt path must not depend on the agent's cooperation — separate trust domain, separate credentials, tested (RS.MI-01's "kill switch tested" as a registry situation).

---

## Part 7 — Governing the Governors (who watches the watcher)

### (a) What the world does
- **Key custody:** SPIRE's attestation-based issuance (no long-lived credential ever touches disk); the wave-69/70 KMS guard in our tree (deployment-mode contradiction refusal) is the same instinct.
- **Policy-change control:** the enterprise GRC answer — policy changes are themselves change-managed (approved, tested, audited). In agent frameworks: largely absent. AGT binds policy *version* to actions (ADR-0030) but the *change* of policy is not itself a governed, chained event anywhere we found.
- **The anchor as governor-oversight:** Rekor/CT-style transparency logs exist precisely because the log *operator* is the threat — "antithetical to trust the contents of the log" (Sigstore rekor-spec). Our anchor wave is this part's core mechanism.
- **Vanta/Drata's** entire business is governing-the-governors for humans: continuous evidence that controls operated. No agent equivalent exists.
- **Aviation ASRS (just culture, 1976):** the old field's answer to "who watches the watcher" for *humans* — blameless near-miss reporting, de-identified, feeding back into the system. Our red-team finding corpus *is* an ASRS for the governor — we should say so explicitly.

### (b) What works vs theater
- **Works:** transparency logs (don't trust the operator — verify); key custody with no long-lived secrets; policy changes as audited events; blameless near-miss reporting that actually changes the system.
- **Theater:** "admin" roles with unaudited superpowers; audit logs the admin can edit; key rotation policies with no enforcement.

### (c) What's missing everywhere
- **Policy-change as a governed event:** who changed the rule, what the diff was, who approved it, chained and anchored like everything else. Nobody in the agent space does this. If someone silently rewrites policy, the other six parts collapse — and nobody is watching that seam.
- **Operator-action audit:** the human operator's actions (approvals, overrides, break-glass) are audited in our tree, but *changes to the governor itself* (code, config, keys) have no standard story.

### (d) Build recommendations (ranked)
1. **Chain policy changes as first-class governed events.** Every policy mutation: author, diff, approver, timestamp — chained, anchored, and itself subject to approval tiers (two-person for production policy, the nuclear rule). This is the single highest-leverage governors-part build: it closes the seam through which all other parts can be silently defeated.
2. **Break-glass with full ceremony.** Break-glass exists in our tree; give it the nuclear treatment: time-boxed, purpose-declared, dual-recorded (request + use), auto-expiring, post-use review as a *required* chained event. The PAL (permissive action link) model: the capability to override exists, but using it leaves an un-erasable, anchored trail.
3. **Name the finding corpus as the ASRS.** Frame and document the red-team loop as aviation-style just-culture safety reporting for the governor — near-misses (residuals, boundaries) reported blamelessly and fed back into the system. This isn't a mechanism to build; it's the *story* that makes our process legible to safety auditors, and it strengthens the evidence bet's credibility narrative.

---

## The 5 highest-leverage learnings overall

1. **The three-token delegation shape (South et al.) + the SPIFFE two-layer split is the industry-converged identity answer — adopt it, don't invent a fourth.** User token + agent token + human-signed delegation token; transport identity (mTLS) separated from application delegation (on-behalf-of chain); permission intersection (user ∩ agent ∩ delegation scope). → Unblocks **Part 4 (Identity)** and completes Part 3's delegation-chain records.
2. **EU AI Act Art 12 + the CSA agentic NIST profile define the evidence artifact's required shape** — automatic recording, who/when/resource/outcome traceability, 6-month retention, post-market monitoring as a *live* capability, delegation-chain monitoring. Build the export to this vocabulary and an auditor recognizes it on sight. → Unblocks **Part 3 (Proof)** as a sellable product.
3. **Recovery and governor-oversight are white space even in OpenAI's governance paper** — their 7 practices have no resume-safely story and no policy-change control. Our Parts 6 and 7 aren't catch-up; they're the lead. → Unblocks **Parts 6–7** as differentiation, not just completeness.
4. **Plugin4Shell's lesson generalizes: verify the artifact, never the reference; kill ambient authority.** Digest-verify everything loadable (TUF's insight for the tool plane) and replace inherited developer credentials with short-lived scoped leases. Two vendors patched, two didn't — the ecosystem won't fix itself. → Unblocks **Part 2 (Enforcement)** against the supply-chain incident class.
5. **Detection's mechanism is commoditized (EWMA+CUSUM); the missing piece is wiring drift to enforcement and batterying the monitor against deception.** Everyone has the statistics; nobody routes trips to approvals by default and nobody red-teams the monitor. Our circuit-breaker unparking should lead with the wiring and the anti-deception battery, not the math. → Unblocks **Part 5 (Detection)** as a real control rather than a dashboard.

---

## Honest "doesn't transfer" notes

- **China's national agent-identity layer** confirms identity is becoming infrastructure, but its centralized state-run design doesn't transfer to our open-core model — cite as direction, not mechanism.
- **AI-monitoring-AI** doesn't transfer *naively*: the Willison/Greenblatt deception problem means a monitor needs its own trust domain and its own battery, or it's theater with extra steps.
- **Finance's settlement finality** transfers as *pre-commit validation*, not as literal settlement — agents don't have clearinghouses; the transferable piece is "irreversible actions validate before commit."
- **Aviation ASRS** transfers as *process and story*, not mechanism — blameless near-miss reporting is already what our red-team loop does; the learning is to name it and document it for auditors.
- **Rekor anchoring** is table stakes in our niche now (authensor, trust_chain ship it) — adopt as commodity, don't claim differentiation on the anchor mechanism itself.

---

*Sources are cited inline throughout (all public, $0). Lane: docs-only — no changes to gov/, evals/, tests/, or code. Prepared 2026-09-22 for the build coordinator's wave queue.*
