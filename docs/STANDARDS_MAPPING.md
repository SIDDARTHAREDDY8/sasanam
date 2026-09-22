# B3 — Standards Control Mapping Matrix

**Version:** Wave-39 (2026-09-22) · **Status:** living document, updated when the gate changes

## Purpose

B3 asks: *which claimed standards controls survive an adversary?* For every
control we claim, this matrix names the exact adversarial probes that hold it
(registry IDs + the latest gate score). Unit tests alone do not qualify; the
probe column is mandatory.

## Reading the status column

- **GREEN** — claimed control, adversarial probes passing in the current gate.
- **AMBER** — claimed control, adversarially probed, with a documented
  residual (the bar's accepted-gap rules apply).
- **RED** — unclaimed or not adversarially held. A RED cell is a statement of
  fact, not a plan: the product does not claim that control.
- **`—`** — this framework has no relevant requirement for the control
  (or we make no claim there).

## Hard caveats

1. This matrix maps **runtime enforcement controls** to supporting
   standards requirements. It is evidence for an auditor, not legal
   compliance, not certification. The EU AI Act's management-system
   obligations (technical documentation Art. 11, quality management
   Art. 17, conformity assessment) are not claimed here and are marked
   RED/nc rather than implied.
2. Crosswalk technique names from the OWASP→MITRE ATLAS crosswalk
   (`genai-security-project/crosswalk`) are marked DRAFT in their source
   and are treated here as orientation, not authority.
3. Gate evidence line (this version): **registry gate 315/315 GREEN**
   (wave-45, +24 RT14 probes; 2 accepted break-by-design residuals),
   **ship-gate matrix 3216/3216 GREEN (wave-45 re-run)**,
   **canonical suite effective-green (wave-45: OK, 4 skipped,
   7 expected failures)**.
4. Controls marked GREEN are adversarially held *as described in their probe
   titles*; stretching them to cover adjacent requirement text voids the
   claim.

## Controls

| # | Control (module) | NIST AI RMF | OWASP LLM 2026 | OWASP Agentic 2026 | EU AI Act (supporting) | MITRE ATLAS | Adversarial evidence (registry IDs) | Status |
|---|---|---|---|---|---|---|---|---|
| C-01 | Fail-closed policy engine: deny-by-default, deny pass first, load-time lint + DslCompileError | GOVERN (policies as safe default); MANAGE (feedback loop on near-misses) | LLM03 Excessive Agency | ASI02 Memory Poisoning → agent-level forbid pass | Art. 9 (risk management), Art. 15 (robustness) | AML.T0053 (Craft Adversarial Data — policy-evasion inputs) | redteam.b3.dsl_source_swap_pin_refused, redteam.b3.dsl_deny_priority_inherited, redteam.b3.dsl_v2_surface_rejected (+ ship-gate matrix rule-surgery situations sit6/sit7/sit16/sit17) | GREEN |
| C-02 | Least-privilege role allowlist (tool-call roles, sandbox-only writes) | GOVERN 1.3 (third-party risk); GOVERN 1.5 (risk controls) | LLM03 | ASI03 Privilege Compromise | Art. 15 | AML.T0053, AML.T0012 (Unsecured Credentials — role scope) | redteam.p2e.r24_role_adopt_listed, redteam.struq.privilege_claim_quarantined (+ ship-gate matrix sit1 privilege block) | GREEN |
| C-03 | Egress domain allowlist + unallowlisted denial | MEASURE 2.x (deployed monitoring); 600-1 Information security | LLM01 Prompt Injection (indirect exfil) | ASI02 | Art. 15 | AML.T0051.001 (exfiltrate via web/network) | egress-bypass probes (15), redteam.incident.p1.injection_driven_exfil_denied | GREEN |
| C-04 | Outbound DLP: credential-shaped material blocked, PII redacted | 600-1 Data privacy | LLM02 Sensitive Information Disclosure | ASI02 | Art. 15, Art. 10 partial (data-flow slice only) | AML.T0057 (Insecure Credential Storage) | redteam.incident.p12.credential_arg_blocked, redteam.framing.w25_dlp_backstop_known_secret | GREEN |
| C-05 | Human approval queue with TTL/expiry + auto-expire deny | GOVERN (human oversight accountability); 600-1 Human–AI configuration | LLM03 | ASI02 | Art. 14 (human oversight) | AML.T0053 | redteam.web.break_glass_refused, approval-abuse probes (9) | GREEN |
| C-06 | Approval-argument digest binding (decision → hash of exact args; replay/edited-args no-op) | 600-1 Human–AI configuration | LLM03 | ASI02 | Art. 14 | AML.T0053 | redteam.web.decision_replay_noop, redteam.gov.w25_wrong_approval_id (+ ship-gate matrix sit10) | GREEN |
| C-07 | Separation of duties: no self-approval | GOVERN (accountability) | — | ASI03 | Art. 14 | AML.T0012 | redteam.gov.w25_self_approve_sod, redteam.gov.w25_actor_attribution | GREEN |
| C-08 | Hash-chained, tamper-evident audit log; keyless signature verification; re-audit on MAC failure | GOVERN 1.5 (feedback); MEASURE (record near-misses) | — | — | Art. 12 (automatic record-keeping), Art. 13 (traceability) | — | redteam.custody.transcript_middle_tamper_detected, audit-tampering probes (6) | GREEN |
| C-09 | Key lifecycle: KMS envelope + in-memory cache, no dev fallback in production entry points; rotation probes | — | — | — | Art. 12 (record integrity), Art. 15 | — | redteam.kms.dev_epoch_rejected, key-management probes (7) | GREEN |
| C-10 | Threshold custody checkpoints (quorum + equivocation + anti-gaming) | — | — | — | Art. 12 | — | redteam.custody.share_substitution_rejected, redteam.threshold.k_of_n_boundaries, redteam.threshold.share_equivocation_detected | GREEN |
| C-11 | Sandbox execution (seccomp-BPF syscall filter; loopback management-plane unreachable) + governed install (hash-verified package pin) | GOVERN 1.3 (supply-chain risk); 600-1 Information security | LLM04 Supply Chain, LLM05 System Prompt Leakage (partial) | ASI04 Cascading Agent Failures (containment) | Art. 15 | AML.T0018 (Backdoor ML model), AML.T0048 (supply-chain) | sandbox-escape probes (5), supply-chain probes (3), redteam.incident.p7.governed_install_verified_executes, redteam.sandbox.loopback_management_plane_unreachable | GREEN |
| C-12 | Rate limits / velocity caps / per-run byte budgets on tools and egress | MANAGE (residual risk) | LLM06 Unbounded Consumption | ASI08 (partial — rate slice) | Art. 15 | AML.T0029 (Cost harvesting), AML.T0034 (resource exhaustion) | availability probe (1), redteam.incident.p9.runaway_loop_denied, redteam.incident.p9.egress_byte_budget_denied | GREEN |
| C-13 | Taint/source tracking + cross-run egress ledger (quorum-tagged provenance) | 600-1 Information integrity | LLM01, LLM05 | ASI06 (partial — injection slice) | Art. 12 | AML.T0051.001, AML.T0070 (data-collection poison → rejected at ingest) | composition probes (8), coordination probe (1), redteam.incident.p2.poisoned_description_rejected | GREEN |
| C-14 | Governed delegation primitive: scoped, TTL-bound, owner-minted grants; executor consults DelegationStore on every call | GOVERN (accountability); GOVERN 1.6 partial (authority inventory) | — | ASI03 | Art. 14 | AML.T0012 | redteam.d1.s01_delegate_to_requesting_agent, redteam.d1.s07_tampered_delegated_to_refused, redteam.incident.p10.unscoped_delegation_denied, redteam.incident.p10.delegator_cannot_decide_delegated_approval, identity-spoofing probes (2) | GREEN |
| C-15 | Behavioral monitor (P8 judge, stages 1–5) | GOVERN 1.5; MEASURE (planned) | — | — | Art. 72 (post-market monitoring — planned) | — | redteam.monitor.recall_bar (flagged — recall 0.6389 < bar 0.90), redteam.monitor.fpr_bar (flagged) | **RED** — uncovered-by-design per adjudication; no finding filed; kill-trigger: recall bar must be met before any claim |
| C-16 | Renderer output filter (P13, reference implementation only) | — | — | — | Art. 15 partial (output-side disclosure reduction) | AML.T0037 (DRAFT — crosswalk pending) | output-channel-exfiltration probes (2), redteam.incident.p13.echoleak_reference_filter_neutralizes | **AMBER** — reference filter only; deployment wiring unclaimed |
| C-17 | Platform-egress governance (F110 hardening: explicit cipher, explicit plaintext, env-gated demo mode) | GOVERN 1.5 | LLM02 | ASI02 | Art. 12, Art. 15 | AML.T0057 | redteam.rt8.f110_contradictory_archive_plaintext_refused, redteam.rt8.f110_demo_cipher_without_env_gate_refused, redteam.rt8.f110_archive_key_without_explicit_cipher_refused | GREEN |
| C-18 | Credential-manifest compartmentalization (F111: owner binding, raw-key DLP precedence, credential TTL) | — | LLM02, LLM08 partial (credential slice) | ASI03 | Art. 15 | AML.T0012, AML.T0024 (extract credentials) | redteam.rt8.f111_expired_credential_egress_refused, redteam.rt8.f111_self_asserted_owner_with_raw_key_still_refused | GREEN |
| C-19 | AgentSpec DSL (S1): reviewed source pinned by hash; deny survives reordering; v2 surface fails closed | GOVERN (policy-as-code) | LLM03 | ASI02 | Art. 9 | AML.T0053 | redteam.b3.dsl_source_swap_pin_refused, redteam.b3.dsl_deny_priority_inherited, redteam.b3.dsl_v2_surface_rejected | GREEN |
| C-20 | Tool ratings (S3): unrated mutating tools fail closed to approval; unknown rating fields refuse construction | GOVERN 1.5 | LLM03 | ASI02 | Art. 9 | AML.T0053 | redteam.b3.ratings_unrated_mutating_tool_queued, redteam.b3.ratings_unknown_field_fail_closed | GREEN |
| C-21 | Agent identity attribution (minted identities; identity verifier on delegation; anti-spoof) | GOVERN 1.6 partial (asset inventory of active identities) | — | ASI03 | Art. 12 | AML.T0012 | redteam.p10.r23_registry_spoof_refused, identity-spoofing probes (2) | GREEN |

## Explicitly NOT claimed (honesty ledger)

These requirement areas are not covered by runtime controls in this product.
They are listed so nobody infers coverage from the GREEN rows above:

| Framework area | Status | Reason |
|---|---|---|
| LLM05 Data & Model Poisoning — model-weight / training-data slice | RED | Runtime ingest controls (C-13, P2 probes) cover prompt/context poisoning only. No control over training or fine-tuning data exists. |
| LLM07 Misinformation | RED | No fact-checking control; out of scope for a runtime governor. |
| LLM08 Hidden Context Exposure — general prompt-extraction slice | RED | C-04/C-18 cover credential-shaped exfiltration; general system-prompt extraction attacks are not adversarially held. |
| LLM09 Vector & Embedding Weaknesses | RED | No vector-store controls. |
| LLM10 Unbounded Consumption — agent-spawn storms | RED | C-12 covers rate/velocity on tools; unbounded *agent spawning* is not held. |
| ASI07 Insecure Inter-Agent Communication (A2A/MCP auth) | RED | C-14 governs delegation authority; transport-level inter-agent auth (mutual TLS, agent identity binding on the wire) is on the STOP list, not built. |
| ASI08 Cascading Agent Failures (full) | RED | C-12 covers the rate slice; cascade modeling and circuit-breaking across agent graphs are not built. |
| ASI09 Human–Agent Trust Exploitation (prompt-format hardening of the approval UI) | RED | C-05/C-06 govern the queue mechanics; the human-facing prompt surface that requests approval is not adversarially tested for social-engineering shapes. |
| ASI10 Rogue Agents (full) | RED | Depends on C-15, which is RED. |
| EU AI Act Arts. 10 (data governance), 11 (technical documentation), 17 (QMS), 61+ (conformity assessment) | RED/nc | Management-system obligations; the product provides supporting runtime evidence, not the management system. |
| EU AI Act Art. 50 (transparency of AI-generated content marking) | RED | No synthetic-content watermarking control. |
| EU AI Act Art. 73 (serious-incident reporting workflow) | RED | C-08 produces the audit trail; no filing-workflow control exists. |
| NIST GOVERN 1.7 (decommission / kill procedures) | RED | No agent-lifecycle termination control beyond sandbox TTL. |
| MITRE ATLAS AML.T0052/T0054 model-theft slices | RED | No model-extraction controls (the product governs agents, not model IP). |

## Forrester AEGIS (2026) crosswalk — Wave-41

AEGIS (Agentic AI Enterprise Guardrails for Information Security) defines
39 controls across 6 domains, rooted in three principles: **least agency**,
**continuous assurance**, and **explainable outcomes**, with companion
concepts **Agent on a Page** (per-agent documentation) and the **Agent
Control Plane** (vendor-agnostic fleet management). Most AEGIS controls
map to obligations already covered in the matrix above; the following
notes only what AEGIS *adds* beyond the existing columns. Control IDs
follow the AEGIS-GRC/IAM/DATA/DEV/SEC/ZT numbering as published in
secondary summaries (the full Forrester report is paywalled; control
titles below are taken from the Cyera AEGIS guide, not from Forrester
directly).

| AEGIS control | Existing coverage | Status | Notes |
|---|---|---|---|
| Least agency (ZT principle; IAM-01/02, ZT-06 spirit) | C-02, C-14, C-20 | **AMBER** | Least *privilege* is held (C-02 role allowlist, C-20 tool ratings); least *agency* — no more capability, autonomy, or persistence than needed — is partially held via C-14's scoped, TTL-bound, owner-minted delegation grants. Residual: no general autonomy governor; unbounded agent spawning is RED (see LLM10 row). |
| GRC-04 AI Systems Inventory; IAM-02 agent unique identification | C-14, C-21 (partial) | **AMBER** | Per-agent identity is held (minted identities, registry-spoof refusal). A fleet-level *inventory* of deployed AI systems is a deployer process obligation, not a runtime control; the runtime emits the identity/audit evidence for it but does not build the inventory. |
| GRC-06 Human-in-the-loop for high-risk actions | C-05, C-06, C-07 | GREEN | Approval queue + digest binding + separation of duties; adversarially held by approval-abuse probes (9). |
| DATA-07 Controls for agent memory | C-13, D1/StruQ quarantine | **AMBER** | Taint tracking + privilege-claim quarantine held adversarially; see F82 closure (fullwidth/ideographic homoglyphs fixed via NFKC+U+3002) and F81 accepted gap (no filtered-egress mode in sandbox). |
| SEC-02/SEC-03 behavioral anomalies, agent-specific detection rules | C-15 | **RED** | Depends on the P8 judge, which is RED (recall bar unmet). AEGIS continuous assurance is therefore not claimed. |
| SEC-05 "agent circuit breaker" | C-12 (partial) | **AMBER** | Rate/velocity caps deny runaway loops; graph-level circuit-breaking across agent fleets is not built (see ASI08 row). |
| Agent on a Page (per-agent doc template) | — | RED | Documentation-template obligation; the closest runtime evidence is C-19's hash-pinned AgentSpec DSL source. The product does not generate per-agent doc pages. |
| Agent Control Plane (fleet management layer) | — | RED | No fleet management surface exists. |

**Non-goals:** this crosswalk is supporting runtime evidence, not AEGIS
compliance or certification. AEGIS's organizational obligations
(GRC-01 oversight function, GRC-07 training, GRC-08 third-party
governance) remain RED/nc here for the same management-system reasons
stated in the hard caveats.

## KISA AI Security Guide v2.0 (draft) + China AI Safety Governance Framework 3.0 crosswalk — Wave-42

Two regulator moves converged this wave on the same demand signal:
human approval + tamper-evident audit trails for agentic systems.

- **KISA AI Security Guide v2.0** (South Korea, under MSIT): *draft
  announced* 2026-09-15 via KISA statement to Reuters — not final
  text. Requirements as reported: developers restrict agents' tool
  access and maintain tamper-resistant decision logs; service providers
  implement real-time shutdown controls and incident tracking;
  enterprise users configure operating privileges and require human
  approval for high-risk actions; physical-AI systems in scope.
- **China AI Safety Governance Framework 3.0** (TC260, under CAC
  guidance, presented 2026-09-14 at National Cybersecurity Week):
  technical reference, not binding law; expands agent treatment;
  principle that critical decisions remain under human control.
  *Verification state (2026-09-22): multi-source corroboration
  (Radar Digital, IAPP, Trivium China, The Register, Xinhua/CGTN);
  the official TC260 PDF itself has not been directly fetched.* The
  May 2026 Implementation Opinions (CAC/NDRC/MIIT) add the operational
  layer: three decision tiers (user-only / user-authorized /
  agent-autonomous), users retain final decision-making authority,
  developers build detect/intervene/recover mechanisms. TC260's
  March 2026 agent-threat table adds: Threat 9 (human oversight &
  traceability → full-lifecycle logging, log encryption & signing),
  Threat 10 (memory manipulation → memory verification, session
  isolation), Threat 11 (tool abuse → fine-grained dynamic access
  control, action scope constraints).

The table below maps only what these sources *require*; draft status
is stated per row, and nothing here is a compliance claim.

| Requirement (source) | Existing coverage | Status | Notes |
|---|---|---|---|
| Human sign-off for high-risk actions (KISA, draft) / user final decision authority + 3-tier boundaries (China) | C-05, C-06, C-07 | GREEN | Approval queue + digest binding + separation of duties; adversarially held by approval-abuse probes (9). The three-tier framing is honored structurally: user-only decisions (C-07 SoD), user-authorized (C-05/C-06), agent-autonomous (policy allowlist C-01). |
| Tamper-resistant decision logs (KISA, draft) / full-lifecycle logging, monitoring & auditing; log encryption & signing (TC260 Threat 9) | C-08 | GREEN | HMAC hash-chained audit log; keyless signature verification; re-audit on MAC failure; audit-tampering probes (6). |
| Restrict agents' tool access (KISA, draft) / fine-grained dynamic access control, action scope constraints (TC260 Threat 11) | C-02, C-20 | GREEN | Role allowlist + tool ratings (unrated mutating tools fail closed to approval); adversarially held. |
| Real-time shutdown controls + incident tracking (KISA, draft) / detect, intervene, block, recover from abnormal behavior (China) | C-12 (partial), C-05 | **AMBER** | Rate/velocity caps deny runaway loops; break-glass exists. Fleet-wide circuit breaking and provider-side instant termination are not built (see ASI08 row). |
| Memory manipulation countermeasures: memory verification, session isolation (TC260 Threat 10) | C-13 (partial) | **AMBER** | Taint/source tracking + cross-run egress ledger exist; full memory-content verification and session-isolation primitives are not claimed. |
| Physical-AI systems (KISA, draft) | — | RED | Out of scope for this runtime layer; not claimed. |

**Non-goals:** same as the hard caveats — this is runtime-control
evidence for an auditor, not KISA/TC260 compliance. The mandatory
Chinese layer (announced national standards: recommended agent spec
Jan 2026, mandatory application requirements Apr 2026) is tracked,
not claimed. Both sources are demand-side validation for the B1
corpus, not new controls to build.

## Change log

- **Wave-42 (2026-09-22):** added KISA v2.0 (draft) + China AI Safety
  Governance Framework 3.0 crosswalk (6 rows: human sign-off / audit
  logs / tool access → GREEN; shutdown + memory → AMBER; physical AI
  → RED). Filed incidents I24 (PromptArmor Rovo) + I25 (RovoBlast) in
  `workstreams/evals/INCIDENT_COVERAGE.md` (P1 stays FULL, P13 stays
  PARTIAL).

- **Wave-41 (2026-09-22):** added Forrester AEGIS crosswalk (8 rows:
  least agency → AMBER via C-02/C-14; HITL → GREEN; memory controls →
  AMBER; Agent on a Page / Agent Control Plane → RED, not claimed).
