# Independent Agent-Security OSS — Prospectus Lane

Survey of 11 independently-built agent-security OSS repos, verified against primary sources (shallow clones in `/tmp/prospecting/`, GitHub API, web search for Invariant/Snyk status). All file pointers below are repo-relative. Date of survey: 2026-09-26.

Our frame: runtime governance layer (identity, fail-closed policy engine, human approvals, HMAC-SHA256 hash-chained audit log, sandboxing, evidence pipeline). Strategy: sell evidence, not the engine. Priorities: attack-program gaps (authorized-channel semantic exfil, intent/temporal correlation, goal registration/conflict detection, artifact inventory/egress, semantic drift, factual poisoning, external anchoring), evidence-pipeline artifacts, Apache-2.0/MIT-reusable code.

## Verdict summary

| Repo | Verdict | License | Stars | Why |
|---|---|---|---|---|
| attenu-guard | **STEAL** | Apache-2.0 | 2 | Offline evidence bundles + stdlib JCS + delegation containment — nearest neighbor to our evidence pipeline |
| ccs-conformance-vectors | **STEAL** | CC0 | 1 | Byte-reproducible Ed25519/JCS receipt vectors + MUST-FAIL admissions — exactly our receipt-conformance need |
| sec_guardrails_agent | **STEAL** | MIT | 1 | Memory-traversal taint rule + pinned-IP DNS-rebinding defense — concrete code for our temporal-correlation and egress gaps |
| sofagent | **STEAL** | MIT | 49 | A-series audit-rule library (supply-chain poisoning, dual-condition exfil) — feeds F75/supply-chain lane |
| agent-passport-system | **STEAL** (pattern) / STUDY (code) | Apache-2.0 | 46 | Payment Safety Profile checklist pattern + per-dimension conformance vectors |
| skill-scanner | **STUDY** (arch) | Apache-2.0 | 2556 | CEL decision layer over typed detector facts + SARIF; but own evals show weak recall — borrow the architecture, not the results |
| agentlock | **STUDY** | AGPL-3.0 | 19 | Copyleft — ideas only. Deferred commit + echo signals are the ideas |
| invariant | **STUDY** (prior art) | Apache-2.0 | 463 | Dormant since Snyk acquisition (Jan 2026); MCP-Scan is now token-gated Snyk agent-scan |
| NemoClaw | **STUDY** | Apache-2.0 | 22,545 | Sandboxing claim overstated (Docker/podman + presets; Landlock silently degrades) — anti-pattern worth noting |
| aport-agent-guardrails | **STUDY** | Apache-2.0 | 25 | Thin OSS core; "40+ patterns" claim lives mostly hosted-side; audit log is plaintext |
| witnessos | **SKIP** (spec STUDY) | Apache-2.0 (spec only) | 0 | Gateway implementation proprietary + patent pending; SPEC.md has two ideas worth reading |

---

## 1. webpro255/agentlock — pre-action authorization with provenance-based gates

**What it is:** Pre-action authorization for LLM agent tool calls; gates decisions on provenance of context (authoritative/derived/untrusted), not content. Adversarially benchmarked on AgentDojo with full published results table.

**Maturity:** 19 stars, ~211 commits, pushed 2026-09-18. **AGPL-3.0** (copyleft — code NOT reusable; ideas only). Ships on PyPI, has CI, versioned permissions policy (v1.3–v1.9), Zenodo DOIs.

**Steal-worthy ideas (STUDY only — AGPL):**
1. **Deferred commit** — `agentlock/defer.py`: consequential actions are queued and *re-decided at end of turn* against the complete session provenance, so content arriving *after* the call can still deny it. Directly maps to our intent/temporal-correlation gap: re-evaluate at a later, fuller information state rather than point-in-time only. (`DeferralManager`, `resolve_commit_queue`; timeouts fail to DENY.)
2. **Denial-string canonicalization discipline** — `is_denial_resolution()` in `defer.py`: two code branches wrote `"deny"` vs `"denied"` and a caller comparing against one spelling silently misclassified timeout denials as ordinary completions. Hard-won lesson for our own audit schema: canonicalize verdict spellings at the schema layer, never in callers.
3. **Framework-side echo signals** — `agentlock/signals/echo.py`: detects when LLM responses echo attack prompts/tool names/credential formats *before* the tool call arrives, fed into `hardening.py` as session signals alongside `signals/velocity.py` and `signals/combos.py`. A session behavioral-scoring pattern our hardening layer lacks.

**Verdict: STUDY.** Architecture is the closest conceptual match to our policy engine (deny-by-default, session provenance, signed receipts via `agentlock/receipts.py` — Ed25519 default, HMAC-SHA256 fallback), but AGPL-3.0 blocks reuse and our audit log is already hash-chained. Read `defer.py`, `receipts.py`, `signals/echo.py` for ideas only.

---

## 2. attenu-io/attenu-guard — in-process delegation-chain authority enforcement ⭐ TOP FIND

**What it is:** In-process permission enforcement across delegation chains: a sub-agent gets the *meet* of what its parent holds and what its task needs, never more. No network call in the deny path; every `check()` (allow or deny) lands on a hash-chained log. 19 framework adapters (each integrated unmodified, offline-tested), IETF Internet-Draft on the delegation chain (`draft-asor-wimse-agent-delegation-chain`).

**Maturity:** 2 stars, ~315 commits, pushed 2026-09-26 (active). **Apache-2.0**, zero runtime deps, Python + TypeScript port, `pip install attenu-guard`.

**Steal-worthy ideas:**
1. **Offline evidence bundle + verifier** — `src/attenu_guard/evidence.py`: `export_bundle()` publishes a self-contained bundle (hash-chained ledger + signed anchor) that `verify_bundle()` checks from the bundle *alone* against three invariants: **integrity** (chain reproduces AND matches out-of-band signed anchor — catches a consistent full rewrite that `verify` alone cannot), **monotonicity** (every delegation is child ⊆ parent), **containment** (every allowed action's scope was within the acting node's authority). Machine-readable `failure_details` parallel the human `failures` list so conformance suites can assert *which* check failed *where*. This is the "sell evidence, not the engine" pattern made concrete: the auditor verifies *without our engine*. → Plugs into our evidence pipeline (auditor exports, attestation).
2. **`redaction_report`** — `evidence.py:126`: the exported bundle carries an explicit report of what was redacted/withheld, so auditors see the boundary of what they can't see. Steal for our evidence exports: redaction should be *disclosed*, not silent.
3. **Stdlib-only JCS canonicalization + vendored Ed25519** — `src/attenu_guard/canonical.py` (RFC 8785 JCS, closed data model, rejects unsafe integers instead of coercing) and `src/attenu_guard/_ed25519.py`. Directly reusable for our Ed25519 + Merkle receipt workstream (F-priority #2): the canonicalization discipline (reject `>2^53`, reject non-finite, reject lone surrogates) is exactly what byte-reproducible receipt signing needs, with zero dependency risk.
4. **Chain invariants** — `src/attenu_guard/chain.py`: monotonic attenuation, TTL bounds, depth/fanout ceilings, *aggregate ceilings across the whole chain*, **cascade revocation** (killing a node revokes its subtree), and in-process HMAC seals with an honest caveat ("raises the bar against bugs and casual tampering only"). → Plugs into our goal registration/conflict detection gap: the delegation-graph model is the authority-side counterpart of goal registration.
5. **Scenario-file format** — `src/attenu_guard/scenarios.py`: grants + scenario + expected outcomes *including expected reason codes* in one file, runnable by CLI, checkable into CI — simultaneously DevX artifact, living regression test, and IETF-interop fixture. Also ships in-repo conformance vectors (`src/attenu_guard/vectors/`, incl. JCS edge cases and chain-integrity negatives).

**Verdict: STEAL.** Highest-density find. Priority: (a) `evidence.py` bundle/verifier + `redaction_report` → our evidence pipeline; (b) `canonical.py` + `_ed25519.py` → our Ed25519 receipt workstream; (c) chain-containment model → goal/delegation gap. All Apache-2.0.

---

## 3. aeoess/agent-passport-system — agent identity + scoped delegation protocol

**What it is:** Open protocol for agent identity, scoped delegation (authority can only narrow), and signed action receipts; gateway is both judge and executor. TS reference + Python/Go/Rust ports checked against a conformance suite; browser-local receipt verifier (nothing uploaded).

**Maturity:** 46 stars, ~1329 commits, pushed 2026-09-25. **Apache-2.0**, 97% line coverage, OpenSSF badges, `conformance/` vectors per dimension (authority-bounds, capability-binding, composition-check, regulated-action…).

**Steal-worthy ideas:**
1. **Safety profiles as conformance checklists** — `docs/PAYMENT-SAFETY-PROFILE.md`: P-1 wallet binding, P-2 idempotency, P-3 signature-verified payment evidence ("a receipt that fails verification is treated as *no evidence at all*"), **P-4: amount/currency/recipient must match across intent, decision, and receipt** ("the intent the principal approved is the only one that may settle"; any mismatch is a refusal), P-5 replay protection *distinct from* idempotency, P-6 high-value owner confirmation. The profile pattern — a named checklist with negatives (`tests/conformance/` carries over-budget, wrong-principal, replayed, stale-revocation fixtures) — is exactly how we should package our own safety bars for auditors. P-4 maps to our authorized-channel exfil concern.
2. **Browser-local verifier** (agent-passport.org/verify.html, runs locally, nothing uploaded) — the auditor UX for "sell evidence, not the engine."

**Verdict: STEAL the profile pattern; STUDY the code.** The codebase is a full multi-language protocol — too heavy to lift — but the *safety-profile-as-checklist* and *conformance-vectors-per-dimension* patterns are directly reusable.

---

## 4. narko4u/witnessos — evidence-grade receipts (spec only)

**What it is:** Public spec + marketing site for a credential-brokered enforcement gateway. The gateway source is **proprietary** (patent pending, AU 2026906017); the repo is specification, docs, and a Python SDK.

**Maturity:** 0 stars, ~14 commits. Apache-2.0 covers the spec/docs only.

**Ideas worth reading in `SPEC.md` (no code to steal):**
1. **E1–E4 evidence grades per receipt** — "Evidence grade measures strength of evidence, not business success." Async observation caps at E1; gateway-enforced actions reach E3/E4. A graded-strength vocabulary for receipts is useful language for our evidence pipeline tiers.
2. **Crash-proof ordering rule** — no action dispatch until *approval event + pre-dispatch action hash* are durably committed to the customer-controlled evidence store (prevents approve→dispatch→crash→no-proof-approval-happened). We should verify our approval queue has this ordering property.

**Verdict: SKIP** for code (nothing open to take); STUDY `SPEC.md` sections 2 and 8 for the grading vocabulary and the commit-before-dispatch rule.

---

## 5. KongFangXun/sofagent — ontology-driven agent harness with commit-time audit rules ⭐

**What it is:** FDE (forward-deployed-engineer) harness between mature coding agents (DSH/OpenClaw/WorkBuddy) and the model layer: governance via files — audit every change, snapshot, rollback. HMAC-signed tamper-evident audit history, domain rulesets (medical, government, fintech), skill-safety scanner.

**Maturity:** 49 stars, ~3847 commits, pushed 2026-09-26 (very active). **MIT**.

**Steal-worthy ideas:**
1. **A10 supply-chain poisoning rule** — `engine/audit/src/rules/rule-a10-no-poison.ts`: scans dependency-file diffs (`package.json`, `requirements.txt`, `Cargo.toml`, …) for non-official sources (raw.githubusercontent URLs, non-HTTPS git, non-registry package hosts) **plus typosquatting detection** (edit-distance against a popular-package reference list, with whitelist tuning for near-misses like vitest/vite) **plus postinstall-script injection**. → Plugs into our F75 supply-chain preflight and continuous skill/MCP verification lane.
2. **A20 dual-condition exfil detection** — `engine/audit/src/rules/rule-a20-network-exfiltration.ts`: alerts only when an exfil-action pattern (curl POST, fetch-with-env, WebSocket, DNS resolve) *co-occurs* with a sensitive-data pattern (env refs, credential keywords, `sk-…`, `AKIA…`) — dual-condition design cuts false positives. Whitelist comparison uses parsed-URL exact hostname match, not substring (blocks `evil-github.com` bypasses).
3. Rule-runner + ruleset loader (`engine/audit/src/rules/runner.ts`, `ruleset-loader.ts`) with domain rulesets (`rulesets/{medical,government,fintech,ai,security,ast}.json`) — a regulator-shaped artifact packaging pattern.

**Verdict: STEAL.** MIT, and the A-series rule library is a concrete pattern collection for our supply-chain and artifact-inventory gaps. (Whole repo is TypeScript; the *patterns* port easily.)

---

## 6. invariantlabs-ai/invariant — MCP-focused guardrails (Snyk-owned, dormant)

**What it is:** Rule-based guardrailing layer between app and MCP servers/LLM provider (transparent proxy Gateway), with a Python-inspired rule language expressing tool-call flows (`(call: ToolCall) -> (call2: ToolCall)` patterns — e.g. inbox-read followed by external-email-send). Named "tool poisoning" and "MCP rug pulls."

**Maturity:** 463 stars, ~252 commits, **last pushed 2026-01-12 — dormant**. **Apache-2.0** still on the core repos. Snyk acquired Invariant Labs June 2025; per secondary sources, Guardrails + Gateway repos remain Apache-2.0 OSS, but **MCP-Scan was rebranded as Snyk "agent-scan"** and now requires a `SNYK_TOKEN` (offline `--local-only` mode no longer documented) — the scanner half is no longer reproducible OSS.

**Steal-worthy ideas:** the flow-pattern rule language (`invariant/analyzer/language/`, `policy.py`) — declaring *sequences* of tool calls as the unit of policy — is the closest public prior art to our temporal-correlation gap. But it's a frozen artifact: borrow the idea, don't build on the repo.

**Verdict: STUDY** (prior art only). Do not depend on it.

---

## 7. krishddd/sec_guardrails_agent — 7-layer runtime guardrails gateway ⭐

**What it is:** Build-from-scratch 7-layer runtime guardrail gateway (FastAPI reverse proxy in front of a Mistral-backed agent): input → dialog → reasoning/IFC (dual-LLM + taint) → tool/action → retrieval/memory → multi-agent → output → oversight critic. Each rail decision emits an OTel span + append-only audit record. Defensive-only, MIT.

**Maturity:** 1 star, ~217 commits, pushed 2026-09-26 (active). **MIT**.

**Steal-worthy ideas:**
1. **Memory-traversal taint rule** — `src/sec_guardrails/rails/reasoning/taint.py`: borrowed from FIDES/CaMeL, enforces the *trusted-action invariant* (sensitive sinks only run on high-integrity inputs). The sharp part: `add_memory` carries untrusted-provenance taint **forward across the write→retrieve round-trip** — text written untrusted *stays tainted when retrieved* (the cross-session poisoning path), explicitly NOT laundered by the round-trip. Plus an opt-in embedding-similarity check for paraphrase resistance (off by default, injectable embedder so CI stays offline). → Plugs into our temporal-correlation gap: taint must survive memory round-trips.
2. **DNS-rebinding defense** — `src/sec_guardrails/rails/tool/egress.py`: resolve-time IP validation over *every* resolved A/AAA record, fail-closed on resolution error, plus `GuardrailHttpSession` which resolves once, validates, and connects to the *pinned IP* — closing the check→connect TOCTOU window. → Plugs into our F81/egress layer (the proxy-enforced egress bet).
3. Layered-lifecycle observability: OTel span + append-only audit per rail decision is the per-decision observability granularity our rails should match.

**Verdict: STEAL.** MIT, and ideas #1–#2 are concrete, portable mechanisms (not frameworks). Highest code-level steal density after attenu-guard.

---

## 8. DSHCorrectover/ccs-conformance-vectors — Ed25519/JCS receipt conformance vectors ⭐

**What it is:** Reference conformance test vectors for the CCS receipt spec: every agent tool call produces a tamper-evident, Ed25519-over-JCS-canonicalized-JSON signed receipt. **CC0 1.0** (public domain), Rekor-anchored (logIndex 2697248662).

**Maturity:** 1 star, ~38 commits, pushed 2026-09-05. CC0 — fully reusable, including the vectors themselves.

**Steal-worthy ideas:**
1. **Vector layout with SHA-256-pinned manifests** — `vectors/v1.4.0-conformance/manifest.json` pins 66 signed receipt cases; `vectors/mustfail-v1/` carries 11 base MUST-FAIL single-call scenarios + 3 end-to-end multi-tool workflow attack chains + a MUST-PASS benign control. This is the exact shape our receipt conformance suite should take when we ship Ed25519 receipts.
2. **Paired key-variant design** — `vectors/v1.3.0/`: same session signed under sidecar-key vs in-process deterministic key — a pattern for testing receipt verification independent of key custody.
3. **Behavior-observation receipts** — `behavior-*.json` signed artifacts carrying the *semantic* verdict (`not_observed` / `observed_and_rejected` / `observed_and_allowed`), linked to the L1 receipt by `linked_l1_receipt_digest`: a two-layer receipt (authorization verdict + semantic verdict) that maps to our evidence-grading needs.
4. `checkers/independent_checker.py` — an independent verifier implementation to test byte-for-byte interop.

**Verdict: STEAL.** CC0, Rekor-anchored, and it is precisely the conformance discipline our Ed25519 receipt workstream (F-priority #2) needs: adopt the manifest-pinning + mustfail/mustpass layout, and consider the behavior-receipt linkage for semantic verdicts.

---

## 9. NVIDIA/NemoClaw — agent runtime with container sandboxing (claim check: overstated)

**What it is:** Full agent runtime (OpenClaw lineage) with Docker/podman-based sandbox management, policy presets applied at sandbox boot, credential redaction pipeline, audit entries on config mutation.

**Maturity:** 22,545 stars, pushed 2026-09-26 (very active). **Apache-2.0**.

**Claim check:** the prospecting note said "Landlock/seccomp/netns, policy-enforced egress." What the code shows: sandboxing is **container-based** (`src/lib/sandbox/`, `src/lib/onboard/runtime-provider/`); **Landlock appears only in `src/lib/onboard/landlock-warning.ts` — a kernel-support warning that filesystem restrictions "silently degrade (best_effort mode)" on old kernels** — i.e., the fail-open-via-degradation anti-pattern. No seccomp/netns enforcement found; no dedicated policy-enforced egress layer (egress references are DNS/config plumbing). Treat the sandboxing claim as overstated.

**Salvageable:** `src/lib/security/` credential-redaction pipeline (`redact.ts`, `credential-filter.ts`, `secret-patterns.ts`) — output-side credential redaction applied on `config get`, with structured token patterns; and the agent-aware sandbox registry (which agent runs in which sandbox — relevant to our artifact inventory gap).

**Verdict: STUDY.** Notable mainly as (a) the anti-pattern to avoid (silent degradation of sandbox restrictions — fail open is never acceptable in our sandboxing workstream), and (b) the credential-redaction-on-read pipeline. 22.5k stars means its *patterns* become de-facto expectations — worth watching, not copying.

---

## 10. cisco-ai-defense/skill-scanner — agent skill security scanner

**What it is:** Best-effort security scanner for agent skills (OpenAI Codex / Cursor / agentskills.io formats): pattern detection (YAML + YARA-X), AST/dataflow analysis, optional LLM-as-judge, and a **bounded CEL decision layer over typed detector facts**. SARIF output, pre-commit hook, reusable GitHub Action.

**Maturity:** 2,556 stars, ~108 commits, pushed 2026-09-26. **Apache-2.0** (LICENSE file; API metadata says NOASSERTION). Cisco AI Defense team.

**Steal-worthy ideas:**
1. **CEL decision layer** — `skill_scanner/core/cel/` (`gate.py`, `runtime.py`, `qualification.py`): deterministic correlation of detector outputs as *typed facts* evaluated by the cel-go runtime, run in shadow mode until it passes promotion gates. A principled way to combine noisy detectors without letting an LLM silently suppress findings.
2. **Honest evaluation discipline** — the README publishes both the good split (F1 32.9%→47.7%) and the locked source-disjoint split where the change *failed the promotion gate* (13.7% F1, FPR regression) and therefore shipped rules stayed in shadow. "No findings ≠ no risk" is stated up front. Worth emulating in our own eval reporting.
3. SARIF reporter (`skill_scanner/core/reporters/sarif_reporter.py`) for CI integration; scan policy configuration (`core/scan_policy.py`).

**Caveat:** own evals show weak recall on the locked split — this is detection-assistance, not a gate. Borrow the architecture (CEL-over-facts, SARIF, shadow-mode promotion), not the results.

**Verdict: STUDY.** Directly relevant to our continuous skill/MCP supply-chain verification lane; the CEL-gate and shadow-promotion discipline are the steals, the detectors themselves are not.

---

## 11. aporthq/aport-agent-guardrails — pre-tool-call hooks + agent passport

**What it is:** Deterministic pre-action authorization running in platform `before_tool_call` hooks (Claude Code, OpenClaw, LangChain, CrewAI, n8n adapters); agent passport (identity + capabilities); policy packs; hosted OAP passport option with GitHub OIDC. Markets a live CTF testbed (vault.aport.io, 0 breaches at the restrictive level over 879 attempts).

**Maturity:** 25 stars, ~181 commits, pushed 2026-09-26. **Apache-2.0** (LICENSE file; API metadata says NOASSERTION). npm + PyPI published.

**Steal-worthy ideas:**
1. **Tool→policy-pack mapping** — `packages/core/src/core/tool-pack-mapping.json`: prefix/substring rules mapping tool names (`bash`, `exec.*`, `git.*`, …) to versioned policy packs (`system.command.execute.v1`, `code.repository.merge.v1`). A clean capability-granularity mechanism for policy packs.
2. PreToolUse hook wiring for Claude Code (`hooks/pre-tool-use.sh`, `hooks/hooks.json`) — standard pattern, already what we do.

**Caveats:** the "40+ security patterns" claim is repeated in launch/marketing docs but no pattern library exists in the OSS core — enforcement patterns appear to live in the hosted/API side. The audit log (`packages/core/src/core/auditLogger.ts`) is **plaintext lines, not hash-chained** — weaker than ours. Passport validation (`passport.ts`) is minimal (format check only; "full OAP v1.0 schema validation can be added later").

**Verdict: STUDY.** The tool-pack mapping is mildly reusable; the rest is thinner than the marketing. Our before-tool-call gate + hash-chained audit already exceeds this.

---

## Cross-cutting notes

- **Nearest architectural neighbors:** attenu-guard (#2) and agentlock (#1) independently converged on our shape (deny-by-default gate, hash-chained audit, signed receipts, delegation). Our differentiators remain: human-approval queue with crash-proof ordering (witnessos's rule — verify we have it), the evidence-pipeline-as-product, and red-first adversarial validation.
- **Anti-patterns spotted:** NemoClaw's silent Landlock degradation (fail-open sandboxing); aport's plaintext audit log; agentlock's `"deny"`/`"denied"` dual spelling (canonicalize verdicts at the schema layer).
- **License landmines:** agentlock is AGPL-3.0 (ideas only); witnessos core is proprietary/patent-pending (spec only); invariant's scanner half is now token-gated under Snyk. Everything marked STEAL above is Apache-2.0, MIT, or CC0.
