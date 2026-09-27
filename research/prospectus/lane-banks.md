# Prospectus Lane: Banks & Fintech

**Lane owner:** Krishna (subagent ca9dd350) · **Date:** 2026-09-26
**Scope:** public repos from jpmorganchase, capitalone, goldmansachs, + other bank/fintech orgs with AI-agent or AI-safety repos. (Fifth Third `lucy` excluded — covered by sibling lane.)
**Method:** GitHub public API search (`org:<org> agent|agentic`) + shallow clones to `/tmp/lane-banks`. $0 spend. Primary sources only; all file pointers are repo-relative paths verified in-clone.

## Search coverage

| Org | Query hit |
|---|---|
| jpmorganchase | `Phantom` (multi-agent RL simulator, ★91), `CodeQuest` (LLM code-quality eval, ★18) — both out of scope |
| capitalone | `VulnHunter` (★1024) |
| goldmansachs | none agent-related (top repos: gs-quant, reladomo, obevo — quant/infra, no governance surface) |
| bankofamerica, adyen, monzo, revolut, squareup | zero agent repos |
| stripe | `link-cli` (★796) |
| paypal | `agent-toolkit` (★195, PayPal API wrapper for agents — integration, not governance) |
| intuit | `NightFalcon` (★0, fresh Sep 2026), `fasteval` (★12, eval decorators), `scikit-rec-agent` (★1) |

---

## 1. stripe/link-cli — verdict: STEAL

**What:** CLI + SDK that lets AI agents complete purchases on a user's behalf via one-time-use payment credentials (virtual PAN, Link Pay Token, Shared Payment Token) — the agent never sees real card details, and a human approves each spend out-of-band.
**Maturity:** ★796 · MIT · created 2026-04-23 · pushed 2026-09-25 (actively maintained, ~20 open issues). Production Stripe product surface.

### Steal-worthy ideas (with file pointers)

1. **Async spend-request approval lifecycle — the production reference for our human-approval queue.**
   - `packages/sdk/src/resources/spend-request.ts` — `SpendRequestResource` implements create → `approval_url` (returned as `RequestApprovalResponse`, zod-validated with `requestApprovalResponseSchema`) → poll status → issue one-time credential. This is exactly the "human approves at a URL, agent waits" pattern our approval queue needs, proven in production at Stripe scale.
   - `packages/sdk/src/resources/approval-policy.ts` — declarative policy rules (`action`, `limits.per_purchase.amount/currency`, `allowed_payment_methods`) fetched from `/approval-policy`. Maps directly onto our fail-closed policy engine: tiered auto-approve limits with human step-up above a threshold. Their README documents "Handling step ups" as a first-class flow — steal the vocabulary.
   - **Duplicate-spend idempotency** (`getDuplicateSpendRequest` in `spend-request.ts`): server-side duplicate detection parsed out of API error payloads, so a retried spend request resolves to the original instead of double-charging. Plugs into our approval dedup / replay-safety (cf. our attack-program gap on intent/temporal correlation — idempotency keys bound to spend requests are the fix).
   - *Plugs into:* `gov/` approval queue — adopt the create→approval_url→poll state machine and the declarative per-action limits schema; adopt duplicate-request reconciliation for our own idempotency story.

2. **Privacy-preserving agent attestations (Blind RSA / PrivateToken-style).**
   - `packages/sdk/src/resources/attestations.ts` + `packages/sdk/src/resources/attestations-crypto.ts` (934 lines combined) — full client implementation of blind-RSA token issuance via `api.link.com/.well-known/aap-issuer`, with QUIC-varint wire encoding, challenge digests, and unblinding. An agent proves "I am an authorized Link agent" without revealing *which* user/agent — attestation without identity leakage.
   - *Plugs into:* our agent-identity layer — the pattern for "prove authorization class without exposing principal" is directly reusable for privacy-preserving agent credentials in the audit log.

3. **Signed per-authority agent auth blocks (WebBotAuth).**
   - `packages/sdk/src/resources/web-bot-auth.ts` — `signUrl()` fetches a short-lived signed block (`signature`, `signature_input`, `signature_agent`, `authority`, `expires_at`), cached per-hostname with a 30s expiry buffer. Every egress request the agent makes carries a fresh cryptographic proof of agent-hood bound to the destination authority.
   - *Plugs into:* our egress/identity story — per-destination, expiring, signed agent-identity headers on tool egress are the concrete mechanism for authorized-channel attribution (attack-program gap: authorized-channel semantic exfil needs exactly this kind of bound identity).

4. **Agent attribution of API calls.** Commit `73af809` "Attribute Link CLI requests to invoking AI agents" — the SDK tags which invoking AI agent made each request. *Plugs into:* our audit log — agent-instance attribution on every governed action, not just the human owner.

---

## 2. capitalone/VulnHunter — verdict: STEAL

**What:** Agentic AI security tool (built inside Capital One) that does attacker-first vuln analysis on source code via three composable skills: `/vulnhunt` (hunt) → `/vulnhunter-fix` (fix) → `/vulnhunt-fix-verify` (independent verify). Falsification engine discards ~50% of candidates as false positives before reporting.
**Maturity:** ★1024 · Apache-2.0 · created 2026-07-07 · pushed 2026-08-15. 27 PRs merged, CI on every PR. Mature prompt-engineering + Python harness.

### Steal-worthy ideas (with file pointers)

1. **Mandatory adversarial falsification phase — the formal version of our break-first discipline.**
   - `vulnhunt/phases/phase2b_verify.md` — "STOP. Before writing any report… your job now is to try to DISPROVE each one." Every candidate is guilty-until-proven-innocent; includes a *candidate manifest* rule (flat list of all candidates up front; the final verdict table must have exactly that many rows — a dropped candidate is a verification *failure*, not an implicit rejection) and consensus-skip gates for audit trail.
   - *Plugs into:* our standing red-first post-wave audit rule — adopt the candidate-manifest discipline (enumerate every claimed closure, verdict table must cover all of them, no silent drops) as the audit checklist format.

2. **Schema-gated findings + honesty-first completeness rubric — regulator-shaped evidence.**
   - `vulnhunter-fix/references/finding-schema.json` + `vulnhunter-fix/scripts/validate-finding.py` (Draft 2020-12 jsonschema validation; exits non-zero with single diagnostic) — no finding enters the pipeline unless it validates against the schema. *Plugs into:* our finding hygiene — machine-checkable FINDINGS.md (close-when criteria as schema, not prose).
   - `vulnhunter-fix/references/fix-completeness-rubric.md` — classifier walks **conservative-first**: checks WORKAROUND signals before MITIGATION before FULL, and returns `LLM_REVIEW` (never `FULL`) when undecidable (REQ-HON-004). `vulnhunter-fix/templates/residual_risk_section.md` renders a **Residual Risk** section that is *mandatory* whenever tier ≠ FULL, with auto-created follow-up issues per residual vector. This is exactly the honest-evidence artifact our "sell evidence, not the engine" bet needs: a fix report that *structurally cannot overclaim*.
   - *Plugs into:* `evals/` + evidence pipeline — steal the conservative-first tier classifier and the mandatory residual-risk section for our closure reports; this is the artifact shape an auditor/regulator wants to see.

3. **Three-role separation of duties (hunt / fix / verify).**
   - `/vulnhunt-fix-verify` is "a completely separate, read-only agent that independently validates whether a finding was successfully remediated… fixes are proven, not taken on faith" (README). Mirrors our wave-closure vs. post-wave-audit separation — validates that our two-agent structure (builder + independent auditor) is the industry shape, not an idiosyncrasy.

---

## 3. intuit/NightFalcon — verdict: STUDY

**What:** Multi-client (Claude Code / Codex / Cursor) harness for deep adversarial security review: one enforced nine-phase workflow producing evidence-backed findings, blind Devil's-Advocate adjudication, SARIF, per-repo reports, and a cross-repo executive report.
**Maturity:** ★0 · Apache-2.0 · created 2026-08-28 · single "Initial commit" + updates through 2026-09-15. Brand new, unproven, but architecturally interesting.

### Steal-worthy ideas (with file pointers)

1. **Append-only agent journal with contract tests.**
   - `claude/scripts/agent-journal.py` (mirrored for codex/cursor), contract-tested by `tests/test_agent_journal_contract.py` + recovery-tested by `tests/test_agent_journal_recovery.py`. Every agent action is journaled to a workspace log with a session manifest (`tests/fixtures/workspace-v1/state.json`) — a per-session action ledger with recovery semantics.
   - *Plugs into:* our hash-chained audit log — compare their journal schema/recovery model against ours; the *session-manifest + phase tracking* shape is a useful input to our evidence export format.

2. **Analysis contracts as mandatory discovery inputs.**
   - `shared/references/analysis-contracts.md` — every authorization candidate must record `principal / action / object / ownership_binding / relationship / observed_decision / expected_decision`; every sensitive workflow must record invariants (cardinality, ordering, atomicity, idempotency-key scope). "Unknown or absent fields increase uncertainty; they never dismiss evidence."
   - *Plugs into:* our eval battery design — the contract-first pattern (declare the evidence fields *before* the agent runs, grade completeness of evidence not just correctness of verdict) is directly applicable to our B2 realistic battery and to artifact-inventory/egress-detection situations.

3. **Install receipts with manifest hashes (supply-chain evidence for agent tooling).**
   - `src/nightfalcon/receipts.py` — `InstallReceipt` dataclass: version, client, destination, `manifest_sha256` (enforced lowercase hex), canonical POSIX path list (rejects `..`, absolute, non-canonical, case-colliding paths), UTC-second timestamps, strict exact-schema decoding.
   - *Plugs into:* our F75 supply-chain surface — a signed install receipt is the artifact shape for "which agent tooling, at which hash, was installed where," relevant to continuous skill/MCP verification (user's 2026-09-23 reallocation stream #2).

---

## Skipped (with reason)

- **goldmansachs/** (whole org): 24 repos, top = gs-quant (★13k, quant finance), reladomo, obevo — no agent/AI-safety surface at all. SKIP.
- **jpmorganchase/Phantom** (★91, Apache-2.0): multi-agent reinforcement-learning *simulator*. Simulation framework, no governance/identity/policy content. SKIP.
- **jpmorganchase/CodeQuest** (★18): LLM-driven code-quality eval loop. Eval-adjacent but no agent-control or evidence artifacts. SKIP.
- **paypal/agent-toolkit** (★195, Apache-2.0): PayPal API/MCP wrapper so agents can call PayPal. Pure integration surface, no approval/policy/evidence patterns worth stealing. SKIP.
- **intuit/fasteval** (★12): decorator-first LLM eval library. Sibling research lane covers eval; nothing agent-governance-specific. SKIP.

## Cross-cutting notes for the build

1. **Banks ship evidence, not just tools.** Both Capital One (schema-gated findings, residual-risk sections, REQ-HON honesty requirements) and Intuit (SARIF + executive reports + analysis contracts) treat the *artifact* as the product. This validates our "sell evidence, not the engine" strategy from inside the target buyer vertical — bank security teams already buy this shape.
2. **The honest-closure pattern is convergent.** VulnHunter's conservative-first classifier ("never FULL when undecidable") and mandatory residual-risk disclosure independently arrived at our standing red-first audit rule. Worth citing in our evidence-pipeline spec as prior art.
3. **Agent identity on egress is becoming standardized surface.** Stripe's WebBotAuth signed per-authority blocks + blind-RSA attestations show where the industry is going: cryptographic agent-hood proofs bound to destination, not bearer API keys. Our identity layer should align with this shape (HTTP Message Signatures-style `signature`/`signature_input` fields).
