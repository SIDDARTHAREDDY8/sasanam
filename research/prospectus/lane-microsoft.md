# Lane: Microsoft — repo prospecting (2026-09-26)

Method: shallow clone + GitHub API; primary sources only (file paths below are repo-relative).
Note on instructions: parent described PR #667 as the "agentrust-io/awesome-ai-governance merge".
Verification: AGT PR #667 is actually the **ScopeBlind protect-mcp integration**
(Cedar policy enforcement + verifiable decision receipts — Tom Farley/tomjwxf, merged Apr 2026).
No awesome-ai-governance merge found in the repo (only passing mentions in
`docs/adr/0032-agt-emits-trace-v01-trust-records.md` and a 2026-07-02 audit doc).
The ScopeBlind/IETF-draft ecosystem around that PR is itself worth mining — see §3.

---

## 1. microsoft/agent-governance-toolkit (AGT) — deep treatment

**What it is:** Enterprise agent-governance monorepo: policy engine, zero-trust agent
identity, sandboxing, human approvals, SRE for agents, and EU AI Act compliance tooling.
**Maturity:** ~6.3K stars / 1.1K forks · v5.0.0 · MIT license · last push 2026-09-26
(active; latest commit `#4157`). Polyglot (Python core in `agent-governance-python/`,
plus TS/Go/Rust/.NET SDKs and CLI plugins).

### Architecture (in their terms)
Deterministic application-layer interception: every agent action is evaluated against
policy *before execution* (`docs/ARCHITECTURE.md`). Two layers:
- **Deterministic policy layer** — YAML/Cedar/OPA policies; `allow/deny/require_approval`.
- **Advisory layer** — ML/LLM classifiers that run *after* allow and can only *tighten*
  (block/flag), never loosen (`.../governance/advisory.py` docstring: "The deterministic
  layer remains the trust boundary; the advisory layer is defense-in-depth.").

Key subsystems: Agent OS policy engine, AgentMesh zero-trust identity (Ed25519/SPIFFE),
Agent Hypervisor (execution rings 0–3, Merkle chain logs, commitment anchoring),
Agent SRE (circuit breakers, replay), MCP Security Gateway, EU AI Act evidence pipeline.

### Policy-enforcement seam
- `agent-governance-python/agent-mesh/src/agentmesh/governance/govern.py` — the 2-line
  wrapper pattern: `governed = govern(my_tool, policy="policy.yaml")`. Every call evaluates
  YAML policy, logs to audit trail, raises `GovernanceDenied` on block. Two hardening
  details worth stealing: (1) shared per-agent `RingBreachDetector` registry so a rogue
  agent with N tools can't spend N× violation budgets; (2) shared `FileAuditSink` per
  path so concurrent writers don't interleave hashes and fake chain breaks.
- `agent-governance-python/agent-mesh/src/agentmesh/governance/approval.py` — HITL with
  **strict mode** (`AGT_APPROVAL_STRICT=1`): rejects the two unsafe legacy behaviors —
  timeout auto-approval and body-supplied approver identity. This is exactly the anti-pattern
  checklist for our approval queue.
- `agent-governance-python/agent-mesh/src/agentmesh/governance/approval_protocol/` — multi-party
  approval coordination (`coordinator.py`, `binding.py`, `digest.py`, `store.py`).

### Identity model
- `agent-governance-python/agent-mesh/src/agentmesh/identity/agent_id.py` — Ed25519-bound
  agent identity issued by an AgentMesh CA; revocation propagates in ≤5s.
- `identity/spiffe.py`, `identity/mtls.py`, `identity/entra_agent_id.py` — SPIFFE/SVID
  workload identity, mTLS, Entra Agent ID federation; `identity/external_jwks.py` —
  cross-org federation (ADR-0007); `identity/attestation.py` — TEE attestation evidence
  (`AttestationClaims`, report-data binding).
- `identity/delegation.py` — `DelegationLink`, `ScopeChain`: sub-agent gets parent's
  scopes minus denied ones; `UserContext` propagates on-behalf-of user context with expiry.
  Directly adjacent to our goal-registration/delegation-provenance thinking.

### Sandboxing approach
- `agent-governance-python/agent-hypervisor/src/hypervisor/rings/` — execution rings 0–3
  (`enforcer.py` `RING_CONSTRAINTS`), `elevation.py` (trust-gated ring elevation),
  `breach_detector.py` — behavioral anomaly detection: tool-call frequency spikes in a
  sliding window + privilege-escalation attempts scored by ring distance; HIGH/CRITICAL
  trips an internal circuit breaker. This is a shipped implementation of the
  intent/temporal-correlation gap (row ~11/12): anomaly scoring over action streams with
  automatic containment.
- Defense-in-depth composition is explicit (`docs/ARCHITECTURE.md`): AGT's interception
  composes with container isolation (Docker/gVisor/Kata) — honest about not replacing
  OS-level sandboxing. Mirrors our "real sandboxing" priority; don't re-invent their
  rings framing without the container layer.

### Audit / evidence (the "sell evidence" part)
- `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py` — append-only
  JSONL log with Merkle chain; HMAC-SHA256 audit sink with **caller-supplied key** and a
  32-byte minimum enforced (`_check_audit_secret_key_strength`); "never generate a key
  per-instance" is stated as an explicit design rule. Design notes match our own audit log
  and validate our direction (HMAC+chain); their min-key-length gate is a steal.
- `agent-governance-python/agent-mesh/src/agentmesh/governance/decision_bom.py` —
  **Decision BOM**: reconstructible view of every factor behind a governance decision,
  queried on demand from audit logs + trust scores + policy evaluations + OTel traces.
  Design principle: "non-invasive over complete." This is the single most evidence-pipeline-
  relevant idea: sell the *decision reconstruction* artifact, not raw logs.
- `agent-governance-python/agent-mesh/src/agentmesh/governance/evidence_pipeline.py`
  (+ `annex_iv.py`) — CLI-driven pipeline that collects policies, audit entries,
  compliance reports, SRE data into an EU AI Act Annex IV dossier: Markdown report +
  machine-readable JSON manifest of evidence sources. Concrete template for our
  auditor-export/attestation artifacts.
- `docs/compliance/data-provenance-model.md` — provenance record schema (source →
  transformation → purpose, classification/PII tags, content hash). Direct template for
  our artifact-inventory/egress-detection gap.
- `agent-governance-python/agent-compliance/src/agent_compliance/` — `prompt_defense.py`
  (pre-deploy regex scan of system prompts against 17 attack vectors, incl. encoding-aware
  injection), `verify.py`, `integrity.py`, `supply_chain.py`.

### Steal-worthy ideas → our gaps
1. **Advisory-can-only-tighten layer** (`governance/advisory.py`) → authorized-channel
   semantic exfil (row ~7): run a cheap LLM/judge classifier *after* deterministic allow;
   it can block or flag-for-review but never override a deny, and its failures default to
   allow with `deterministic: false` logged. Gives us a semantic-detection seam that can't
   weaken the fail-closed core. **STEAL** (pattern + API shape).
2. **Decision BOM** (`governance/decision_bom.py`) → evidence pipeline: reconstructible
   decision explanations assembled on demand from existing signals instead of storing
   pre-built explanations. Cheaper to build, harder to tamper with. **STEAL**.
3. **Approval strict mode** (`governance/approval.py`, `AGT_APPROVAL_STRICT`) → our
   approval queue: ban timeout auto-approval and unvalidated approver identity. **STEAL**
   (checklist, ~20 lines).
4. **Ring breach detector** (`hypervisor/rings/breach_detector.py`) → intent/temporal
   correlation (rows ~11/12): frequency-spike + privilege-escalation anomaly scoring with
   circuit-breaker containment, per-agent budget shared across all its tools. **STUDY→STEAL**
   (adapt scoring to our action stream).
5. **Ed25519 signed decision receipts** (via PR #667 integration,
   `agent-governance-python/agentmesh-integrations/scopeblind-protect-mcp/`) + IETF
   draft `draft-farley-acta-signed-receipts` → external anchoring + our Ed25519/Merkle
   priority: offline-verifiable, replay-protected receipts with JCS canonicalization.
   **STUDY** (follow the draft; don't fork their adapter).

**Verdict: STEAL** (highest-value Microsoft lane). MIT, active, and architecturally
closest to us in the industry — but note the prior teardown verdict stands: their
approval chain is plain SHA-256 where ours is HMAC; keep our crypto choices.

---

## 2. microsoft/autogen (v0.4+)

**What it is:** The dominant multi-agent framework: `autogen-core` (actor-style agent
runtime, topic routing), `autogen-agentchat` (teams, termination, HITL), `autogen-ext`
(code executors, tools, model clients).
**Maturity:** ~61K stars / 9.3K forks · code under `LICENSE-CODE` = **MIT** (repo-level
`LICENSE` is CC-BY-4.0 for docs/content — code itself is MIT) · active through Apr 2026.

### Steal-worthy ideas
1. **MessageContext provenance seam** — `python/packages/autogen-core/src/autogen_core/_message_context.py`:
   every message handler receives `sender: AgentId | None`, `topic_id`, `is_rpc`,
   `message_id`. A provenance/audit hook can be bolted onto *any* runtime at this one
   choke point. Their `AgentId` (`_agent_id.py`: `type/key` string) is weak identity
   (no crypto binding — AGT does this properly), but the *seam placement* is the lesson:
   provenance at message dispatch, not at the model.
2. **HITL pattern** — `autogen-agentchat/src/autogen_agentchat/agents/_user_proxy_agent.py`:
   `UserProxyAgent` with a pluggable `input_func` (sync/async + `CancellationToken`);
   guidance explicitly warns against blocking a running team — use `HandoffTermination`/
   `SourceMatchTermination` to park team state and resume on human input. Relevant shape
   for our approval queue UX: suspend-resume, not block-forever.
3. **Code execution sandbox adapters** — `autogen-ext/src/autogen_ext/code_executors/`
   (`docker/`, `docker_jupyter/`, `local/`, `azure/`, `jupyter/`): the industry's reference
   "swap the executor backend" interface for sandboxing. STUDY for our real-sandboxing
   priority (executor interface shape), not for enforcement.

No serious prompt-injection defense found in-repo (only scattered references in
`web_surfer`/`magentic_one`); their security story is effectively delegated to AGT-style
tooling (`agent-mesh` has an AutoGen adapter).

**Verdict: STUDY.** Take the dispatch-seam and HITL-state patterns; skip their identity
model (weaker than AGT's); code-executor adapter shape is useful background for our
sandbox work.

---

## 3. Adjacent targets surfaced (from the PR #667 ecosystem)

- **ScopeBlind/protect-mcp** (npm `protect-mcp`, MIT) — Cedar-based MCP tool-call gateway
  with Ed25519-signed, hash-chained, replay-protected decision receipts;
  offline verifier `@veritasacta/verify` (Apache-2.0). Its AGT adapter is
  `agent-governance-python/agentmesh-integrations/scopeblind-protect-mcp/` in AGT.
  → STUDY for our evidence-pipeline receipt format + external anchoring.
- **IETF draft-farley-acta-signed-receipts** — proposed standard for signed agent-action
  receipts (JCS canonicalization RFC 8785 + Ed25519 RFC 8032). → track; if it standardizes,
  our evidence exports should emit it.
- **cedar-policy/cedar-for-agents** (WASM bindings, merged PR #64) — Cedar policy eval
  in-agent; deterministic, formally verified policy language from AWS. → STUDY as a
  candidate deterministic policy backend alternative to YAML rules.

---

## Bottom line for the parent

1. **AGT is the single most on-domain open-source governance codebase in the Microsoft
   lane** — MIT, actively maintained (pushed today), and it already ships working
   answers to four of our needs: deterministic/advisory two-tier enforcement, Decision
   BOM evidence reconstruction, Annex IV evidence pipeline, and behavioral breach
   detection. Prioritize steals in this order: advisory-tighten-only pattern,
   Decision BOM, approval strict-mode checklist, ring breach detector.
2. **AutoGen's value is architectural, not security**: its `MessageContext` dispatch seam
   (`sender`/`message_id`) is the right choke point for provenance hooks, and its
   suspend-resume HITL pattern informs our approval UX. Its identity model is weaker
   than ours/AGT's — do not copy.
