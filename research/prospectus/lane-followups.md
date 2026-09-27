# FLAGGED FOLLOW-UPS (lane completed 2026-09-26)

Deep-review of four repos flagged in round 1. Full prospectus: `research/repo-prospectus.md`.

---

## 1. `Agent-Threat-Rule/agent-threat-rules` — **STEAL**

"Sigma, but for AI agents": 825 versioned YAML detection rules (ATR-YYYY-NNNNN), each with test cases, wild-scan validation stats, and EU AI Act / NIST / ISO 42001 compliance mappings.

**Maturity:** 400 stars, MIT (verified `LICENSE`), pushed 2026-09-26 (today — actively maintained), 60 forks, 70 open issues. Round-1's "825" was the rule count, not stars — verified by counting `rules/**/*.yaml` = 825 files.

**The rule schema** (`spec/atr-schema.yaml`; canonical example `rules/agent-manipulation/ATR-2026-00030-cross-agent-attack.yaml`):
- `id: ATR-YYYY-NNNNN`, `title`, **`rule_version` (integer, "bump when detection logic changes", starts at 1)** — the versioning mechanism; plus `wild_validated` (date of last wild-scan validation) and `wild_samples` (e.g. 53,577) as quality metadata.
- `detection_tier`: **787 `pattern`, 32 `semantic`**. `confirm: embedding` is a schema hook for a second-pass confirmation step.
- `detection`: named conditions (`field` / `operator` / `value` / `description`), `condition: any|all`, plus `false_positives` and **`evasion_tests`** (documented bypass cases with technique labels — an honesty feature).
- `response`: actions (`block_input`, `escalate`, `snapshot`), `auto_response_threshold`, `message_template`.
- `compliance`: audit-grade mapping — EU AI Act articles 9/12/14/15, NIST AI RMF, ISO 42001, each with `strength: primary|secondary` and a context paragraph. This is evidence-pipeline gold: every detection ships with its regulator citation.
- `test_cases` (true_positives / true_negatives) + per-rule `confidence`.

**`scan_target` taxonomy** (maps 1:1 onto our gates): `mcp` (398), `llm_io` (114), `both` (103), `user_input` (62), `skill` (39), `runtime` (44), `tool_output` (21), `tool_args` (13), `tool_call`/`tool_response` (2+2), `agent` (4), `llm` (3).

**Ingestion path:** engines exist in Python, Go, TypeScript (`engines/`); `python/pyatr/engine.py` is explicitly "Layer 1 (regex/pattern) detection only". `INTEGRATION.md` enshrines detection-vs-enforcement separation ("ATR is a detection layer, not a complete security product… ATR reports, you decide"). The 787 pattern-tier rules are plain regex conditions over named fields — directly ingestible into our check-at-use (tool_call/tool_args/llm_io targets) and registration gates (skill/mcp targets) as detection content. The 32 `semantic`-tier rules are still regex under the hood (the `confirm: embedding` second pass has no shipped engine support) — treat them as candidates for our advisory-judge layer, mirroring AGT's advisory-can-only-tighten seam. Quality caution: regex quality varies; grade by `wild_samples` and TP/TN cases before adopting.

**Top 10 rules for our gaps (row 13 authorized-channel exfil, semantic injection):**
1. `ATR-2026-02304` — "Base64-Encoded Path Segment in a WebFetch URL to a Pre-Approved Trusted Domain" — covert exfil over an **authorized channel** (row 13, direct hit)
2. `ATR-2026-00102` — "Data Exfiltration via Disguised Analytics Collection" — exfil disguised as a legitimate channel (semantic tier, `scan_target: both`)
3. `ATR-2026-00421` — "Natural-Language Covert Conversation Exfiltration Instruction" (`scan_target: skill`)
4. `ATR-2026-00081` — "Semantic Evasion via Multi-Turn Prompt Injection"
5. `ATR-2026-00573` — "Paraphrased Prompt Injection (Semantic)"
6. `ATR-2026-00083` — "Indirect Prompt Injection via Tool Responses"
7. `ATR-2026-00136` — "Tool Response Data Piggybacking"
8. `ATR-2026-00089` — "Polymorphic Skill and Capability Aliasing Attack" (artifact-inventory angle)
9. `ATR-2026-00425` — "Natural-Language Persistent Covert Action Hook"
10. `ATR-2026-00030` — "Cross-Agent Attack Detection" (multi-agent impersonation/instruction-override battery)

---

## 2. `x-arc-ai/airlock` — **STEAL** (code + patterns; STUDY the model pipeline)

On-device agent firewall: untrusted content (web pages, emails, tool results) is screened by a local Gemma (Ollama) *before* reaching the model; every verdict lands in a bi-temporal trust ledger.

**Maturity:** 0 stars, Apache-2.0 (verified), pushed 2026-07-10 — hackathon artifact (2nd place, Google DeepMind track, RAISE Summit July 2026), stale since. Borrow the engineering, not the roadmap.

**Steal-worthy:**
1. **Bi-temporal trust ledger** (`airlock/ledger.py`) — tables `sources`, `trust_events`, `quarantine_log`; trust grants are explicit validity intervals (`trust_granted_at` / `trust_revoked_at`); **`as_of(ts)` replays exactly which sources were trusted at any moment in time** — the audit-time trust-state replay our evidence pipeline's "decision reconstruction" needs. `quarantine_log` stores `threat_family` + `malicious_span` + `confidence` + 280-char `content_preview` (the quarantined-evidence artifact shape). Pure stdlib sqlite3, WAL mode, RLock — trivially portable.
2. **Fail-closed screener contract** (`airlock/screener.py`) — `Verdict(decision: allow|quarantine, threat_family, malicious_span, reason, confidence)` from a JSON-emitting local model; on model error it returns quarantine with `"screener produced no valid JSON; failing closed"`. Same module family includes embedding-based `FamilyMatcher` (`airlock/families.py`) over `corpus/payloads.jsonl` for obfuscated variants.
3. **`redact_secrets(text) -> (redacted_text, findings)`** (`airlock/policy.py`) — findings carry `{kind, preview (4 chars + …), length}` and **never the secret itself** (evidence hygiene by construction); plus `host_allowed()` (exact-or-subdomain allowlist) and `path_allowed()` (deny-path subtree + component matching). Dependency-free.
4. **Two-tier choke points** (`CONTRACTS.md` is the frozen module spec): `airlock run` (netns + mitmproxy screening proxy — every HTTP(S) response screened pre-read; egress host-allowlisted and secret-redacted) and `airlock/mcp_gateway.py` (stdio MCP proxy screening **tool results** before they enter agent context; quarantine → withheld-notice). Validates our MCP-gateway choke-point placement independently.

**Reproducibility caveat:** Gemma 12B QAT via Ollama is $0/local but heavy; steal the ledger, verdict schema, and policy module — not the model weights.

---

## 3. `cedar-policy/cedar-for-agents` — **STEAL** (schema generator); **STUDY** (builder idioms)

Cedar bindings/samples for agents — this repo does exist, and it goes beyond base Cedar in exactly our direction.

**Maturity:** 50 stars, Apache-2.0 (verified), pushed 2026-09-23 (active).

**Steal-worthy:**
1. **MCP schema generator** (`rust/cedar-policy-mcp-schema-generator/`) — auto-generates a Cedar schema from an MCP server's `list_tools` JSON Schema: one Action per tool with inputs (and optionally outputs) encoded as action-specific context, e.g. `examples/simple/tool_default.cedarschema`: `action "test_tool" in [Action::"call_tool"] appliesTo { principal: [User], resource: [McpServer], context: { input: test_toolInput, session: CommonContext } }`. Its `RequestGenerator` also builds the `AuthorizationComponents` for a live tool call. **This is our tool-registration gate mechanism**: mint validated, policy-ready Cedar schemas automatically at registration so policies can be written against real tool shapes and validated (`policy validate`) before anything runs. Python wrapper published on PyPI (`cedar-policy-mcp-schema-generator`, PyO3) — no Rust toolchain needed to use it.
2. **Agent policy builder idioms** (`rust/cedar-policy-agent-builder/src/builder.rs`, rendered in `src/policy.rs`) — a fluent API whose outputs are exactly our seams: `rate_limit(tool, max)` → `forbid` policy over `context.session.call_count_<tool>` (temporal-correlation primitive); `time_window`; **`consent_all`/`consent_for_roles`** → permits gated on `context.session.user_consent == true` (the HITL consent seam — consent restricts existing access, never adds); `deny_in_env`; `restrict` (forbid unless input field ∈ allowed values). Confirms our design: pass per-session counters and consent state through the Cedar request `context`.
3. **Entity vocabulary**: `Agent::User`, `Agent::Action`, `Agent::Resource` — a ready-made agent identity/action/resource shape compatible with the `cedar-policy/cedar` Request contract we already adopted.

**Beyond base Cedar:** yes — schema auto-generation from MCP tool descriptions (base Cedar gives you neither), the request-generator for tool calls, and the consent/rate-limit policy idioms. Caveat: the builder crate itself is Rust-only.

---

## 4. `ScopeBlind/protect-mcp` + IETF signed receipts — **STEAL**

**Repo-name correction:** `ScopeBlind/protect-mcp` no longer exists (404 — renamed). Two successors:
- `ScopeBlind/protect-mcp-adk` (0 stars, MIT, PyPI `protect-mcp-adk`) — an Ed25519 receipt-signing **Google ADK plugin** (`after_tool_callback` signs a decision receipt per tool call). Tiny; the format, not the plugin, is the find.
- **`ScopeBlind/scopeblind-gateway`** (9 stars, MIT, pushed 2026-09-17 — the actual "Cedar MCP gateway" round 1 described): npm `protect-mcp`. JSON-RPC stdio-intercepting MCP gateway that evaluates tiered policy (trust-tier admission, `src/cedar-evaluator.ts`, rate limits, approval mandates) and emits Ed25519-signed decision receipts. This is what to review.

**How it gates / where it sits** (`src/gateway.ts`, `ProtectGateway`): intercepts MCP JSON-RPC over stdio (same choke point as our MCP gateway design and CrowdStrike's aidr-mcp-proxy). Approval grants keyed by `request_id` with `once|always` modes + expiry; per-tool rate-limit store; chain resume across restarts via `lastReceiptHash`; modes `enforce|shadow|audit`. `claude-code-hooks.json`: **PreToolUse evaluates the call against `./cedar` and blocks a deny (exit 2); PostToolUse signs a receipt for every call; "a missing policy denies, fail-closed"** — the reference hook split for our own hook surface.

**IETF draft status** — `draft-farley-acta-signed-receipts` has **progressed**: -01 → **-02 live on datatracker** (individual submission, Active) → **-03 in flight** (per `scopeblind-gateway` v0.10.0 release notes: normative `acta-policy-digest-v1`, `require_approval` as a decision value, PureEdDSA over JCS bytes directly with no pre-hash). Envelope: `{ payload, signature: { alg: "EdDSA", kid, sig } }`, JCS (RFC 8785) canonicalization, `previousReceiptHash` chaining, privacy-preserving hashes (`tool_input_hash`, `output_hash` — no raw content). Still an individual submission, not WG-adopted — but it is the de-facto interop point: 14+ implementations cross-verify byte-identical output in `ScopeBlind/agent-governance-testvectors`; `@veritasacta/verify` is the Apache-2.0 offline verifier; Microsoft AGT merged receipt interop (their `agt-integration-profile`).

**Steal-worthy file pointers** (`scopeblind-gateway`, all MIT):
- `src/policy-digest.ts` — **acta-policy-digest-v1**: a recomputable policy commitment (per-file SHA-256 manifest + JCS) — the receipt can prove *which policy was in force* when the decision was made. This is the missing link in our receipts; plugs into the evidence pipeline.
- `src/acta-envelope.ts` + `src/receipt-registry.ts` + `src/receipt-enrichment.ts` — draft envelope implementation and receipt registry/enrichment patterns.
- `src/signing.ts` + `src/signing-failclosed.test.ts` — fail-closed signing with **signing-failure tombstones** so unsigned gaps in the chain stay detectable (never silently skip a receipt).
- `src/egress-guard.ts` — fixed-schema egress summaries: the local receipt stays authoritative and never leaves the machine; only pseudonymous commitments go to hosted dashboards — the honest local-vs-hosted evidence split.
- `src/hook-server-mandate-approval.test.ts` / `src/standard-gate.ts` — approval-mandate tests and financial standard gates (amount checks, person-required) as the pattern for our approval queue's gate contracts.

**Patent caveat:** `PATENTS.md` — ScopeBlind Pty Ltd holds AU provisional patent applications covering VOPRF Metering, Verifier Nullifiers, and Offline Enforcement. Code is MIT; treat like our AGPL discipline — ideas and code are usable, but note the provisional patents before productizing anything in those three method areas.

**Alignment note:** our receipt workstream should emit the draft -02/-03 envelope (`type: "protectmcp:decision"`, `spec: "draft-farley-acta-signed-receipts-02"`) rather than a bespoke format — cross-verifiability with 14+ implementations is worth more than format novelty, and our differentiator (Decision BOM reconstruction, policy digests) layers on top.

---

## Verdict summary

| Repo | Maturity (verified) | License | Verdict |
|---|---|---|---|
| `Agent-Threat-Rule/agent-threat-rules` | 400★, MIT, pushed today | MIT | **STEAL** — ingest 787 pattern rules as gate content; adopt rule schema + versioning |
| `x-arc-ai/airlock` | 0★, Apache-2.0, stale since 2026-07-10 | Apache-2.0 | **STEAL** (ledger, screener contract, policy module); STUDY the Gemma pipeline |
| `cedar-policy/cedar-for-agents` | 50★, Apache-2.0, pushed 2026-09-23 | Apache-2.0 | **STEAL** the MCP schema generator (PyPI); STUDY the builder idioms |
| `ScopeBlind/scopeblind-gateway` (+ `protect-mcp-adk`, IETF draft) | 9★, MIT, pushed 2026-09-17; draft at -02/-03 | MIT | **STEAL** — receipt format, policy-digest, hook split, fail-closed signing |
