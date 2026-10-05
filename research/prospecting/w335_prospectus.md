# Wave-335 Industry Prospectus: Agent-Framework Interception, CIMD Safe Subset, Sigstore-Bundle OCI Wiring, Tier-1 Competitor Delta

**Date:** 2026-10-05 · **Base:** `0fd4f736` (wave-334 merge)
**Method:** primary sources only (spec texts, source code, first-party docs, LICENSE files). Every factual claim carries URL + access date 2026-10-05.
**Standing rule honored:** for EVERY verdict the tree was checked FIRST (commands printed). Prior prospectuses (w320 distribution, w332, w333) are not repeated — only deltas and remaining gaps.

## Prior-prospectus avoidance

Covered before (not repeated): Landlock/nsjail (w330); MCP RFC 9207 `iss` + RFC 8707 `resource` (w332 — LANDED `gov/mcp_oauth_binding.py`); MCP server-side token validation (w333 §1b — LANDED `gov/mcp_server_authz.py`); RFC 9728 PRM verification (w334 — LANDED `gov/mcp_prm.py`, F419→F420); liboqs PQ envelope slot (w333 §3); GPAI ch.9 cadence (w333 §2, w334 gpai lane); GUAC SKIP (w332); Teleport AGPL trap (w332); Bernstein/Attestix WATCH (w332); C2PA/Rekor/offline-verifier/dex/SPIFFE/keto/Cedar (w306–w325); EmpowerID/Omada OSS deep-read (w333-empowerid-oss — proprietary license, read-only); Sigstore keyed-bundle v0.3 shape (w320 + w321 — LANDED `gov/sigstore_bundle.py`); OCI distribution of native bundles (w191 — `gov/evidence_distribute.py`); offline verifier (w311); in-toto re-enveloping (w310); CIMD SSRF-gated constraint recorded (w333 §1d). This wave assesses only what remains.

---

## 1. CIMD — the safe subset (deep-dive on the w333 backlog item)

**Primary source (read in full, 2026-10-05):** `draft-ietf-oauth-client-id-metadata-document-02` (Parecki & Smith, Okta; expires 2027-01-07) — https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/

**Tree check (run).** `grep -rniE "cimd|client.id.metadata|SEP-991" gov/*.py evals/*.py` → **zero hits**. CIMD is still entirely absent. Our MCP OAuth stack assumes pre-registered `client_id`s only (`gov/mcp_oauth_binding.py` seals `(issuer, client_id, token_endpoint_allowlist)` per-AS under the deployment key; no client credentials are handled at all).

**What the spec actually requires — the parts that change the w333 verdict.** The draft's §7.2 ("Pre-Registering Client Identifier URLs") explicitly blesses the enterprise pattern: an AS *may* pre-register Client Identifier URLs, fetching the document *once at onboarding* ("at the time of establishing this pre-registration"), after which the client "behave[s] the same way as a pre-registered client. There is no obligation to support dynamic client onboarding." The draft states this pattern "is expected to be common in enterprise environments." That is exactly Sasanam's deployment shape (fleet-deployed agents, operator-controlled onboarding) — the safe subset is not a compromise, it is the spec's own enterprise track.

**The SSRF control set, from the spec's own §8.6/§5/§8.7 (not just the figranium caution):**
- §5: the AS **MUST NOT automatically follow HTTP redirects** when fetching the document; non-200 → error (§5.1 SHOULD abort the authorization request).
- §8.6: **MUST NOT** fetch any URL (document or embedded) resolving to RFC 6890 special-use IPs (loopback, private, link-local, multicast, etc.). Dev/test MAY allow loopback only if the AS itself is loopback-bound *and* the resolved address matches the same loopback interface — **MUST NOT in production**. SHOULD apply network policies; only fetch known/supported URI schemes (https in practice).
- §8.7: cap the read at **5 KB** (recommended), treat over-limit as error.
- §8.9: AS **may** maintain allowlists of trusted domain patterns (e.g. `*.example.com` = known operator → reduced friction) and domain-reputation heuristics (new-domain warnings).
- §8.4/§8.4.1: metadata is client-controlled and *changes*; key changes (`jwks`/`jwks_uri`) → AS **may** revoke tokens/consent. Caching rules §5.2: respect cache headers, never cache errors or malformed docs.

**Verdict: ADAPT — build the safe subset now, in three pieces (all red-first, all stdlib):**

**(a) CIMD document EMISSION (client role) — zero SSRF, pure win.** We host our own Client ID Metadata Document at a stable `https://<our-domain>/oauth/client` URL: `client_id` == URL, `token_endpoint_auth_method: private_key_jwt`, `jwks_uri` pointing at our published Ed25519 keys, `redirect_uris` same-origin-locked per §8.1. Lets our agent-clients interoperate with ASes that prefer CIMD over pre-registration. No fetch anywhere. Falsifiable: shape-validation battery against §3/§4 rules.

**(b) CIMD URL SHAPE validation (pure, no fetch) — the deterministic core.** `validate_client_id_url(url)`: https scheme, no userinfo, path present, no `.`/`..` segments, no query (spec says SHOULD NOT — we refuse, fail-closed), no fragment; comparisons by simple string comparison (RFC 3986 §6.2.1 — note `https://example.com/client` ≠ `https://example.com:443/client`). Plus `check_document_binding(document, fetch_url)`: `document["client_id"]` MUST equal the fetch URL string. Refusals coded (new `mcp-oauth-cimd-*` codes). This is the entire verification core minus the network — and it is where our architecture already draws the line (cf. `fetch_prm_document`'s caller-supplied `fetcher`: deployment-owned transport, verification core never does implicit I/O).

**(c) Pre-registration intake (§7.2 pattern) — fetch ONCE at onboarding, never at request time.** Operator-driven onboarding: fetch the document through the deployment-owned transport with the full control set (no redirects, DNS-pin the resolved IP and refuse if re-resolution differs, reject RFC 6890 ranges, 5 KB cap, https-only, timeout), then **pin the document hash**; request-time checks compare against the pinned copy only. This kills the request-time SSRF surface *by construction* — there is no request-time fetch to attack. New deployments get (a)+(b); (c) activates only for deployments that onboard third-party CIMD clients.

**Explicitly deferred:** request-time fetching with DNS-aware SSRF/rebinding controls (the figranium caution stands — do not build until dynamic onboarding is a real deployment shape).

**Composition notes (new connections this wave):**
- §8.4.1 key-change detection → feed into the wave-333 CAEP/SSF revocation-push intake: a rotated `jwks_uri` content hash mismatch becomes a revocation event, not just a consent question.
- §8.9 domain-trust allowlists compose with our deployment-config trust root (the `seal_as_binding` model): the allowlist lives in deployment config, never in fetched metadata.
- §4.1 credential restrictions are satisfied vacuously by our stack (we handle no client secrets at all — verified in w333 §1c).

**License:** IETF draft — patterns only, no code copied, no encumbrance. (Draft-02 is "work in progress"; re-check on RFC publication.)

---

## 2. Sigstore-bundle distribution — the remaining wiring gap

**Tree check (run).** `grep -rn "sigstore_bundle" gov/evidence_distribute.py` → **zero hits**. `gov/sigstore_bundle.py` (w321: spec-valid keyed Bundle v0.3, `verificationMaterial.publicKey.hint`, exactly-one-signature DSSE, payloadType `application/vnd.sasanam.evidence+json`) and `gov/evidence_distribute.py` (w191: OCI push of the native tar bundle + Decision BOM referrer + manifest signature referrer, digest-pinned pull, registry treated as untrusted storage) are **parallel exports with no wiring between them**. An auditor pulling from the registry today gets the native bundle only — never the third-party-verifiable keyed form that cosign/sigstore-go can verify independently.

**Verdict: ADAPT — wire the keyed bundle as an OCI referrer artifact (small, falsifiable, no format invention).**

**Falsifiable next step:** `evidence_distribute.py` gains `attach_sigstore_bundle(client, repo, subject, bundle_bytes)` following the existing `_attach()` referrer pattern (same digest-pinned, tagless referrer edge — the module's own docstring explains why tags on referrers are an identity hazard): push the keyed-bundle bytes as a blob with artifactType `application/vnd.dev.sigstore.bundle.v0.3+json`, attach to the subject manifest. `audit_bundle` gains a check: when the deployment's distribution policy requires third-party verifiability, the Sigstore-bundle referrer MUST be present in the referrer graph (same "stripped signature is invisible" logic the module already applies to the manifest signature — D1). Red-first probes: (a) bundle referrer absent under strict policy → coded refusal; (b) tampered referrer bytes → digest mismatch before any verification; (c) referrer present → bytes verify via `verify_keyed_bundle` against the pinned key.

**Why not a new format or a new transport:** w320 already proved the composition (keyed bundle + OCI 1.1 referrers + registry-as-untrusted-storage); both halves are built and tested. The gap is literally one function and one audit check. Do not re-litigate the envelope.

**License:** n/a — our own modules; Sigstore bundle shape is Apache-2.0 spec text, already landed.

---

## 3. Real-agent framework integration survey

**Method:** primary sources (framework docs/source, first-party tutorials), access date 2026-10-05. **Tree check FIRST (run):** `gov/adapters/` already ships `core.py` (GovernedBinding), `generic.py`, `langchain_tools.py` (verified vs langchain-core 1.6.3, funnel-pinned), `mcp_adapter.py` (P2 metadata guard + K-012 provenance), `openai_loop.py` (raw function-call loop). `grep -rliE "crewai|autogen|ag2" gov/ evals/*.py` → **zero hits** — no CrewAI/AutoGen adapter exists. All framework licenses below are permissive (MIT/Apache-2.0), verified via repo LICENSE catalogs 2026-10-05 — no traps; patterns described, nothing copied.

**Standing principle (from `gov/adapters/README.md`):** adapters are the *only* objects handed to agent code; the executor mediates every call (identity → role allowlist → DLP → rate/volume/loop guards → fail-closed policy → tamper-evident audit). Residual: in-process Python cannot stop code holding its own unmediated reference — an operational rule, not a code gap.

### 3a. LangChain (classic) — SKIP (built) + WATCH (new middleware path)

Tree already covers it: `make_governed_tool` builds a `StructuredTool` with `func=None` whose `_run`/`_arun` route through the binding (funnel `invoke→run→_run` pinned by test). **New since:** LangChain's Agent Middleware adds `after_model` ("allows approval, modification, or rejection of tool calls") and `wrap_model_call` — the new idiomatic gate (https://github.com/hxs1103/langchain/blob/HEAD/openwiki/middleware.md). Legacy `BaseCallbackHandler.on_tool_start` is **observe-only** — handler exceptions are logged and swallowed by default (https://github.com/hxs1103/langchain/blob/HEAD/openwiki/callbacks.md) — so any "callback as enforcement" pattern is a bypass; our shim correctly does not rely on it. **Verdict: SKIP** the adapter (exists, F62-hardened); **WATCH** the middleware path — if deployments adopt it, re-verify the funnel-pinning assumption and consider an `after_model` shim that calls the same binding.

### 3b. LangGraph — ADAPT (thin: interrupt→approval-queue recipe)

Three interception levels documented in the ecosystem (https://github.com/kisyntra/agent_sudo/blob/HEAD/docs/ecosystem/langgraph_feasibility.md): (1) tool-wrapper decorator (granular), (2) `ToolNode` subclass (centralized chokepoint), (3) `interrupt_before/after` (coarse). Levels 1–2 are mechanically covered by our existing `langchain_tools` shim (ToolNode calls `tool.invoke` → `_run`). The native HITL story is `interrupt()` + checkpointer, and deepagents' `interrupt_on` per-tool map with **approve/edit/reject/respond** decisions (https://github.com/baem1n/langchain-langgraph-deepagents-notebooks/blob/HEAD/docs/deepagents/08-human-in-the-loop.md). **Gap:** nothing wires LangGraph's interrupt payloads into *our* durable `ApprovalQueue` (chained, auditable) — their interrupt is UI-mediated and advisory; ours is the enforcement record. **Verdict: ADAPT** — a thin documented recipe + helper: LangGraph `interrupt()` payload → `ApprovalQueue` entry → `Command(resume=…)` on decision. Small, no new enforcement semantics.

### 3c. CrewAI — ADAPT (new BaseTool wrapper)

Tools attached to `Agent(tools=[...])` **must be `crewai.tools.BaseTool` instances** (pydantic rejects plain callables; https://github.com/unionai/unionai-docs/blob/HEAD/content/integrations/agents/crewai.md). Task-level `guardrail` is output-validation only; `human_input: bool` forces human review but is coarse (all-or-nothing per task; https://github.com/edisplay/crewai/blob/HEAD/lib/cli/src/crewai_cli/templates/AGENTS.md). Quirk: CrewAI invokes tools **synchronously** (adapters bridge via background-thread loop). License: MIT. **Verdict: ADAPT** — new `gov/adapters/crewai_tools.py` following the `langchain_tools.py` pattern: a `BaseTool` subclass whose `_run` routes through `GovernedBinding` (no raw callable, fail-closed construction). Red-first: undeclared-arg passthrough audit (F62 class) on CrewAI's input handling.

### 3d. AutoGen / AG2 — ADAPT (hook-based shim)

`ConversableAgent` keeps `hook_lists`: `process_last_received_message`, `process_all_messages_before_reply`, `process_message_before_send`, `update_agent_state`; tool execution flows through `generate_tool_calls_reply` → `execute_function` (https://docs.ag2.ai/0.9.1/docs/api-reference/autogen/ConversableAgent/). Note: `microsoft/autogen` is in **maintenance mode**; README points new users to `microsoft/agent-framework` (MIT) — target AG2 (`ag2ai/ag2`, Apache-2.0). **Verdict: ADAPT** — new `gov/adapters/ag2_hooks.py`: register a `process_all_messages_before_reply` hook that scans proposed tool calls through the binding pre-dispatch, plus wrap `execute_function` so direct execution is mediated. Fail-closed on hook-registration failure.

### 3e. OpenAI Agents SDK — ADAPT (native guardrail shim + documented residual)

The SDK (v0.14+) has **native tool guardrails**: `tool_input_guardrails`/`tool_output_guardrails` on `@function_tool`; input guardrails run before execution and can skip/replace/raise tripwire; `ToolExecutionConfig(pre_approval_tool_input_guardrails=True)` runs input checks *before* the approval interruption (https://github.com/mandax94/openai-agents-python/blob/HEAD/docs/guardrails.md — mirror of official docs). **Critical scope limit, from the official docs:** tool guardrails apply **only** to function tools — hosted tools (`WebSearchTool`, `FileSearchTool`, `HostedMCPTool`, `CodeInterpreterTool`, `ImageGenerationTool`), built-in execution tools (`ComputerTool`, `ShellTool`, `ApplyPatchTool`, `LocalShellTool`), handoffs, and `Agent.as_tool()` do **not** use the guardrail pipeline. Our existing `openai_loop.py` covers the raw function-call loop, not this SDK. License: MIT. **Verdict: ADAPT** — thin shim mapping `GovernedBinding` onto the SDK's native `tool_input_guardrails` (fail-closed tripwire on deny/queue); **document the hosted/built-in-tool gap as an explicit residual** — those paths need a separate enforcement point and must never be described as covered.

### 3f. MCP clients — SKIP (built; industry converges on our pattern)

`GovernedMCPClient` already wraps `ClientSession.call_tool` (mediate → only on `"executed"` touch the session; session name-mangled, no accessor). The ecosystem does the same: Microsoft's agent-governance-toolkit `GovernanceKernel.EvaluateToolCall` → `mcpClient.CallTool` (https://devblogs.microsoft.com/dotnet/governing-mcp-tool-calls-in-dotnet-with-the-agent-governance-toolkit/), Vörður's `guard_tool_call(..., require_confirmation=True)` middleware (https://github.com/mhcoen/vordur). **Verdict: SKIP** — no duplication; our adapter is the most complete of the surveyed (P2 description-injection guard + metadata re-validation pre-dispatch, which neither surveyed analog has).

### 3g. Third-party governance-adapter projects — WATCH (competitive)

A cluster of thin adapter projects validates the direction but none has our depth: `agentic-control-plane/acp-governance-sdks` (17 framework scouts — systematic, the one to watch), `razel369/intentfence` (OpenAI Agents SDK + JS, digest-only args), `trustifai/typed_evals` (langchain/crewai/agent-framework adapters), `giselleevita/agent-security-gate` (OpenAI Agents SDK), `mhcoen/vordur` (MCP middleware), `freemason9226/governed-autonomy-substrate` (hash-chained replay log — closest to our evidence story, still no fail-closed engine). **Verdict: WATCH** — re-sweep quarterly; steal patterns only, never code, with license checks.

**Framework verdict summary:** LangChain SKIP(+WATCH middleware) · LangGraph ADAPT (recipe) · CrewAI ADAPT (new shim) · AG2 ADAPT (new shim) · OpenAI Agents SDK ADAPT (native-guardrail shim + residual doc) · MCP clients SKIP · third-party adapters WATCH.

---

## 4. Tier-1 competitor delta (since 2026-10-05)

**Method:** primary sources only, access date 2026-10-05 for all claims. Public material only; no code copied. "Nothing new found" recorded honestly where applicable.

### 4a. Algedonic (algedonic.ai, CEO Sandeep Gopisetty) — WATCH, nothing new

Newest public material remains the **2026-09-30 EIN Presswire release** ("Algedonic Demonstrates Runtime Enforcement for Enterprise AI Agents, Opens Early Access" — https://world.einnews.com/pr_news/945899633/algedonic-demonstrates-runtime-enforcement-for-enterprise-ai-agents-opens-early-access): first public demo at The AI Conference 2026, enforcement "at the point of action," early access opened. No whitepaper update (Framer-hosted whitepaper unchanged): still "Non-Bypassable Governance Sidecar" with patent **#19/403,811 (AI Agentic Control Plane)** the only publicly named one of their "4 patent apps" — **vendor claim, unverified**, no USPTO publication sighting. **No funding announcement, no docs/technical blog, no GitHub, no enterprise customer claims** found. No human-in-the-loop claim anywhere; positioning remains deterministic point-of-action blocking. **Threat delta: none.** Their gaps vs us (no durable HITL approval queues, no offline auditor-verifiable evidence claims) persist. Re-check after any funding or docs sighting.

### 4b. EVE AI Core (EVE NeuroSystems LLC, Jamaurice Holt) — WATCH, nothing new

`jamaurice/eve-core` (https://github.com/jamaurice/eve-core): **5 commits total, created 2026-05-08, last updated 2026-05-18**, 0 stars; README unchanged (CoreGuard decision certification, ECDSA P-384 dual-signed certificates over RFC-8785 claims — vendor claim, unverified; hardware/FPGA phases are their own roadmap labels). `jamaurice/eveaicore`: last updated ~June 2026 (HMAC-SHA256 decision certificates + Merkle chains "Shipped"; CloudHSM/FPGA pending). Blog newest post **2026-09-04** ("Authenticated Doesn't Mean Authorized"); no October material. **No human-in-the-loop addition** — their gap vs us remains. "90 USPTO patent applications" still **vendor claim, unverified**. **Threat delta: none.** Closest conceptual twin (fail-closed pre-execution + signed offline-verifiable evidence) but publicly stalled since summer.

### 4c. Bernstein (github.com/abu-pixel/bernstein fork of sipyourdrink-ltd/bernstein, bernstein.run) — ADAPT (4 patterns) + WATCH

**License check: Apache-2.0, unchanged** (repo metadata + PyPI https://pypi.org/project/bernstein/3.18.0/). Upstream release **v3.20.0 ~2026-09-21** (https://github.com/sipyourdrink-ltd/bernstein/releases/tag/v3.20.0); no commits/releases post-2026-10-01. Maintainer Alex Chernysh (@chernistry), solo.

**Steal-worthy patterns (Apache-2.0, described not copied):**
1. **ADAPT — tamper-falsifiable demo evidence:** their README demo ships a signed run receipt + public key under `docs/assets/demo-run/`, and **CI re-verifies the committed receipt on every push and proves a tampered copy fails**. Directly applicable to our offline-evidence bundle: a `verify` that only ever says "valid" is untested. Falsifiable: golden-receipt + tamper-negative CI check for `gov/evidence_verify_offline.py`.
2. **ADAPT — verify must weigh findings, not just chain integrity:** their v3.19.2 security fix (**GHSA-594x-5h3g-wj34**, PR #5784): `bernstein audit verify` "weighed only chain failures on its success path, so a valid signed chain plus a critical grant-sweep finding printed a green panel and exited zero." Our verify paths should pin the regression test: *valid chain + critical finding ⇒ non-zero / non-green*. Cautionary tale with a commit hash (06850966d).
3. **ADAPT — offline re-projection verbs:** `bernstein replay latest --verify` (recompute journal head, name first divergent step), `bernstein lineage verify <run_id>`, `bernstein audit diagnose <run_id> --signal gate` (name the exact step a failure entered, as a signed receipt). The "diagnose names the step" verb is a good UX shape for our evidence tooling.
4. **STEAL — CI gate "no dead security controls":** v3.20.0 "ci: fail when a security or identity control has no production caller (#5053)" — a CI gate asserting every security/identity control has a production caller. Cheap, directly applicable to our controls/decision-code registry.
5. **WATCH/ADAPT — per-worker-hop trust records + aggregate** (v3.20.0, PR #6050): one signed record per hop with delegation links over the complete signed parent, plus run-level aggregate with member-execution references, mapped onto the agentrust-io/trace-spec Trust Record (https://github.com/agentrust-io/trace-spec/pull/371 — journal hash `H(prev_hash, event_type, payload_hash, index)` is explicitly *not* RFC-8785; only exported digests are). Converges with our VSA/evidence-bundle direction; their annex documents the field-mapping pitfalls if we adopt a hop-record shape.
6. Release hygiene worth noting: release-note **fragments** per-PR under `docs/release-notes/fragments/` rotated by `scripts/rotate_release_notes.py`; every PyPI release ships **Sigstore in-toto attestations via Trusted Publishing** — supply-chain posture worth noting.

**Threat delta: none new.** Bernstein remains the closest OSS analog and the only competitor with shipped, inspectable offline-verification machinery. Still no human-in-the-loop enforcement (deterministic scheduler only), orchestrator-side not point-of-action — our differentiators hold. Solo maintainer ships ~weekly; re-sweep monthly.

| Competitor | New since 2026-10-01 | Threat delta | Verdict |
|---|---|---|---|
| Algedonic | Nothing (latest: 9/30 demo PR) | None — no HITL, no offline evidence, patents unverified | WATCH |
| EVE AI Core | Nothing (repos stale May/Jun; blog 9/4) | None — HITL gap persists, 90-patent claim unverified | WATCH |
| Bernstein | Nothing (latest v3.20.0 ~9/21) | None — differentiators hold | ADAPT (4 patterns) + WATCH |

---

## Verdict table

| # | Item | Verdict | One-line reason |
|---|------|---------|-----------------|
| 1a | CIMD document emission (client role) | ADAPT | Zero SSRF; static doc; interop with CIMD-preferring ASes |
| 1b | CIMD URL shape + document binding validation (no fetch) | ADAPT | Deterministic core; red-first; matches our no-implicit-I/O architecture |
| 1c | CIMD pre-registration intake (§7.2, fetch-once-at-onboarding) | ADAPT | Spec-blessed enterprise pattern; kills request-time SSRF by construction |
| 1d | CIMD request-time fetching | WATCH | figranium caution stands; build only for dynamic-onboarding deployments |
| 2 | Keyed Sigstore bundle as OCI referrer | ADAPT | One function + one audit check; completes the w320 distribution story |
| 3a | LangChain classic adapter | SKIP (+WATCH middleware) | Built + F62-hardened; new `after_model` middleware path watched for funnel drift |
| 3b | LangGraph interrupt→ApprovalQueue recipe | ADAPT | Thin helper; mechanical tool path already covered by langchain shim |
| 3c | CrewAI BaseTool wrapper shim | ADAPT | New `gov/adapters/crewai_tools.py`; no existing adapter; MIT |
| 3d | AG2 hook-based shim | ADAPT | New `gov/adapters/ag2_hooks.py`; target AG2 (autogen in maintenance mode); Apache-2.0 |
| 3e | OpenAI Agents SDK native-guardrail shim | ADAPT | New thin shim on `tool_input_guardrails`; hosted/built-in tools documented as uncovered residual |
| 3f | MCP client adapter | SKIP | Built; most complete of surveyed analogs (P2 + metadata re-validation) |
| 3g | Third-party governance-adapter projects | WATCH | acp-governance-sdks (17 scouts), intentfence, typed_evals, vordur — thin, no fail-closed engine |
| 4a | Algedonic | WATCH | Nothing new since 9/30 demo; no HITL, no offline evidence, patent claims unverified |
| 4b | EVE AI Core | WATCH | Nothing new; repos stale since May/Jun; HITL gap persists |
| 4c | Bernstein tamper-negative CI for evidence verify | ADAPT | Golden receipt + tampered-copy-must-fail CI (Apache-2.0) |
| 4d | Bernstein findings-weighted verify | ADAPT | GHSA-594x-5h3g-wj34 lesson: valid chain + critical finding must not print green |
| 4e | Bernstein re-projection verbs (replay/diagnose) | ADAPT | "Diagnose names the step" UX shape for our evidence tooling |
| 4f | Bernstein no-dead-controls CI gate | STEAL | Fail CI when a security control has no production caller (#5053) |
| 4g | Bernstein per-hop trust records | WATCH/ADAPT | Converges with VSA direction; trace-spec annex documents pitfalls |

## Build recommendations (for wave planning)

- **R1.** `gov/mcp_cimd.py`: (1a)+(1b) — CIMD shape validation + document emission, new `mcp-oauth-cimd-*` codes, pin bump. Red-first: malformed URLs, binding mismatches, secret-bearing documents refused coded.
- **R2.** Pre-registration intake (1c): onboarding-time fetch with the full SSRF control set + document-hash pinning; composes with revocation-push intake for key-rotation events.
- **R3.** `attach_sigstore_bundle` in `gov/evidence_distribute.py` + strict-policy audit check.
- **R4.** Tamper-negative CI for the offline evidence bundle (Bernstein pattern 4c): golden receipt committed, CI proves a tampered copy fails verify.
- **R5.** Findings-weighted verify regression (Bernstein pattern 4d): pin the test "valid chain + critical finding ⇒ non-green/non-zero" on our verify paths.
- **R6.** No-dead-security-controls CI gate (Bernstein pattern 4f): fail when a registered control/decision-code has no production caller.
- **R7.** Monthly re-sweep of `sipyourdrink-ltd/bernstein` releases (solo maintainer, ~weekly cadence, Apache-2.0).
- **R8.** `gov/adapters/crewai_tools.py`: CrewAI `BaseTool` wrapper on `GovernedBinding` (3c); red-first incl. F62-class undeclared-arg audit; sync-execution bridge documented.
- **R9.** `gov/adapters/ag2_hooks.py`: AG2 `process_all_messages_before_reply` hook + `execute_function` wrap (3d); fail closed on hook-registration failure.
- **R10.** OpenAI Agents SDK shim on native `tool_input_guardrails` (3e) + explicit residual doc: hosted/built-in tools, handoffs, `Agent.as_tool()` are NOT covered by the SDK pipeline.
- **R11.** LangGraph `interrupt()` → `ApprovalQueue` recipe + helper (3b); quarterly re-sweep of third-party adapter projects (3g).
