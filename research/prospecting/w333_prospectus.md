# Wave-333 Industry Prospectus: MCP PRM/CIMD Gaps, GPAI-9 Checklist Mapping, PQ Envelope Slot Design, EmpowerID/Omada OSS Verdict, Credential WATCH Audits

**Date:** 2026-10-05 · **Base:** `43d539c7` (wave-332 merge, footer open none / next F417, pin 2062)
**Method:** primary sources only (spec texts, source code, first-party docs, LICENSE files). Every factual claim carries URL + access date 2026-10-05.
**Standing rule honored:** for EVERY verdict the tree was checked FIRST (commands printed). w332's #1 STEAL (RFC 9207 + RFC 8707) has now landed in the tree — this prospectus assesses only what remains.

## Prior-prospectus avoidance

Covered before (not repeated): Landlock/nsjail (w330), MCP RFC 9207 `iss` + RFC 8707 `resource` (w332 §1 — LANDED in `gov/mcp_oauth_binding.py`), liboqs naming table (w332 §2 — verified again below), GPAI ch.9 cadence summary (w332 §3 — corrected and mapped here), GUAC SKIP (w332 §4), Teleport AGPL trap (w332 §5), Bernstein/Attestix WATCH (w332 §6), C2PA/Rekor/offline-verifier/dex/SPIFFE/keto/Cedar (w306–w325).

---

## 1. MCP Authorization spec 2026-07-28 — remaining client/server gaps

**Primary source (read in full, 2026-10-05):** https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization — "Authorization - Model Context Protocol". Corroborating reviews: harekrishnarai/mcp-security-review `references/spec-2026-07-28.md`, rohitg00/ai-engineering-from-scratch `phases/13-tools-and-protocols/18-mcp-auth-production/docs/en.md` (both accessed 2026-10-05).

### 1a. RFC 9728 Protected Resource Metadata — STEAL (genuine gap)

**Tree check (run).** `grep -rniE "9728|protected.resource.metadata|resource_metadata|WWW-Authenticate" gov/*.py` → **zero hits**. No PRM discovery, no PRM validation, no 401 challenge handling anywhere.

**What the spec requires (primary).** Overview item 4: "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC 9728). MCP clients **MUST** use OAuth 2.0 Protected Resource Metadata for authorization server discovery." The client discovers via `/.well-known/oauth-protected-resource` or the `WWW-Authenticate: Bearer resource_metadata="<PRM-URL>"` parameter on a 401 (note: the challenge parameter is `resource_metadata`, a discovery pointer — there is no `resource` parameter in the challenge). The PRM document carries a canonical `resource` identifier and an `authorization_servers` list (at least one entry required). Scope selection order: (1) `scope` from the 401 `WWW-Authenticate` challenge if present, else (2) `scopes_supported` from the PRM document.

**Why this is a steal, not a duplicate.** Wave-332 bound the token to a *deployment-configured* `resource_server` (`check_token_resource`) — deliberately never derived from server metadata. That is the right trust posture (deployment config is the trust root), but it leaves the discovery leg unaudited: a client that fetches PRM and ignores it can be steered to a different AS by a spoofed PRM, and a client that never fetches it cannot detect that the server it is calling is not the server the AS authorized. The steal is the *verification* of PRM against the sealed binding, not trust in PRM:

**Falsifiable next step:** `mcp_oauth_binding.py` gains:
- `fetch_protected_resource_metadata(resource_url)` — fetch + shape-validate the RFC 9728 document (EMITTER CLAIM; never trusted, only checked);
- `check_prm_against_binding(sealed_binding, prm, key)` — refuse coded (new codes, e.g. `mcp-oauth-prm-resource-mismatch`) when the PRM `resource` ≠ the deployment-configured canonical resource; refuse `mcp-oauth-prm-issuer-unknown` when the PRM `authorization_servers` list does not contain the bound AS issuer;
- `parse_www_authenticate_challenge(header)` — extract `resource_metadata` + `scope` from a 401 challenge; the scope feeds the least-privilege scope-selection order (challenge scope first, then PRM `scopes_supported`).

Red-first probes: (a) PRM naming a different `resource` → coded refusal; (b) PRM whose `authorization_servers` omits the bound issuer → coded refusal; (c) 401 challenge scope honored over `scopes_supported` in the request builder; (d) malformed PRM (non-https resource, missing authorization_servers) → coded refusal before any binding use.

**License:** IETF RFC 9728 + published protocol profile — patterns only, no code copied, no encumbrance.

### 1b. Server-side token-passthrough ban — STEAL (unwired, not absent)

**Tree check (run).** Client-side: `check_token_resource` in `gov/mcp_oauth_binding.py` refuses `mcp-oauth-resource-misbound` for A-replayed-at-B — present. Server-side: `grep -rniE "check_token_resource|WWW-Authenticate|bearer" gov/mcp_surface_guard.py gov/mcp_invocation_authz.py gov/mcp_discovery_trust.py` → **zero hits**; `grep -rniE "401|WWW_Authenticate|resource_metadata" gov/*.py` → **zero functional hits**. Nothing in the tree emits a 401, validates a presented token per request, or enforces the ban on the serving side.

**What the spec requires (primary).** "Access Token Usage / Token Handling": "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2" and "**MUST NOT** accept or transit any other tokens." Invalid/expired → HTTP 401; insufficient scope → 403 with `error="insufficient_scope"` (SHOULD) plus `WWW-Authenticate: Bearer error="insufficient_scope" resource_metadata="<PRM-URL>" scope="..."`.

**Why this is a steal.** The refusal vocabulary exists (`check_token_resource`); the *enforcement point* does not. Any MCP server built on our stack today accepts whatever token-shaped bytes arrive — the library cannot refuse what it never sees. This is the server-side half of the wave-332 client work.

**Falsifiable next step:** new `gov/mcp_server_authz.py` (server-side guard): `validate_bearer_request(resource_server, authorization_header, verify_fn)` — per-request: missing/invalid/expired → 401 + `WWW-Authenticate: Bearer resource_metadata="<PRM-URL>"`; audience mismatch → 401 (never 403 — 403 is for scope); insufficient scope → 403 + `insufficient_scope`. Wires `check_token_resource` as the audience check behind a caller-supplied signature verifier (same authenticity-boundary contract as the client function). Red-first probes: (a) token for server A presented at server B → 401, never accepted; (b) no token → 401 with well-formed `WWW-Authenticate` carrying `resource_metadata`; (c) valid token, insufficient scope → 403 `insufficient_scope`; (d) token in query string → refused (spec: never in query).

**License:** IETF/OAuth profile — patterns only, no encumbrance.

### 1c. Issuer-keyed credential isolation — NO STEAL (covered by construction)

**Tree check (run).** `grep -rniE "client_secret|client_secret_basic|private_key_jwt" gov/mcp*.py` → **zero hits**: the MCP OAuth path handles **no client credentials at all**. `seal_as_binding(as_issuer, client_id, key)` seals `(issuer, client_id, token_endpoint_allowlist)` per-AS under the deployment key; the verdict carries `issuer_digest` so downstream issuance chains to the exact AS.

**What the spec requires (primary, via mcp-security-review):** "Credentials **MUST** be keyed by `issuer` and **MUST NOT** be reused across authorization servers."

**Why no steal.** The requirement is satisfied vacuously and then some: there are no client credentials to re-use across ASes, and the binding that *does* exist is keyed by issuer by construction. Document as covered; no code.

### 1d. CIMD (Client ID Metadata Documents, SEP-991) — ADAPT (backlog, not a gap today)

**Tree check (run).** `grep -rniE "cimd|client.instance.metadata|SEP-991" gov/*.py evals/*.py` → **zero hits**. There is also no dynamic client registration code anywhere — the module assumes a pre-registered `client_id`.

**What the spec requires (primary).** Overview item 2: "Authorization servers and MCP clients **SHOULD** support OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document-00)." Item 3: DCR (RFC 7591) is **MAY**, "deprecated and retained for backwards compatibility." Registration priority: pre-registered → CIMD → DCR.

**Why ADAPT-backlog.** We use mechanism #1 (pre-registered) exclusively, which the spec lists first and never deprecates. CIMD matters only if we ever need *dynamic* client onboarding (fleet-deployed agents registering themselves). The shape to adapt when that day comes: the client presents a `client_id` that is an HTTPS URL serving its own metadata document; the AS/client fetches it with SSRF/rebinding controls and validates `client_id == document URL` (the figranium HOSTED_MCP.md note is the cautionary tale: they deliberately do NOT advertise CIMD yet because "securely dereferencing attacker-controlled client metadata URLs requires DNS-aware SSRF/rebinding controls" — https://github.com/figranium/figranium-mcp/blob/HEAD/HOSTED_MCP.md, accessed 2026-10-05). Verdict: no code now; record the SSRF-gated design constraint for the future lane.

### 1e. Spec-deviation note: our `iss` posture is stricter than the spec

**Primary source, Authorization Response Validation table.** The spec's matrix: `authorization_response_iss_parameter_supported=true` + absent `iss` → Reject; `false`/absent + absent `iss` → **Proceed**. Our `validate_authorization_response` refuses missing `iss` **unconditionally** (`mcp-oauth-iss-missing`) — fail-closed beyond the spec. This is a deliberate hardening (the spec itself says "A future revision ... is expected to upgrade authorization server inclusion of `iss` from SHOULD to MUST. Implementers are encouraged to emit and validate `iss` now"), but it is an interop decision: ASes that neither emit `iss` nor advertise support will fail against our client. Keep the posture; document the deviation in the module docstring so a future interop lane can relax it deliberately rather than discovering it.

### 1f. Step-up authorization — ADAPT (carried from w332 §1, still backlog)

Spec: 403 `insufficient_scope` → client re-authorizes with scope-union → retry-limit. The §1b 403 emission is the prerequisite; step-up client logic follows.

---

## 2. GPAI Code of Practice ch. 9 — Measure 9.2/9.3/9.4 mapped to `gov/incident_export.py`

**Primary source (read, 2026-10-05):** Code of Practice for General-Purpose AI Models, Safety and Security chapter, via https://api.eubound.eu/docs/legal-corpus/archive/ec-gpai-code-safety-security-2025.pdf (corroborated by smith-mern/aisecuritysecondbrain transcription).

**Correction to w332 §3:** Measure 9.2 lists **nine** numbered points, not seven:
(1) start/end dates (or best approximations); (2) resulting harm + victim/affected group; (3) chain of events; (4) the model involved; (5) material describing the model's involvement; (6) the Signatory's response (done/intended); (7) recommendations to the AI Office/NCAs; (8) root-cause analysis incl. the model's outputs, contributing factors, inputs used, and failures/circumventions of systemic-risk mitigations; (9) post-market-monitoring patterns (Measure 3.5) reasonably connected, incl. near-miss data. "If Signatories do not yet have certain relevant information ... they will record that in their serious incident reports" — **explicit unavailable-marking is mandatory**.

Measure 9.3 timelines (from *awareness*, which **includes reasonably suspected** model involvement): critical-infrastructure disruption ≤ 2 days; **serious cybersecurity breach (exfiltration, cyberattack) ≤ 5 days**; death ≤ 10 days; serious harm to health/fundamental rights/property/environment ≤ 15 days. **Intermediate report at least every 4 weeks** while unresolved; **final report ≤ 60 days after resolution**; consolidated reporting permitted for similar incidents within a window. Measure 9.4: **retain ≥ 5 years** from the later of documentation date or incident date.

**Tree check (run).** `gov/incident_export.py` (1173 lines) has: the 5-section Art. 73 template (admin info, AI system data, incident description, preliminary analysis, comments), Art. 73 deadline tiers (2/10/15 days — "suggested tier ... the operator confirms"), causal chain, redaction, anchor. `grep -niE "9\.2|9\.3|9\.4|five.year|intermediate|60.day|cybersecurity.breach|5.day|unavailable" gov/incident_export.py` → **zero functional hits**.

**Gap map (what's missing, point by point):**

| GPAI requirement | Tree status |
|---|---|
| 9.2 points (1)–(3): dates, harm+victims, chain of events | **Partial** — sections 1/3/4 cover dates, persons affected, causal chain |
| 9.2 point (4): the model involved | **Missing as a field** — "AI system data" names the system, not the model version implicated |
| 9.2 point (5): material describing the model's involvement | **Missing** — no dedicated involvement-evidence section |
| 9.2 point (6): response done/intended | **Partial** — "corrective actions" in preliminary analysis |
| 9.2 point (7): recommendations to authorities | **Missing** |
| 9.2 point (8): root-cause analysis incl. model outputs, inputs, mitigation failures/circumventions | **Missing as a checklist** — `_root_cause_pointers` exists but is not a 9.2(8)-shaped field |
| 9.2 point (9): post-market-monitoring patterns / near misses | **Missing** |
| Explicit "unavailable" marking per missing point | **Missing** — no unavailable-marking mechanism |
| 5-day serious-cybersecurity-breach band | **Missing** — Art. 73 has no such class; our highest cyber-adjacent tier is 15 days |
| 4-week intermediate cadence | **Missing** — no intermediate-due computation |
| 60-day final report | **Missing** |
| 5-year retention | **Missing** — no retention policy surfaced |
| Awareness includes reasonable suspicion | **Unconfirmed** — `detect_incidents` keys on trigger events; suspicion-tier onset is not modeled |

**Verdict: ADAPT** (narrowed from w332's blanket ADAPT — the table above is the build spec). 

**Falsifiable next step:** `incident_export.py` gains a `build_gpai9_report(incident)` producing the 9-point checklist with per-point `value | UNAVAILABLE` marking (a point that is neither present nor explicitly marked unavailable refuses `incident-gpai9-incomplete`); clock mapping adds the 5-day cybersecurity class keyed on suspicion-inclusive awareness; `intermediate_due(initial_report_ts)` and `final_due(resolution_ts)` computed; retention floor constant `GPAI9_RETENTION_YEARS = 5` asserted by the verifier. Red probes: (a) report missing point (7) without unavailable-mark → coded refusal; (b) cybersecurity-class incident with awareness 6 days ago, no initial report → timeliness violation flagged; (c) resolved 61 days ago, no final report → violation flagged; (d) intermediate overdue at 29 days unresolved → flagged.

**License:** Commission-published regulatory document — public source, no license trap; cite as regulatory authority.

---

## 3. liboqs — reserved PQ evidence-envelope slot (format-only design)

**Tree check (run).** `grep -rniE "pq_alg|mldsa|ml-dsa|mlkem|pqc" gov/evidence* gov/evidence/*.py gov/*bundle*.py` → **zero hits**: still no slot (w330 §2 / w332 §2 unbuilt).

**Naming re-verified (primary, 2026-10-05):** https://raw.githubusercontent.com/open-quantum-safe/oqs-provider/main/ALGORITHMS.md — signature identifiers: `mldsa44` (0x0904), `mldsa65` (0x0905), `mldsa87` (0x0906); `slhdsasha2128s/f`, `slhdsasha2192s/f`, `slhdsasha2256s/f`, `slhdsashake128s/f`, `slhdsashake192s/f`, `slhdsashake256s/f`; `falcon512`, `falcon1024` (+ padded variants); hybrid `p256_mldsa44` etc. (lowercase, no hyphens — matches w332's table).

**Envelope anatomy (tree).** `gov/evidence_envelope.py`: DSSE-shape `{payload, payloadType, signatures}` with exactly-one-signature discipline (`dsse-envelope-multi-signature` on two), Ed25519 over PAE bytes, per-record and manifest seal/open.

**Slot design (format-only, no crypto — for the build lane):**
- The signature entry gains two optional fields: `pq_alg_id` (string) and `pq_signature` (bytes/hex).
- Closed table `PQ_ALG_IDS = frozenset({"mldsa44","mldsa65","mldsa87","slhdsasha2128s","slhdsasha2128f","slhdsasha2192s","slhdsasha2192f","slhdsasha2256s","slhdsasha2256f","slhdsashake128s","slhdsashake128f","slhdsashake192s","slhdsashake192f","slhdsashake256s","slhdsashake256f","falcon512","falcon1024"})` — unknown identifier refuses `evidence-pq-unknown-alg` (same closed-vocabulary discipline as the decision graph).
- While disabled (the only v1 state): any `pq_alg_id` present refuses `evidence-pq-not-enabled`; any non-empty `pq_signature` refuses `evidence-pq-not-enabled`; the classical Ed25519 path is byte-identical (no format break for existing bundles — old bundles verify, new bundles with the slot empty verify).
- Activation rule (documented, not implemented): when Sigstore's ML-DSA enums leave Experimental, the slot activates per-algorithm without a format bump — the table is the extension point.

Red-first probes for the build lane: (a) unknown `pq_alg_id` → coded refusal; (b) `pq_signature` non-empty while disabled → coded refusal; (c) `pq_alg_id: "mldsa44"` while disabled → `evidence-pq-not-enabled`; (d) classical bundle byte-identical before/after.

**License:** **MIT verified** (w332 verified the liboqs LICENSE; re-confirmed the naming source is oqs-provider, same project). No code copied — identifiers only.

---

## 4. EmpowerID / Omada open source — verdict: NOTHING TO READ

**EmpowerID.** Search (2026-10-05): the only `github.com/empowerid/*` repo surfaced is `empowerid/nginxreverseproxy`, last touched ~3037 days ago and self-described as "the private repository" — no agent-governance code, nothing maintained. All other hits are third-party labs, Upwork experiments, or unrelated template projects. **No meaningful open source exists.**

**Omada (Omada A/S, the Danish IGA acquirer — not TP-Link Omada SDN, which pollutes every search).** `https://github.com/omadaidentity` exists as an org page but shows no public repositories/members. Third-party comparison (itechguides.com, accessed 2026-10-05): "No open-source deployment option" for Omada Identity Cloud. **No open source.**

**Verdict: SKIP (nothing to steal because nothing is published).** The user's question is answered negatively with evidence. Prospecting consequence: EmpowerID/Omada remain a *documentation-only* WATCH — their public docs (missions, authority bounds, credentials-without-custody) are the only observable surface; treat marketing claims as unverified until their behavior is observable.

---

## 5. EmpowerID/Omada WATCH audits against our tree

### 5a. Per-tool rate limiting for the tool surface — ADAPT (gap)

**Tree check (run).** `grep -niE "rate|throttle|per.minute|window" gov/mcp_invocation_authz.py gov/mcp_surface_guard.py` → **zero hits**. `gov/executor.py` has `rate_limit` policy keys (per-run egress-byte caps, tamper-evidence flood guard) and `gov/mcp_invocation_authz.py` has an argument-budget gate — but **no per-tool invocation-rate limit** (N calls to tool T per time window) exists anywhere on the tool surface.

**Why it matters.** An agent (or a prompt-injected agent) can legally invoke an allowed tool thousands of times — exfiltrating via repeated small reads, or burning budget — while every individual call passes authorization. Rate-per-tool is the standard mitigation (and the EmpowerID "govern each consequential action" framing implies it).

**Falsifiable next step:** `mcp_invocation_authz.py` gains a per-`(server::tool)` sliding-window counter: policy declares `tool_rate_limits: {"server::tool": {"max_calls": N, "window_seconds": W}}`; the N+1st call inside the window refuses coded (new code, e.g. `mcp-tool-rate-exceeded`) *before* execution; counters are in-memory per process with documented reset semantics (no persistent state to poison). Red probes: (a) N+1 calls in-window → coded refusal; (b) window expiry resets; (c) limits on tool A don't affect tool B; (d) no policy entry → unlimited (fail-open only where the deployer said so — documented).

### 5b. Refresh-token single-use race guard — audit: RACE WINDOW PRESENT

**Tree check (run, code read).** `gov/agent_identity.py` `RefreshTokenStore.refresh`: checks `rec["rotated"]`, and on reuse revokes the whole chain (`identity-refresh-reuse-detected` — the dex-adapted reuse detection). **But the check-then-set is not atomic**: `if rec["rotated"]: ... revoke` ... `rec["rotated"] = True` with **no lock**. Two concurrent `refresh()` calls with the same token can both pass the `rotated` check before either sets it — both mint new identity tokens, and only the *second* reuse is detected. In a single-threaded deployment this is unreachable; in any threaded/async server it is a live double-spend window.

**Verdict: ADAPT (small, surgical)** — wrap `refresh()`'s check-and-rotate in a `threading.Lock` (or document the single-threaded assumption in the class docstring and refuse to instantiate under a threaded server — the lock is cheaper). This is an audit-grade catch, not a finding: exploitability depends on the deployment threading model, which the module does not declare. Falsifiable probe for the build lane: two threads racing `refresh()` on one token → exactly one succeeds, the other gets `identity-refresh-reuse-detected`, chain revoked exactly once.

Note the spec angle (primary, MCP 2026-07-28 §Refresh Tokens): "MCP Clients **MUST** keep refresh tokens confidential in transit and storage" and OAuth 2.1 §4.3.1 makes rotation a MUST for public clients — our rotation exists; the race guard is what makes it *mean* single-use.

### 5c. No-silent-plaintext-fallback for credential storage — NO STEAL (covered)

**Tree check (run).** `gov/sentinel_substitution.py` `_attested_decision`: attestation-mandatory credential with no trust anchor configured → refused with **"(no silent fallback to host-only)"** — the exact property, loud and coded. `gov/leased_credentials.py`: "response wrapping returns a one-use token instead of the plaintext"; KMS/Vault transit adapter present (`gov/kms_vault.py`). `grep -rniE "plaintext.fallback|fallback.*plaintext|unencrypted.fallback" gov/*.py` → zero silent-fallback paths.

**Verdict: covered.** No code. (The residual to keep watching: at-rest encryption of the lease store is KMS-mediated; a deployment without KMS configured should fail closed rather than store plaintext — worth a one-line probe in a future lane, not a prospectus steal.)

---

## Prioritized build list (strongest first)

1. **MCP server-side token guard** — `gov/mcp_server_authz.py`: per-request audience validation via `check_token_resource`, 401 + `WWW-Authenticate: Bearer resource_metadata=...` challenges, 403 `insufficient_scope` (§1b). The client half shipped in wave-332; without this, the ban is a library function nobody calls.
2. **RFC 9728 PRM verification** — fetch + shape-validate + check against sealed binding (`mcp-oauth-prm-resource-mismatch`, `mcp-oauth-prm-issuer-unknown`) + 401 challenge scope parsing (§1a). Spec-MUST for clients.
3. **GPAI-9 report builder** — 9-point checklist with unavailable-marking, 5-day cybersecurity band, 4-week intermediate + 60-day final computation, 5-year retention floor (§2). Live law.
4. **Per-tool rate limiting** — sliding-window counters in `mcp_invocation_authz.py` (§5a).
5. **Reserved PQ envelope slot** — closed `pq_alg_id` table, refuse-while-disabled, classical path byte-identical (§3). Format-only.
6. **Refresh-token race guard** — lock around `RefreshTokenStore.refresh` check-and-rotate (§5b).
7. **WATCH:** CIMD when dynamic client onboarding becomes a deployment shape (SSRF-gated design recorded, §1d); Bernstein offline governance re-projection (open question from w332 §6); Sigstore ML-DSA enums leaving Experimental (activates §3 slot); EmpowerID/Omada docs-only (no OSS to read, §4).

## Explicit non-steals (tree-checked)

- Issuer-keyed credential isolation (spec §"keyed by issuer"): no client credentials in the MCP path; binding keyed by issuer by construction (§1c).
- Silent-plaintext-fallback ban: refused loudly in `sentinel_substitution.py`; one-use tokens instead of plaintext in `leased_credentials.py` (§5c).
- Token-passthrough ban *client-side*: `check_token_resource` + `delegation_tokens.py` (§1b — the steal is the unwired server side, not the check itself).
- GUAC / Teleport / Bernstein verdicts stand from w332 (no new evidence).

## Open questions

- `detect_incidents` suspicion-tier onset: does awareness include "reasonably suspected" model involvement (GPAI 9.3), or only trigger events? (§2)
- Does the offline verifier re-project approval/budget decisions from the bundle (Bernstein's `governance verify` shape)? (carried from w332)
- `gov/evidence/crosswalk.py` Annex XI/XII coverage (carried from w330)
- At-rest lease-store behavior when no KMS is configured: fail closed or plaintext? (§5c residual)
- MCP spec LICENSE for quoting spec prose (implementation targets IETF RFCs — no encumbrance — but confirm before quoting)
- Final Art. 73 guidance publication date — re-run §2 gap analysis when it lands
