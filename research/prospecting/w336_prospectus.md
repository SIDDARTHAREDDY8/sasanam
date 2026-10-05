# Wave-336 Industry Prospectus: CIMD Safe-Subset Build Spec, Rekor-Pattern Witness (deeper), Tier-1 Delta, New-Surface Steal Check

**Date:** 2026-10-05 · **Base:** `c4acf39e` (wave-335 merge) · **Lane:** wave-336 lane 6 (research)
**Method:** primary sources only (spec texts, source code, first-party docs/release notes, LICENSE files), access date 2026-10-05 for all claims. Tree checked FIRST for every verdict (commands printed). $0 spend.
**Standing rule honored:** prior prospectuses (w320 distribution, w321 witness/monitor, w332, w333, w335) are not repeated — only deltas, remaining gaps, and the build-ready specs this wave was asked for.

## Prior-prospectus avoidance

Covered before (not repeated): CIMD SSRF constraint analysis (w333 §1d, w335 §1 — this wave converts it to a build-ready spec); Sigstore-bundle v0.3 keyed shape (w320 + w321 — LANDED `gov/sigstore_bundle.py`); OCI referrer wiring gap (w335 §2, ADAPT — still open, see carry-forward); framework adapter survey (w335 §3 — CrewAI/AG2/OpenAI-Agents-SDK/LangGraph ADAPTs are being built by wave-336 lanes adapters12/adapters34 RIGHT NOW, do not re-litigate); witness checkpoint publication + fail-closed monitor loop + offline export (w321 — LANDED `gov/witness_policy.py`, `gov/witness_publish.py`, `gov/witness_monitor.py`, `gov/checkpoint_note.py`); gossip SKIP (w320, w321); Bernstein 4 ADAPT patterns (w335 §4c — still open, see carry-forward); liboqs PQ envelope slot (w333 §3, w335 — LANDED `gov/pq_envelope.py`, format-only, disabled).

---

## 1. CIMD safe-subset — build-ready spec

**Spec status re-verified 2026-10-05:** `draft-ietf-oauth-client-id-metadata-document-02` is still the latest WG revision (dated 6 July 2026, expires 7 January 2027; https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/). No -03, no RFC. The w335 analysis stands; what follows is the implementable spec.

**Tree check (run):** `grep -rniE "cimd|client.id.metadata" gov/*.py evals/*.py` → zero hits (still absent). `gov/mcp_oauth_binding.py` seals `(issuer, client_id, token_endpoint_allowlist)` per-AS; coded refusal convention is `mcp-oauth-*` constants + registry entries in `gov/decision_codes.py` (domain `mcp-oauth`). The PRM module (`gov/mcp_prm.py`) establishes the architecture pattern to follow: **caller-supplied fetcher, verification core never does implicit I/O**.

### 1a. Module shape: `gov/mcp_cimd.py` (stdlib only, no network imports)

Three public surfaces, matching the w335 three-piece verdict:

### 1b. Part A — document EMISSION (client role). Zero SSRF. Pure win.

- **Endpoint:** `https://<deployment-domain>/oauth/client` — the domain comes from deployment config, never from agent input. The deployment operator provisions this; the module only *renders* the document.
- **Document fields (JSON, RFC 8259):**
  - `client_id`: the URL itself (string equality with the serving URL — the draft's binding rule).
  - `client_name`: operator-configured display name.
  - `redirect_uris`: array; **same-origin-locked** to the document's own origin. The draft §8.1 *permits* the AS to impose this restriction ("may impose restrictions ... for example to restrict the redirect_uri to the same-origin as the Client ID Metadata Document"); we impose it unconditionally. Documented deviation from the Solid-OIDC back-compat allowance: we are not back-compat with Solid-OIDC.
  - `token_endpoint_auth_method`: `"private_key_jwt"` (the draft §8.2 example shape — `token_endpoint_auth_method` + `jwks_uri` — verified in the draft text 2026-10-05).
  - `jwks_uri`: `https://<deployment-domain>/.well-known/jwks.json` serving our Ed25519 keys (https-only).
  - `logo_uri`: OPTIONAL, https-only. **We never auto-fetch logos** (the draft says an AS "SHOULD prefetch" the logo; prefetching is a new SSRF surface — our documented deviation is to display the client_id hostname instead, which the draft itself offers as the fallback: "the authorization server SHOULD display the hostname of the client_id").
- **Explicitly never emitted:** any `client_secret*` member (we handle no client secrets at all — w333 §1c, vacuously satisfied); `software_statement` (out of our threat model; ignored if seen inbound, never emitted).
- **Serving contract:** 200 OK, `Content-Type: application/json` (draft §5: the document MUST be served with 200 OK; all other statuses are errors).
- **Falsifiable:** shape battery pins the emitted bytes against every rule in §1c; a byte-change to the emitter breaks the pin.

### 1c. Part B — URL shape validation + document binding (pure, no fetch). The deterministic core.

`validate_client_id_url(url) -> None` (raises coded `CIMDError`):

| # | Rule | Draft source | Strictness |
|---|------|--------------|------------|
| 1 | scheme == `https` | §3 MUST | as spec |
| 2 | no userinfo component | §3 MUST NOT | as spec |
| 3 | port MAY be present | §3 MAY | as spec |
| 4 | path component MUST be present | §3 MUST | as spec |
| 5 | path MUST NOT be empty or `/` | §3 NOT RECOMMENDED for `/` | **stricter** (fail-closed: a root-path document collides with site content; the draft's own rationale) |
| 6 | no `.` / `..` path segments | §3 MUST NOT | as spec |
| 7 | no query component | §3 SHOULD NOT | **stricter** (refuse; fail-closed) |
| 8 | no fragment component | §3 MUST NOT | as spec |
| 9 | comparisons by **simple string comparison** (RFC 3986 §6.2.1) — `https://example.com/client` ≠ `https://example.com:443/client` | §3 | as spec (pin a regression test on the `:443` example from the draft text) |

`check_document_binding(document, fetch_url)`: `document["client_id"] == fetch_url` by string equality (draft §4: "A Client Identifier URL MUST be associated with a set of client metadata ... available at the Client Identifier URL"). Mismatch → `mcp-oauth-cimd-binding-mismatch`.

`validate_document_shape(document)` (used by intake, Part C):
- `client_id` REQUIRED, string, must itself pass `validate_client_id_url`.
- If `token_endpoint_auth_method == "private_key_jwt"` then `jwks_uri` REQUIRED and https (draft §8.2: the AS "MUST require client authentication ... using the corresponding key discovered from the client's metadata document" — a private_key_jwt claim without a discoverable key is a misbinding; refuse).
- `redirect_uris` (if present): every entry https AND same-origin as `client_id` (our §8.1 restriction from §1b, applied symmetrically inbound).
- `logo_uri` (if present): https only; **never fetched** (see §1b deviation).
- Any key starting with `client_secret` → `mcp-oauth-cimd-credential-present` (credential smuggling via metadata is refused, not ignored — cf. the F94 block-marker lesson: match the prefix deliberately, document it).
- Unknown fields: **ignored** (MUST-ignore-unknown — the C2SP rotation lesson, applied to document evolution).

**Refusal codes** (new, domain `mcp-oauth`, registered in `gov/decision_codes.py` following the existing `mcp-oauth-*` convention):
`mcp-oauth-cimd-url-not-https`, `mcp-oauth-cimd-url-userinfo`, `mcp-oauth-cimd-url-dot-segment`, `mcp-oauth-cimd-url-query`, `mcp-oauth-cimd-url-fragment`, `mcp-oauth-cimd-url-root-path`, `mcp-oauth-cimd-binding-mismatch`, `mcp-oauth-cimd-document-malformed`, `mcp-oauth-cimd-credential-present`, `mcp-oauth-cimd-redirect-origin-mismatch`.

**Red-first battery** (`evals/w33x_cimd_probes.py`): one bypass probe per rule row above (userinfo smuggling, dot-segment traversal, query smuggling, fragment, `:443` equivalence confusion, binding mismatch, secret-bearing document, cross-origin redirect_uri, private_key_jwt without jwks_uri). All must refuse coded.

### 1d. Part C — pre-registration intake (draft §7.2 pattern). Fetch ONCE at onboarding, never at request time.

This is the draft's own enterprise track ("This deployment pattern is expected to be common in enterprise environments ... There is no obligation to support dynamic client onboarding" — draft §7.2, verified in draft text 2026-10-05). It kills the request-time SSRF surface **by construction**: there is no request-time fetch to attack.

- **Trigger:** operator-driven onboarding only. No agent-reachable API initiates a fetch.
- **Transport:** caller-supplied `fetcher` (the `fetch_prm_document` pattern — deployment owns the socket; the verification core never does implicit I/O).
- **Fetch control set** (all from the draft's own §§5/8.6, verified in draft text 2026-10-05):
  - MUST NOT follow redirects; non-200 → error, abort (`mcp-oauth-cimd-fetch-redirect`, `mcp-oauth-cimd-fetch-non200`).
  - DNS-pin the resolved IP before connect; refuse if re-resolution differs (rebinding control; our addition, documented as stricter than the draft).
  - Refuse any resolution to RFC 6890 special-use ranges (draft §8.6 MUST NOT; loopback included).
  - https scheme only (draft §8.6 SHOULD "only fetch or parse URLs with known and supported URI schemes").
  - 5 KB read cap, over-limit → error (draft §8.7, per w335 verification).
  - Timeout (deployment-configured); respect cache headers, never cache errors or malformed documents (draft §5.2).
- **Post-fetch:** run Part B validation (`validate_client_id_url` + `check_document_binding` + `validate_document_shape`); then **pin `sha256(document_bytes)`** in deployment config. Request-time checks compare against the pinned copy only.
- **Key rotation (§8.4.1 composition):** on re-onboarding, if the `jwks_uri` content hash differs from the pinned hash, emit a **revocation event** into the CAEP/SSF revocation-push intake (w333) — a rotated key is a revocation-shaped event, not a silent re-pin. New code: `mcp-oauth-cimd-key-rotated` (advisory, not a refusal).
- **Domain trust (§8.9 composition):** the allowlist of trusted domain patterns (e.g. `*.example.com` = known operator) lives in **deployment config**, never in fetched metadata — same trust-root placement as `seal_as_binding`.
- **Deliberately NOT implemented in v1:** the draft §8.6 dev/test loopback exception ("MAY relax ... when the authorization server itself is also running on a loopback address"). Production-only rule; a dev override needs an explicit deployment opt-in flag, not a code path that can drift into production. Document the omission.
- **Fetch-side refusal codes:** `mcp-oauth-cimd-fetch-ssrf-range`, `mcp-oauth-cimd-fetch-too-large`, `mcp-oauth-cimd-fetch-scheme`, `mcp-oauth-cimd-fetch-timeout`, `mcp-oauth-cimd-pin-mismatch`.

### 1e. Explicitly deferred (WATCH, not build)

- **Request-time fetching** with DNS-aware SSRF/rebinding controls — the figranium caution stands (w333 §1d). Build only when dynamic onboarding becomes a real deployment shape.
- **Operating a CIMD Service** (draft appendix — provisioning Client Identifier URLs for developers). The appendix itself warns it is "effectively acting as a proxy for static client registration" with "security and reputation implications" — we do not operate one.
- **Verdict: ADAPT** — build Parts A+B now (R1), Part C when a deployment onboards third-party CIMD clients (R2). License: IETF draft — patterns only, no code copied; IETF Trust Legal Provisions apply to extracted code components (none extracted). Re-check on RFC publication.

---
## 2. Sigstore-bundle distribution follow-up + Rekor-pattern witness, one level deeper

### 2a. Industry state re-verified 2026-10-05

- **Sigstore's public witness network has NOT launched.** `sigstore/rekor-tiles` CLIENTS.md (updated ~2026-10-01, read 2026-10-05 — https://github.com/sigstore/rekor-tiles/blob/HEAD/CLIENTS.md): "Future: Witnessing ... In the initial launch of Rekor v2, checkpoints will not be witnessed, while we wait for the launch of a public witness network. Clients do not need to implement verification of witness signatures initially." The witness policy "will be distributed by Sigstore's TUF root" when it launches. This answers w321 open question 7: **still pending, no launch detected.** Rekor v2 is GA since 2026-05 (third-party skill doc, unverified version claim — treat as approximate).
- **No one in production has shipped the witness-network operations layer yet** — which means our local stack (`gov/witness_policy.py` signed witness-policy artifact, `gov/witness_publish.py` synchronous cosigning, `gov/witness_monitor.py` fail-closed loop, `gov/checkpoint_note.py` C2SP notes, `gov/rekor_anchor.py` `RekorWitness` that recomputes the Merkle root before cosigning) is at parity with the industry's *published* state, and ahead on the signed witness-policy artifact (w321's greenfield — still no deployed standard).

**Tree check (run):** `gov/witness_consistency.py::require_cosignatures`, `gov/witness_publish.py::publish_checkpoint` (synchronous cosignature collection), `gov/rekor_anchor.py::RekorWitness.cosign_checkpoint` (recomputes root from leaves, records equivocations), `gov/witness_rekor.py::anchor_evidence` (bundle digest → local Merkle witness log → offline receipt) all present. The remaining gap is NOT cryptographic — it is the **witness-network operations design**: who the independent witnesses are for a deployment's evidence log, and the anchoring policy. That is the "one level deeper."

### 2b. The Rekor-pattern witness for OUR evidence envelopes — remaining design

**What the witness is for (the standing lesson, restated):** the witness proves the *evidence log* is append-only (anti-equivocation), not that any bundle is true. `anchor_evidence` already binds bundle digests into the local Merkle log with checkpoint-first offline receipts (`witness-rekor-digest-mismatch` kills cross-bundle receipt travel). The witness network below is what makes the *checkpoint* trustworthy to a third party.

**(i) Independent witness operators (the Rekor production shape, adapted).**
- Witnesses are **separate operators**, not the log operator: each runs the `RekorWitness` discipline — recompute the Merkle root from served leaves and require equality with the checkpoint's claimed root before cosigning (the wave-193 lesson is load-bearing here: an attacker holding the real operator key can forge a same-size checkpoint with a different root whose signature *verifies*; only independent Merkle recomputation detects it). A cosignature over a signature-valid-but-dishonest checkpoint is the failure mode the whole layer exists to prevent.
- **Diverse trust placement** (industry standard practice; cf. the third-party yubi-os Rekor v2 skill's 3-of-5 recommendation — third-party, unverified, cited as practice not authority): witnesses on different infrastructure, different operators, different regions. Minimum viable: 3 witnesses, quorum 2 (tolerates one witness outage without freezing the evidence pipeline — the availability budget from w320's cross-cutting rules applies: a fail-closed witness set that can't reach quorum *freezes checkpoint publication*, and the runbook must say so).
- **Onboarding/rotation via the signed witness-policy artifact** (`gov/witness_policy.py` — already built): threshold-signed policy updates, overlap-then-retire rotation, N+1 version monotonicity. A witness key DROP requires a threshold-signed strictly-newer version. The auditor pins the policy-signing key, never the witness keys directly.
- **Witness liveness contract:** persist-before-respond (w321 — a witness MUST NOT resume cosigning from the log's current head after losing state); cosignature timestamps bound (reject future-dated per C2SP MAY); the monitor's `max_checkpoint_staleness_seconds` policy bounds staleness.
- **Falsifiable:** red-first battery — a witness presented with a signature-valid but root-dishonest checkpoint MUST refuse and record the equivocation (the `RekorWitness` contract, already pinned); a checkpoint carrying an unknown witness line MUST still verify (MUST-ignore rotation rule, already pinned); dropping below quorum MUST freeze publication with a coded refusal, not silently publish unwitnessed.

**(ii) Anchoring policy for evidence envelopes (the deployment decision).**
- Which bundles enter the witness log: every exported evidence bundle by default (the log is cheap; selective anchoring creates "why wasn't this anchored" audit gaps). Deployment MAY narrow by policy, but narrowing is itself a governed, audited decision.
- Checkpoint cadence: the synchronous-cosigning cost is real — Rekor v2's documented mitigations are ≥20s client timeouts and increased checkpoint intervals (rekor-tiles CLIENTS.md). Our `publish_checkpoint` cosigns synchronously at publish time; the deployment sets the checkpoint interval explicitly, and the runbook budgets the witness-outage freeze (fail-closed on both sides is stricter than production — w320 cross-cutting rule, restated because it bites here).
- The monitor loop (`gov/witness_monitor.py`) runs against our own published checkpoints with the three-conjunct gate (authenticated ∧ ¬tree_bad ∧ leaf_verified), alert-before-leaves ordering, and the missing-fringe fix (backfill-or-alert, not silent non-advance — w321).

**(iii) What stays OUT.**
- **VSA decision packets** remain the next build-order step after the witness (w314 order) — not this design.
- **No Rekor cosplay:** our log is not Rekor; receipts stay in our own format. When Sigstore's public witness network launches, the interop question is whether our *keyed bundles* (not our log) should additionally carry a public-Rekor inclusion proof — WATCH, not build.
- **Verdict: ADAPT** — the cryptography and wire formats are built; the remaining work is the witness-network operations design above (operator runbook + quorum/interval policy + red-first equivocation battery). No new code patterns to steal: Sigstore hasn't shipped theirs either.

---

## 3. Tier-1 competitor delta (since the w335 pass, 2026-10-05)

**Method:** primary sources only, access date 2026-10-05. "Nothing new found" recorded honestly.

### 3a. Algedonic — WATCH, nothing new

Latest public material remains the **2026-09-30 EIN Presswire release** (syndicated copies crawled within the last 5 days; no new release since). No whitepaper update, no funding announcement, no docs/technical blog, no GitHub, no enterprise customer claims, no human-in-the-loop claim. Positioning unchanged: deterministic point-of-action blocking. **Threat delta: none.**

### 3b. EVE AI Core — WATCH, nothing new

`jamaurice/eve-core`: last updated **139 days ago** (still the 5-commit May 2026 state). `jamaurice/eveaicore`: last updated **108 days ago**. Newest blog post remains **2026-08-31** ("Open at the Edges, Sovereign at the Core"). No October material, no human-in-the-loop addition, "90 USPTO patent applications" still vendor-claim-unverified. **Threat delta: none.** (Note: `vercel/eve` — "The Open Framework for Building Agents," Apache-2.0, 5,457 stars, 237 releases — is an unrelated name collision, not EVE AI Core. Do not conflate.)

### 3c. Bernstein — WATCH, nothing new since v3.20.0

Upstream `sipyourdrink-ltd/bernstein`: latest release **v3.20.0 (2026-09-20)**; latest commit sightings **2026-09-21**; no October releases or commits found. Repo at **1,295 stars**. License still Apache-2.0. The w335 §4c steal verdicts (tamper-negative CI 4c, findings-weighted verify 4d, re-projection verbs 4e, no-dead-controls gate 4f, per-hop trust records 4g) were re-checked against the tree 2026-10-05: **none are built yet** — they carry forward as open build recommendations (see §6). **Threat delta: none** — still no human-in-the-loop enforcement, still orchestrator-side not point-of-action; our differentiators hold. Re-sweep monthly (solo maintainer, ~weekly cadence).

| Competitor | New since 2026-10-01 | Threat delta | Verdict |
|---|---|---|---|
| Algedonic | Nothing (latest: 9/30 demo PR) | None | WATCH |
| EVE AI Core | Nothing (repos stale 108–139d; blog 8/31) | None | WATCH |
| Bernstein | Nothing (latest v3.20.0 9/20; 1,295★) | None — 4 steal patterns still open | ADAPT (patterns, carried forward) + WATCH |

---
## 4. Steal check on our own new surface (w335 additions + wave-336 adapters)

**Method:** tree checked FIRST (commands printed per item), then OSS surveyed for anything doing the same thing better. License read before every verdict. Patterns described, nothing copied.

### 4a. Per-tool rate limiting (`gov/tool_rate_limit.py`, F422) — ADAPT (one pattern) + SKIP (rest)

**Tree check (run):** `ToolRateWire.charge(tool)` — per-tool sliding window, monotonic injectable clock, deployment-set limits with conservative built-in defaults, fail-closed on malformed config (`tool-rate-limit-config-invalid`) and on limiter failure (`tool-rate-limiter-unavailable`); wired at the two F33 execution boundaries before the F162 class tempo charge.

**What the industry does:**
- **AG2 / TealTiger `GovernancePolicy.rate_limit` — MERGED and shipped in ag2 v1.0.6** (release notes 2026-09-22 — https://github.com/ag2ai/ag2/releases/tag/v1.0.6; PR #3246 by @nagasatish007 — https://github.com/ag2ai/ag2/pull/3246). Apache-2.0 (ag2). Deterministic sliding-window cap on tool-call frequency with **fnmatch glob scoping**: `rate_limit(30, window_seconds=60)` global, `rate_limit(5, window_seconds=60, tool="send_email")` per-tool, `rate_limit(100, window_seconds=3600, tool="db_*")` pattern-family. 15 tests + 198-passed suite; OBSERVE/MONITOR/ENFORCE modes.
  - **Steal-worthy (ADAPT): glob-scoped limit families.** Our `tool_rate_limits:` config is exact-name only. A `db_*`-style family lets a deployment bound a whole tool family with one line — the same "finer refusal fires first" layering we already document, extended to families. Small, additive, no semantic change to the wire.
  - **Cautionary lesson (ADAPT as a test):** their PR review caught a real bug — two policies sharing a key double-counted each call (bucket, not policy, is what a window counts); fixed by collecting distinct bucket keys and recording one timestamp per key, with a regression test. If we add glob scoping, overlapping exact+glob matches MUST record one timestamp per distinct bucket, not per matching rule — pin the test first (red-first).
  - Difference noted honestly: TealTiger is opt-in per-policy with OBSERVE/MONITOR modes; ours is default-enforced fail-closed (F162 precedent). We do not adopt their modes — fail-closed is the product's position.
- **harbefas/arbitus** (MCP security gateway, Rust): per-agent sliding window + per-tool limits + per-IP, X-RateLimit-* headers. **License: AGPL-3.0** (badge on README — https://github.com/harbefas/arbitus) — **hands off code entirely**; patterns observed only. Also a different deployment shape (network gateway vs our in-process executor). **Verdict: SKIP** (license trap + shape mismatch).
- **nousresearch/agent-governance-toolkit** (.NET): sliding-window limiter per agent/tool combination, lock-protected timestamp queue — the same shape as ours, no better. **SKIP** (convergent evolution).
- **Verdict: ADAPT** the glob-scoping pattern (Apache-2.0, described not copied) + the distinct-bucket regression test; SKIP the rest.

### 4b. Refresh-token per-token locks (`gov/agent_identity.py`, F421) — SKIP (industry converges on our shape)

**Tree check (run):** F421 MEDIUM CLOSED — per-token locks against the refresh-token double-spend race (first-filing lane rtlock, wave-335 merge).

**What the industry does (all within the last ~4 months — this is a live, repeatedly-rediscovered bug class):**
- **elizaos/eliza** commit `dfaa412de` (~2026-09-27): "serialize OAuth2 PKCE token refresh so concurrent loops don't double-spend the single-use refresh token" — single-flight `authInFlight` guard; concurrent expiry-window callers join one in-flight refresh instead of starting a competing one. MIT-licensed project. Same fix class as ours.
- **sectapunterx/heap** commit `e3020a962` (~2026-09-20): pins a guard "stops two syncs spending one rotated refresh token" with test `TwoSyncsRacingAnExpiredTokenSpendTheRefreshTokenOnce` — the same red-first shape as our battery.
- **jesssullivan/oauth-mux** issue #336: treats this as "OAuth mutual-exclusion / semaphore serialization" it intends to own — confirms the industry sees this as a distinct concern, which is what F421 filed.
- **cnighswonger/claude-code-cache-fix** (directive `proxy-owned-oauth-refresh.md`, ~2026-09-06): the **cross-process** variant — a proxy holding the client's own `.oauth_refresh.lock` file during refresh so a waking client short-circuits without POSTing. Our lock is in-process.
- **Verdict: SKIP** — independent convergence on the same fix shape validates F421's closure; nothing does it better. **WATCH** the cross-process file-lock variant for multi-process deployments (a documented residual if our lock is process-local — the merge lane should confirm the lock's scope in the F421 close notes).

### 4c. PQ envelope slot (`gov/pq_envelope.py`, w335 pqslot) — ADAPT (design rule for the future enable)

**Tree check (run):** format-only reservation, `PQ_ENABLED = False`; closed table of pure-PQ identifiers (ML-DSA FIPS 204, SLH-DSA FIPS 205, Falcon; identifiers from oqs-provider ALGORITHMS.md, MIT); hybrid forms deliberately OUTSIDE the table; any PQ-claimed bundle refused `evidence-pq-not-enabled` rather than verified down the classical path (algorithm-confusion kill, documented).

**What the industry does:**
- **Sigstore's own PQ migration:** the 2025-06-06 Sigstore blog (https://github.com/sigstore/sigstore-blog/blob/HEAD/content/post-quantum-2025.md) says Sigstore wants PQCA signing "as soon as possible" and service adoption "when reliable and vetted PQCA is available in the Go ecosystem." No 2026 update found — the migration is still aspirational upstream.
- **adityasharma1307/qknot** (MIT — license verified: https://github.com/adityasharma1307/qknot): hybrid **non-separable** Ed25519 + ML-DSA-87 signature in an OMS v1.0-compatible Sigstore bundle, validated against 180 NIST ACVP FIPS 204 vectors, tested against the real Sigstore/Fulcio/Rekor chain. **The steal-worthy insight is the negative design rule:** the naive hybrid (one classical + one PQ signature side by side) is broken by **deleting a JSON field** — a verifier that checks "every signature present is valid" accepts the remainder and the PQ protection is gone at no cost. qknot's fix: both algorithms sign a value committing to the *set* of algorithms in use, so stripping one breaks the other. **ADAPT as a binding design rule now:** when `PQ_ENABLED` flips, the hybrid envelope MUST be non-separable (each signature commits to the algorithm set) — record this in `gov/pq_envelope.py`'s module docstring as a MUST for the future implementation, with the qknot reference. Our current slot deliberately excludes hybrids, so nothing is broken today; the rule guards the future.
- **Ecosystem measurement (qknot docs/RESULTS.md):** 60,000 artifacts sampled across HuggingFace/npm/PyPI — **0 post-quantum signatures found** (one-sided 95% upper bound 0.038% per stratum). Confirms we are early; no ecosystem pressure to rush the enable.
- **Verdict: ADAPT** (design rule only, no code — the slot stays disabled).

### 4d. Framework adapters (landing in wave-336 lanes adapters12/adapters34) — WATCH + one composition note

**Tree check (run):** `gov/adapters/` ships core/generic/langchain_tools/mcp_adapter/openai_loop (w335 base); the CrewAI, AG2, OpenAI-Agents-SDK, and LangGraph ADAPTs are being built by sibling lanes right now — not re-surveyed here.

**What changed since the w335 pass:**
- **agentic-control-plane/acp-governance-sdks**: no new framework adapters (READMEs updated ~18 days ago, no new packages). Still WATCH. Noted for the record: their Python SDKs are **fail-open by default** (commit `4677278a0cdce878a979fa40c17b3709ef788758`) while the TypeScript originals are fail-closed — a competitive weakness against our fail-closed posture, worth one line in competitive positioning if ever needed.
- **AG2's TealTiger is now a native governance middleware** (merged #3128, docs #3158): tool allowlists (fnmatch), PII/secret scanning, per-agent cost limits, kill switch, REFER escalation, SARIF/JUnit decision receipts — deterministic, <5ms, no LLM in path. **Composition note for the wave-336 AG2 shim lane:** our `ag2_hooks.py` shim should *compose with* TealTiger's native policies (both can be registered; ours is the fail-closed audit record, theirs is the framework-native UX) rather than fight them — and our shim's documented residual (direct `execute_function` paths) should be re-checked against TealTiger's interception points, since TealTiger may cover a path our hook misses or vice versa. Flag to the adapters34 lane via the merge coordinator.
- **try-loopers/loopers-oss** (MIT — license verified: https://github.com/try-loopers/loopers-oss; repo moved from `asadravian/loopers-oss` to the `try-loopers` org, updated ~9 days ago): reverse proxy for AI spend with **per-tool budget enforcement** (e.g. $0.05 per Snowflake query), deterministic tool-call circuit breakers, CrewAI & AutoGen framework adapters, Redis-Lua sliding-window per-key rate limiting. **ADAPT candidate: per-tool *budget* enforcement** — the cost axis to our frequency axis. Our `gov/aggregate_budget.py` is run/class-level; fine-grained per-tool budgets would compose exactly the way per-tool rate limits do (finer refusal fires first, rotation still meets the class tripwire). Small, falsifiable, same architecture. The CrewAI/AutoGen adapters overlap our in-flight lanes — compare on merge, don't duplicate.
- **Verdict: WATCH** (acp, loopers adapters) + **ADAPT** (per-tool budget enforcement — new build recommendation R12; TealTiger composition note to adapters34).

---

## Verdict table

| # | Item | Verdict | One-line reason |
|---|------|---------|-----------------|
| 1a | CIMD document emission (client role) | ADAPT | Zero SSRF; static doc; spec-blessed shape — build-ready spec §1b |
| 1b | CIMD URL shape + document binding validation | ADAPT | Deterministic core, red-first — build-ready spec §1c |
| 1c | CIMD pre-registration intake (§7.2) | ADAPT | Fetch-once-at-onboarding kills request-time SSRF — build-ready spec §1d |
| 1d | CIMD request-time fetching / CIMD Service | WATCH | figranium caution stands; appendix warns of proxy implications |
| 2 | Rekor-pattern witness: independent witness operators + anchoring policy | ADAPT | Crypto built; remaining gap is operations design — §2b |
| 2b | Sigstore public witness network | WATCH | Not launched (CLIENTS.md ~10/01); policy via TUF root when it ships |
| 3a | Algedonic | WATCH | Nothing new since 9/30 demo PR |
| 3b | EVE AI Core | WATCH | Nothing new; repos stale 108–139d |
| 3c | Bernstein | WATCH (+4 carried ADAPTs) | Nothing new since v3.20.0; patterns still unbuilt |
| 4a | Per-tool rate limits: AG2 TealTiger glob scoping | ADAPT | fnmatch families + distinct-bucket test (Apache-2.0) |
| 4a2 | arbitus / MS toolkit rate limiting | SKIP | AGPL-3.0 trap (arbitus); convergent shape (MS toolkit) |
| 4b | Refresh-token locks | SKIP (+WATCH x-process) | Industry converges on our shape (eliza/heap/oauth-mux) |
| 4c | PQ slot: qknot non-separable hybrid rule | ADAPT | Design rule for the future enable (MIT) |
| 4d | Per-tool budget enforcement (loopers, MIT) | ADAPT | Cost axis to our frequency axis — new R12 |
| 4d2 | acp-governance-sdks / TealTiger composition | WATCH | No new adapters; composition note to adapters34 lane |

## Build recommendations (for wave planning)

- **R1.** `gov/mcp_cimd.py` Parts A+B — CIMD emission + shape/binding validation, 10 new `mcp-oauth-cimd-*` codes, pin bump. Spec: §1b–§1c. Red-first: one bypass probe per rule row.
- **R2.** Part C pre-registration intake — onboarding-time fetch with the full §1d control set + document-hash pinning + key-rotation revocation event into the CAEP/SSF intake. Activates only for deployments onboarding third-party CIMD clients.
- **R3.** Witness-network operations design (§2b): independent-witness operator runbook (diverse infrastructure, 3 witnesses / quorum 2 minimum viable), checkpoint-interval policy with the synchronous-cosigning availability budget stated, equivocation red-first battery. No new crypto.
- **R4.** (carried w335) Tamper-negative CI for the offline evidence bundle: golden receipt committed, CI proves a tampered copy fails verify (Bernstein pattern, Apache-2.0).
- **R5.** (carried w335) Findings-weighted verify regression: valid chain + critical finding ⇒ non-green/non-zero on our verify paths (Bernstein GHSA-594x-5h3g-wj34 lesson).
- **R6.** (carried w335) No-dead-security-controls CI gate: fail when a registered control/decision-code has no production caller (Bernstein #5053, Apache-2.0).
- **R7.** (carried w335) Monthly re-sweep of `sipyourdrink-ltd/bernstein` releases.
- **R8.** AG2 TealTiger glob scoping ADAPT: `tool_rate_limits:` gains fnmatch family keys; distinct-bucket counting regression test (their double-count bug, described not copied).
- **R9.** PQ non-separable hybrid design rule: record in `gov/pq_envelope.py` docstring as a MUST for the future enable (qknot, MIT).
- **R10.** (carried w335) `attach_sigstore_bundle` OCI referrer wiring (w335 §2) — still open, tree-checked.
- **R11.** Composition note to the wave-336 adapters34 lane (via merge coordinator): AG2 shim vs TealTiger native interception points — compose, don't fight; re-check residual coverage.
- **R12.** Per-tool budget enforcement (loopers-oss pattern, MIT): `tool_budgets:` deployment section, finer refusal before the aggregate budget tripwire — the cost analog of F422.

## Carry-forward WATCH list

- CIMD draft → RFC publication (re-check spec; currently -02, expires 2027-01-07).
- Sigstore public witness network launch (witness policy via TUF root).
- Cross-process refresh-token lock (`.oauth_refresh.lock` pattern) for multi-process deployments.
- acp-governance-sdks quarterly re-sweep (17 scouts; Python SDKs fail-open by default — noted weakness).
- Bernstein monthly re-sweep (solo maintainer, ~weekly cadence, Apache-2.0).

## License notes (all checked 2026-10-05)

- **Clean (permissive):** IETF draft text (patterns only, no code extracted); AG2/ag2 **Apache-2.0**; qknot **MIT**; loopers-oss **MIT**; Bernstein **Apache-2.0**; Sigstore CLIENTS.md (Apache-2.0 project docs).
- **Trap (do not copy code):** harbefas/arbitus **AGPL-3.0** — patterns observed only, zero code contact.
- **Unverified (not relied upon):** yubi-os agent-skills Rekor v2 doc (third-party claims cited as practice, not authority); elizaos/eliza + heap + oauth-mux + claude-code-cache-fix (cited as existence proofs of the bug class/fix shape; no code copied; eliza is MIT per its repo metadata).
- No GPL/AGPL/BSL code copied or vendored anywhere in this prospectus. All verdicts describe patterns; the build lanes will implement from scratch.
