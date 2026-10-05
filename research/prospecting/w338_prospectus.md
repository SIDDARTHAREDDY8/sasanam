# Wave-338 Industry Prospectus: Bernstein v3.21.0 Landed, Witness Build Spec, OCI Registry Matrix, PQ Trigger Calendar, Adapter Watch, Two New Entrants

**Date:** 2026-10-05 (access date for all claims) · **Base:** `6cdf5fdd` (wave-337 merge) · **Lane:** wave-338 lane 6 (research)
**Method:** six parallel research scouts, primary sources only (release notes, advisory text, spec text, source code, vendor docs, official blogs, GitHub API), access date 2026-10-05 on every citation. Tree checked FIRST for every verdict (commands at end). $0 spend.
**Standing rule honored:** prior prospectuses are not repeated — only deltas since the 2026-10-05 pass and the carried items this wave was asked for.

## Headline finds

1. **Bernstein v3.21.0 LANDED** (published 2026-10-05T06:42:53Z, 244 changes, cut #6405 atop the #6404 security fix) — but its two headline advisories (GHSA-xw82-w5hr-hrm2, GHSA-4r8r-jx5c-w954) **404 publicly**, and the v3.21.0 milestone shipped OPEN with 35 unresolved issues. The #5990 quorum window expires **today 12:00 UTC** with 60 PRs still open and no reviewer-capacity fix. 4 STEALs this month (test hermeticity ×2, dead-code gate, verifiable-only bundle payloads) + 16 ADAPT-worthy honesty mechanics.
2. **Witness ops (R18) now buildable**: `gov/witness_policy.py` + `gov/witness_consistency.py` + `gov/witness_log.py` already exist; the remaining build is the `add-checkpoint` daemon + the log-side block-until-quorum-2 submission client, all C2SP-spec'd. Sigstore's own `TrustedRoot` proto still has **no witness-key field** — our signed witness-policy artifact remains greenfield. One flag: policy-signer-set changes should enforce TUF dual-threshold.
3. **OCI transport correction**: the transport the w337 brief called "unbuilt" is **BUILT** (`gov/oci_distribution.py`, `gov/evidence_distribute.py`, coded `oci-referrers-*` refusals). This wave's question was which registries the existing transport may trust: **IN** — Zot, Harbor (push/ORAS-copy only), Docker Hub (flipped to YES), ECR (direct PUT), ACR (non-CMK), Artifactory ≥7.90.1, Quay.io, GAR; **OUT** — GHCR, CNCF distribution 2/3, **Harbor Replication Service** (#23210 still open), ACR-CMK.
4. **PQ trigger calendar now exists**: 0/60k PQ signatures unchanged, but CNSA 2.0 mandates exclusively-PQ software/firmware signing by **2030**; Sigstore PQ migration is at design phase (cosign#4960 still open); vendor deployments (Microsoft ADCS, AWS Private CA, Cloudflare 2029 target, Google 2029 target) are all verifier-controlled domains, none in artifact-signing ecosystems. "Early and ready" posture stands; the named flip triggers are recorded.
5. **Framework adapters**: no new shims; **nobody in the ecosystem addresses the F426 misattachment class** — the F426 close-when (issued guardrail declares its intended tool; audit raises on mismatch) is novel for this domain. AG2 v1.1.2 added invocation-scoped plugins (fail-closed survives, audit surface changed — recommend battery probes).
6. **Competitors**: Algedonic/EVE — no technical change; **NEW entrant Rig Security** ($12M seed, endpoint sensor enforcing agent-vs-human attribution + real-time action blocking — WATCH-HIGH); **Ping Identity** launched runtime allow/deny/log + human-approval-per-action Sept 1 (closest incumbent to our HITL opening — incumbent watch-up); DeepInspect (fail-closed signed-evidence proxy at model boundary, unverified traction — WATCH-LOW).

---

## 1. Bernstein: v3.21.0 landed since the pass (R7)

**Source:** https://github.com/sipyourdrink-ltd/bernstein/releases/tag/v3.21.0 (published 2026-10-05T06:42:53Z; tag created 2026-10-04T21:50:33Z); GitHub API milestones/advisories; raw `scripts/quorum_check.py`. License: Apache-2.0 re-read 2026-10-05, unchanged (Copyright 2026 Alex Chernysh).

### 1a. The release and its headline gap

v3.21.0 shipped 244 changes since v3.20.0, cut via `chore(release): v3.21.0` #6405 on top of security fix #6404 (the two HIGH advisories from the w337 pass). Release notes open: "Two hundred and forty-four changes since v3.20.0; **read the two advisories first**." But as of 2026-10-05 ~08:20 UTC, **neither GHSA-xw82-w5hr-hrm2 nor GHSA-4r8r-jx5c-w954 resolves publicly**: both repo advisory URLs and the global advisory DB return 404; the repo advisory index lists only 10 advisories, newest GHSA-594x-5h3g-wj34 (2026-09-10) — the two October HIGHs are absent. Likely private/draft or publication-delayed. For a project whose brand is "records that verify," shipping a release whose headline instruction points at unpublished advisories is a process gap — **WATCH** whether the advisories become public and match #6404's scope. No NEW advisories beyond these two.

### 1b. v3.21.0 milestone shipped open (35/54 unresolved)

The v3.21.0 milestone is still OPEN with 35 open / 19 closed issues, due_on 2026-10-04 (past due). They shipped the release with 35 milestone issues unresolved and never closed the milestone. Their #6094 (2026-09-20) redefined milestone dates as "planning targets, not commitments" — consistent, but the open-milestone-shipped-release means the milestone no longer gates anything. Next dated milestones: volunteer-workers MVP due 2026-10-15, agent-authority due 2026-10-31. **WATCH** whether milestone discipline changes post-window.

### 1c. The #5990 window closes today 12:00 UTC

#5990 ("governance: backlog window — maintainer approval alone meets the ordinary quorum until 2026-10-05") merged 2026-09-24; `BACKLOG_WINDOW_ENDS = 2026-10-05 12:00 UTC` still live in `scripts/quorum_check.py:232` (cleanup not yet landed — pending, expected), and the sibling #5996 `ADOPTION_ENDS` also still live (line 154). The window worked as a drain: open PRs 100+ → **60**, but with ~3.7h of window left and no reviewer-capacity fix (same 4 core reviewers, 40–80 open review requests each; no new maintainers; 8 first-time external contributors in v3.21.0). **Strain signal: the backlog re-accumulates the moment the window closes unless reviewer capacity changed — nothing indicates it did.** Next sweep: check whether the BACKLOG/ADOPTION cleanup lands promptly and whether open PRs climb back over ~100 within two weeks. Stars 1295→1397 (~+100 in 3 weeks); repo active to within the hour (#6411 opened 2026-10-05T07:43:36Z).

### 1d. Threat delta: none

Bernstein remains orchestrator-side, deterministic-scheduler, no human-in-the-loop. The two HIGH advisories' fix shape (per their release notes: identity records MAC'd keyed outside the workdir; gates take only signed, nonce-bound decisions; token scope checked everywhere; trusted-workspace workflow nodes; role-bound claims; pinned-key receipts; git-dir-only docker mounts) converges with classes we already defend. Differentiators hold.

### 1e. This month's steal-worthy mechanics (tree-checked)

**STEAL (4)** — small, in our threat surface:
1. **#6010 — unit tests block DNS** (`socket.getaddrinfo` blocked in the harness). Our `tests/` has no hermeticity guard; the five socket-touching test files are the network-machinery tests themselves, but nothing stops the other ~575 test files from phoning home. **R19.**
2. **#5721 — bounded waits use a monotonic clock.** Concrete instance: `gov/egress_proxy.py:796-797` — `deadline = time.time() + timeout; while time.time() < deadline:` is wall-clock; an NTP step shortens it. Replace with `time.monotonic()`. **R20.**
3. **#4645 — dead-code gate**: a `core/` module nobody imports fails CI; the allowlist can only shrink. We have no import-reachability gate over `gov/`. This extends R16 — implement as the gate's first version. **R21.**
4. **#6371 — batch builder returns only verifiable payloads; redact failure reasons.** Our `gov/bundle_*.py` builders should carry the same contract: never emit a bundle containing a payload the verifier cannot verify, and failure reasons stay out of the artifact (an unverifiable member poisons the bundle's claim). **R22.**

**ADAPT (16)** — the class, reshaped: #6363 bench-verify contract (one result per task, score+verdict cross-check, refuse duplicate/missing task results) → our offline-verifier track; #5464 cost per verdict in bundles (we have hard caps + loud refusal in `evals/realmodel_harness.py:262` — ahead on the refusal half, missing per-verdict cost); #6051/#6063 refusal-to-fabricate provider identity (check real-model driver and adapter registry for default/inferred provider naming); #6137 non-interactive approval gate records refusals with approval-grade durability; #5441 probe-environment parity (probe harnesses must never run cushier than production); #5948 precedence proven in both insertion orders (adopt order-independence testing); #5920/#5951-class tests must not read a neighbor's leftover state (turn the AGENTS.md fresh-TMPDIR convention into an automated hermeticity check); #5852 signed recall receipts (memory recall as receipted primitive); #5443 archive manifest hashes every member (verify our member-level hashing is complete — no count-only coverage); #5069-class per-run "not covered" panel (extends R15 — static honesty exists in STANDARDS_MAPPING.md:70, no per-run panel); #6402 policy limits make no network call without a configured endpoint; #6282 collusion check at admission (`gov/admission.py` exists — check cross-task collusion screening); #6370 approve-on-timeout label honesty; #6020 no recording transient resource exhaustion as findings; #5964 spawn prompts name the run's origin server; #6056 crash-as-crash reporting (exit-status discipline for subprocess helpers).

**SKIP (already have):** #5569-class (our B3 matrix predates theirs — `docs/STANDARDS_MAPPING.md` + `tests/test_b3_matrix.py` since Wave-39); #6328 (have `effect_digest` in `gov/action_capsule.py`); #6223 (have `evals/c2pa_provenance_probes.py`).

**WATCH (10):** advisory publication; post-window backlog re-accumulation; #6239 identifier scope; #6339 test-infra revert; #5448 evasion-coverage honesty (2/8 caught, honestly stated — the benchmark for our break-battery reporting); COSE_Sign1 receipts; CI ancestry checks; orphan-module rule #5505; batch pass receipts; metric schemas; their MAC-keyed-outside-workdir identity design.

---

## 2. Rekor-pattern witness ops (R18) — build spec

**Industry state (2026-10-05):** Rekor v2 synchronous witnessing is specified (rekor-v2-spec §5.3: log "blocks until it receives the co-signed checkpoint"; verifying clients SHOULD verify co-signatures against trust-root witness keys). CLIENTS.md's "witnessing is future" prose is **stale** — live `log2025-1` checkpoints already carry 3 cosignatures (captured w321). **Sigstore's `TrustedRoot` proto has no witness-key field at HEAD** — witness distribution ("M-of-N distributed by Sigstore's TUF root", CLIENTS.md) is prose-only. The C2SP witness protocol (tlog-witness.md) is fully spec'd: `add-checkpoint` wire shape, 63-proof-line cap, 404/403/400/409/422/200 status table, **MUST persist-before-respond atomically**, MUST-ignore-unknown-signatures, cosignature/v1 76-byte lines (`keyID(4) || u64BE time(8) || sig(64)`).

**Tree check (2026-10-05):** `gov/witness_policy.py` (677 lines — threshold-signed witness-policy artifact, N+1 monotonicity, policy_id continuity), `gov/witness_consistency.py` (850 lines — C2SP cosignature verification, `require_cosignatures`, MUST-ignore, fork detection), `gov/witness_log.py` (794 lines — RFC 6962 log), `gov/checkpoint_note.py`, `gov/rekor_v2_anchor.py`, `gov/rekor_v2_witness.py` all present. **Not in tree:** no `add-checkpoint` daemon, no log-side block-and-collect orchestration.

**Build direction (R26) — the remaining surface, minimal:**
1. **Witness daemon** (stdlib only; OmniWitness pattern, Apache-2.0 reference): sqlite `{origin → (size, checkpoint)}`; `POST /add-checkpoint` with the full C2SP status table; atomic persist-before-respond; Ed25519 keys, cosignature/v1 76-byte lines; optional monitor surface; first checkpoint operator-pinned (never blind TOFU in production).
2. **Log-side submission client**: on each checkpoint tick POST to all 3 witnesses; on 409 rebase and retry once; **block publication until ≥2 valid cosignatures** (fail-closed); per-witness timeout default 10s, total budget ≥20s (CLIENTS.md rule); below-quorum → head freezes, alert fires, no checkpoint published.
3. **Policy inputs** inside the signed witness-policy artifact (zero log calls for a verifier holding it): witness vkeys + operator identity + `valid_for` windows; 2-of-3 quorum; checkpoint cadence (infrequent enough for witness consensus — Rekor v2 §4.4); per-witness timeout; freshness bound; version N+1; threshold-signed.
4. **One flag for the build lane**: `check_policy_update` enforces N+1 + policy_id continuity, but a *policy-signer-set change* should require TUF dual-threshold (threshold(old set) + threshold(new set)) — currently only N+1.
5. **Rotation rules** (TUF + TrustedRoot precedent): overlap-then-retire — successor enters with a future-dated `valid_for`, predecessor stays until expiry; clients MUST accept overlapping instances; verifiers MUST-ignore unknown cosignature lines (non-breaking by construction); same-key-different-name = same witness; state-lost witnesses must not resume from the log's head.
6. **Honesty boundaries**: consistency-only (anti-equivocation), not bundle truth; no RFC-3161 timestamp claim; fail-closed availability cost explicit (Tessera's `FailOpen: true` is documented temporary — do not copy); Ed25519 today, ML-DSA-44 cosignatures are spec-SHOULD with zero deployed practice; no sourced dollar figures exist (OmniWitness = sqlite + HTTP; key custody + 24/7 availability dominate).

**Verdict: ADAPT** — the spec above is the runbook + daemon + client + policy-fix remainder. **WATCH**: Sigstore `TrustedRoot` witness-key slot, Tessera FailOpen default flip, ML-DSA-44 cosignatures, witness-network.org production list.

---

## 3. OCI distribution — registry trust matrix (transport already built)

**Tree-check correction (2026-10-05):** the transport the w337 brief called "unbuilt" is **built and committed**: `gov/oci_distribution.py` (wave-321 lane 2 — stdlib-urllib referrers client, Referrers API primary → 404 tag-schema fallback, registry untrusted, digest-addressed pulls, per-blob re-hash, subject-digest matching), `gov/evidence_distribute.py` (Wave-191 lane B — client-injected wire protocol, requires signature referrer in graph), coded `oci-referrers-malformed` / `oci-referrers-unavailable` in `gov/decision_codes.py`. The research question this wave was which registries the existing transport may trust.

**Status (2026-10-05, primary sources — goharbor issues via GitHub API, vendor docs, live-probe matrices):**

| Registry | Referrers API | Notes |
|---|---|---|
| Zot | ✅ | Native endpoint; live-probed 200 + empty index; `zot sync` preserves referrer graph; Apache-2.0 |
| Harbor (direct push / `oras copy`) | ✅ | UI gap CLOSED (#22592, #22643 closed; PRs #22628, #23029, #23237 merged) — push path first-class |
| Harbor (Replication Service) | ❌ | **#23210 still OPEN** (`kind/bug`, `needs/follow-up`, revived 2026-10-03; no fix PR; v2.15.2-rc3 has no fix) — silent referrer drop |
| Docker Hub | ✅ | **Flipped to YES** (live-probed ~10d ago; cosign v3 referrers verified working; older "no" reports stale) |
| GHCR | ❌ | 404 MANIFEST_UNKNOWN on referrers endpoint (cosign#4641) |
| Amazon ECR | ✅ | Direct PUT; caveat: `oras copy -r` of referrer manifests 405 (aws/containers-roadmap#2783) |
| Azure ACR | ✅ | Except CMK-encrypted registries (tag-schema fallback only) |
| JFrog Artifactory ≥7.90.1 | ✅ | Vendor docs |
| Quay.io | ✅ | Announced + implemented (quay/quay#6385; fallback-tag merge semantics) |
| Google Artifact Registry | ✅ | Vendor docs + matrix confirmation |
| CNCF distribution (`registry:2/3`) | ❌ | No route |

**cosign/ORAS notes:** cosign v3.1.3 current; **v3.1.2 fixed missing `artifactType` in referrer manifests** (older artifacts may lack it → our filter must treat missing as non-match, never pass); v3.1.1 deprecated legacy referrers flags ahead of v4 (`--attachment`, `--attachment-tag-prefix`, `--replace`, `--sign-container-identity`, `--experimental-oci11` — being deleted upstream, not just deprecated); ORAS v1.3.4, no discover-behavior changes since v1.3.0.

**Build directions (R27):**
1. **Registry onboarding gate (STEAL pacto's live-probe method, Apache-2.0):** probe `GET /v2/<repo>/referrers/<digest>` on an empty subject — `200` + empty index ⇒ candidate IN; 404 ⇒ tag-schema-only (refuse if fallback absent); anything else ⇒ OUT. Re-probe on registry upgrades (Docker Hub's flip is the cautionary tale).
2. **artifactType pin test (ADAPT):** discovery treats a referrer manifest with missing `artifactType` as a non-match (not an error, not a match) — test-first at the existing seam.
3. **Distribution matrix documentation**: same-repository pinning (never chase referrers across a replication/copy boundary — Harbor #23210 proves the graph does not survive silently); Harbor deployments = push/`oras copy` only, replication path excluded; registry always untrusted (already the tree's boundary).

**Verdict: ADAPT** (R27 — the transport exists; this is the trust matrix + onboarding gate). **WATCH**: Harbor #23210, GHCR, cosign v4, ECR 405 edge. **SKIP**: cosign legacy `.sig` scheme (already SKIP-as-design; upstream deleting), own-registry builds (Zot instead), Harbor replication for evidence.

---

## 4. PQ ecosystem — trigger calendar

**Sources:** qknot PyPI + repo (README, docs/RESULTS.md, docs/BENCHMARKS.md, crawled 2026-10-05); sigstore/cosign#4960; vendor docs. License: qknot MIT re-confirmed.

**State (2026-10-05):**
- **"0 in 60k" unchanged**: qknot v0.1.1 (still the only release; MIT) carries its audit — zero PQ signatures across 60,000 sampled HF/npm/PyPI artifacts (95% upper bound 0.038%). All PyPI attestations remain ECDSA P-256.
- **Deployments accelerated, but only in verifier-controlled domains**: Altera ML-DSA secure boot shipping (Sept 2026), Microsoft ADCS ML-DSA issuance GA (May 2026), AWS Private CA ML-DSA GA, Cloudflare ML-DSA origin auth (2029 full-PQ target), Google internal 2029 target. Nothing in open artifact-signing ecosystems.
- **Sigstore PQ: design phase, not shipped.** cosign#4960 (opened June 2026) still open: no ML-DSA keygen/sign/verify, no Fulcio PQ issuance, no Rekor PQ storage. Two 2026 conference talks present the PQC design; protobuf-specs ML-DSA enums still Experimental.
- **Trigger calendar (named, sourced):**
  - **CNSA 2.0: software/firmware signing exclusively CNSA 2.0 by 2030** — earliest hard signing deadline adjacent to our evidence-bundle surface; NSS acquisitions support PQ by 2027-01-01; full NSS transition 2035.
  - **Chrome Merkle Tree Certificates**: Q1 2027 bootstrapping, Q3 2027 dedicated Quantum-resistant Root Store; Apple MTC draft requires ML-DSA+ECDSA cosignatures — industry converging on hybrid-at-issuance, matching our non-separable rule.
- **Non-separable hybrid rule reaffirmed (R9 stands)**: both algorithms sign a value committing to the algorithm set (side-by-side JSON hybrids are broken by field deletion); hybrid cost +0.31ms/+64B over ML-DSA-87 alone — "backward compatibility is nearly free" is structural. `gov/pq_envelope.py` still `PQ_ENABLED = False` with the closed 19-identifier table unchanged (tree-checked 2026-10-05); the docstring still doesn't record the MUST-rule — carry R9 forward.
- FN-DSA (FIPS 206): explicitly excluded from CNSA 2.0 → SKIP.

**Verdict: ADAPT** (design rule only, no code — the slot stays disabled). **WATCH**: cosign#4960 resolution (named flip-start trigger), CNSA 2030 signing deadline (mandatory driver). **Urgency read**: "early and ready" remains right — no vendor sunsets classical-only verification in artifact ecosystems today; the flip trigger is Sigstore shipping ML-DSA issuance, and the mandatory date is 2030.

---

## 5. Framework adapter watch

**Sources:** GitHub API, PyPI metadata, OpenAI Agents SDK docs, AG2/CrewAI/LangGraph release notes. All accessed 2026-10-05.

**Findings:**
- **No new OSS governance shims** for CrewAI/AG2/OpenAI Agents SDK/LangGraph. acp-governance stays 0.2.0. New repos are DSH-specific or scanner/demos (SKIP). `asqav` 0.10.10 (ML-DSA-65 signed receipts) is **proprietary** — WATCH for evidence-format ideas only, no code.
- **The F426 close-when is novel for this domain.** Surveyed: OpenAI Agents SDK docs (guardrails carry no declared target name; misattachment silently legal), K8s admission controllers (binding by name, no authored-for check; `istioctl analyze` flags unselected workloads, not mis-selected ones), AWS WAF (absence/misconfiguration findings only), AWS IAM (no written-for-X-but-attached-to-Y detection), OPA/Styra (policy "not cryptographically bound" to operations — third-party analysis). Every domain audits **presence/coverage**, never policy↔target identity binding. The F426 close-when (issued guardrail exposes `framework_tool` + declared name; audit raises on missing/mismatch) has no external precedent — ADAPT the certificate-pattern framing (scope-carrying credential, TUF/Sigstore shape) when writing the closure spec, no code to reuse.
- **Framework drift:** CrewAI 1.15.23 — tracing/eval only, no funnel change; **AG2 v1.1.2 (2026-10-03) adds invocation-scoped plugins** (PR #3335: `plugins=` on `Agent.ask`/`run`/`resume`; same-named plugin tools shadow) — our middleware still mediates by name and unknown names fail closed (no bypass), but the audit surface changed (per-invocation tools can't be pre-registered); **recommend battery probes** — (a) new tool name via plugin → `UnregisteredToolError` fail-closed; (b) same-named tool with different behavior → governance still mediated (R28). openai-agents 0.23.1 — shim already verified against it, no drift; langgraph 1.2.12 — additive optional `response_schema` on `interrupt()`, no drift.

**Verdict: SKIP** (no steals; our four adapters lead). **R28**: AG2 invocation-plugin battery probes for the closure lane.

---

## 6. Competitor delta

| Competitor | Delta since 2026-10-05 pass | Threat delta |
|---|---|---|
| Algedonic | Demo PR syndication only; early access ≥1k-employee orgs; no patents found in USPTO/Google Patents (likely unpublished provisionals) | NO CHANGE (HIGH, accelerating GTM) |
| EVE AI Core | No new posts/commits; still no HITL; hardware-attestation roadmap honest-but-stale | NO CHANGE (HIGH, quiet) |
| Omada+EmpowerID | No post-acquisition product update; analyst still waiting on "committed delivery dates" | NO CHANGE (HIGH, integrating) |
| CrowdStrike/SGNL | Agentic Identity Provider (Sept) — identity issuance, not enforcement | NO CHANGE |
| Okta / Palo Alto Idira / Microsoft Agent 365 | Identity-first, nothing new | NO CHANGE |
| **Ping Identity** | **Enterprise Personal Agent Access (Sept 1): runtime allow/deny/log + human approval per action + MCP controls, piloted in global enterprises** | **INCUMBENT WATCH-UP — closest incumbent to our HITL opening** (still identity-anchored, no fail-closed pre-execution, no signed evidence) |
| **Rig Security** | **NEW: $12M seed (~Sept 29, 2026; Ten Eleven + CrowdStrike Falcon Fund + Wiz co-founder), endpoint "Bifrost" sensor distinguishing agent-vs-human sessions and blocking risky actions in real time, claims Fortune-200 production traction** | **NEW — WATCH-HIGH** (endpoint layer, no evidence story, no HITL; name-collides with Maxim's Bifrost — track carefully) |
| DeepInspect | NEW-ish: fail-closed signed-per-decision-evidence inline proxy at the model-call boundary; funding/traction unverifiable (vendor self-description only) | NEW — WATCH-LOW |

Ping remains the only incumbent shipping per-action runtime allow/deny with a HITL option — the enforcement gap is narrowed, not closed (no fail-closed pre-execution refusal primitive, no offline/signed evidence per decision). Rig Security is a genuine new enforcement entrant from a credible team but enforces at the endpoint, not the tool path.

**Recommended cadence:** Algedonic weekly + USPTO/Espacenet monthly; Rig Security weekly; Ping monthly; EVE/Omada bi-weekly; CrowdStrike/Okta/Palo Alto/Microsoft monthly; DeepInspect monthly; Maxim quarterly.

---

## Verdict table

| # | Item | Verdict | One-line reason |
|---|------|---------|-----------------|
| 1 | Bernstein v3.21.0 advisory gap (headline advisories unpublished) | WATCH | Brand is "records that verify"; release points at 404s |
| 2 | Bernstein #5990 window expiry / backlog re-accumulation | WATCH | 60 PRs remain, no reviewer-capacity fix; milestone discipline slipped |
| 3 | Bernstein #6010 DNS-block unit tests (R19) | STEAL | ~575 test files with no hermeticity guard |
| 4 | Bernstein #5721 monotonic-clock waits (R20) | STEAL | `gov/egress_proxy.py:796-797` wall-clock deadline is the concrete instance |
| 5 | Bernstein #4645 dead-code gate, shrink-only allowlist (R21) | STEAL | Extends R16; no import-reachability gate exists over `gov/` |
| 6 | Bernstein #6371 verifiable-only bundle payloads (R22) | STEAL | An unverifiable member poisons the bundle's claim |
| 7 | Bernstein 16 ADAPT mechanics (#6363, #5464, #6051, #5441, #5948, #5920-class, #5852, #5443, #5069-class, #6402, #6282, #6370, #6020, #5964, #6056-class) | ADAPT | Reshape to our architecture; §1e inventory is the menu |
| 8 | Bernstein threat delta | NONE | Advisory classes structurally defended; differentiators hold |
| 9 | Witness `add-checkpoint` daemon + block-until-quorum-2 client (R26) | ADAPT | C2SP-spec'd, minimal new code; policy/consistency/log already built |
| 10 | Witness policy dual-threshold on signer-set change | ADAPT | TUF rule; currently only N+1 in `check_policy_update` |
| 11 | Sigstore public witness network / TrustedRoot witness slot | WATCH | Proto has no witness-key field at HEAD; CLIENTS.md prose stale |
| 12 | OCI registry trust matrix + onboarding gate (R27) | ADAPT | Transport built; IN/OUT matrix + pacto probe method documented |
| 13 | OCI artifactType pin test (missing ≠ match) | ADAPT | cosign v3.1.2 lesson; test-first at the existing seam |
| 14 | Harbor #23210 / GHCR / cosign v4 | WATCH | Replication gap open; GHCR still 404; legacy flags being deleted |
| 15 | PQ: 0/60k unchanged, posture "early and ready" | ADAPT (rule only) | Slot disabled; R9 MUST-rule still not recorded in `pq_envelope.py` docstring |
| 16 | PQ trigger calendar: cosign#4960, CNSA 2030 | WATCH | Named flip-start trigger + mandatory driver |
| 17 | Framework shims | SKIP | No new shims; our four adapters lead |
| 18 | F426 misattachment class — industry precedent | NONE FOUND | Close-when is novel for this domain; certificate-pattern framing |
| 19 | AG2 v1.1.2 invocation plugins (R28) | WATCH→battery probes | Fail-closed survives; audit surface changed |
| 20 | Algedonic / EVE AI Core | WATCH (no change) | No new technical facts |
| 21 | Rig Security (NEW) | WATCH-HIGH | Real enforcement entrant, credible team, endpoint layer |
| 22 | Ping Identity (WATCH-UP) | WATCH | Sept-1 runtime allow/deny/log + HITL option; identity-anchored |

## Build recommendations (for wave planning)

- **R19.** Test hermeticity gate (#6010 shape): block `socket.getaddrinfo` in the unit-test harness with exemptions for the network-machinery tests. Red-first: a probe that asserts DNS resolves nowhere in the suite.
- **R20.** Monotonic-clock waits (#5721 shape): audit `gov/` for wall-clock deadlines (`time.time()` deadline loops) — concrete instance `gov/egress_proxy.py:796-797` — replace with `time.monotonic()`.
- **R21.** Dead-code gate v2 (#4645 shape, extends R16): import-reachability over `gov/` — a security module nobody imports fails CI; allowlist with written reasons that can only shrink; orphan security modules need a finding number or expiry.
- **R22.** Verifiable-only bundle payloads (#6371 shape): contract test over `gov/bundle_*.py` — builders never emit a bundle containing a payload the verifier cannot verify; failure reasons redacted from artifacts.
- **R23.** Bernstein ADAPT menu: pick per wave — bench-verify contract (#6363 → offline-verifier track), per-run "not covered" panel (#5069-class → extends R15), per-verdict cost in the realmodel harness (#5464), crash-as-crash reporting (#6056), signed recall receipts (#5852), precedence order-independence (#5948), test-hermeticity check (#5920-class), collusion check at admission (#6282), timeout label honesty (#6370), refusal-to-fabricate provider identity (#6051).
- **R24.** Witness operations build (`gov/witness_daemon.py` + submission client + runbook): C2SP `add-checkpoint` wire protocol, atomic persist-before-respond, Ed25519 cosignature/v1 lines, block-until-quorum-2 with ≥20s budget, below-quorum freeze; plus the `check_policy_update` dual-threshold fix for signer-set changes; red-first battery (equivocation refuse, unknown-witness-line ignore, below-quorum freeze).
- **R25.** OCI distribution matrix lane: registry onboarding gate (pacto probe method), artifactType-missing pin test, distribution-matrix runbook (IN/OUT table, Harbor push-only caveat, same-repository pinning); fail-closed rules §3.
- **R26.** AG2 invocation-plugin probes (R28): (a) per-invocation new tool name → `UnregisteredToolError` fail-closed; (b) same-named shadowed tool → still mediated by binding name.
- **R27.** Bernstein monthly sweep (R7 continues): post-window quorum behavior (did the BACKLOG/ADOPTION cleanup land? did open PRs re-accumulate?), advisory publication, milestone discipline, v3.22.0 tracking.
- **R13/R14/R15/R16/R17/R18/R9 (carried).** Advisory regression pins; decision-code coverage table; VSA "not verified" list; no-dead-controls gate (R21 implements); OCI transport (BUILT — transport items R17→R25 matrix); witness min-viable spec (superseded by R24 build spec); PQ non-separable rule docstring (still undone).

## Carry-forward WATCH list

- Bernstein: advisory publication; post-window backlog re-accumulation; v3.21.0 milestone closure; v3.22.0; COSE_Sign1 receipts; milestone discipline; governance strain.
- Sigstore public witness network + TrustedRoot witness-key slot; Tessera FailOpen default; ML-DSA-44 cosignatures; witness-network.org production list.
- Harbor #23210 (replication gap); GHCR referrers; cosign v4 legacy-flag removal; ECR `oras copy -r` 405 edge.
- PQ: cosign#4960 (flip-start trigger); CNSA 2.0 2030 signing deadline (mandatory driver); first pure-PQ signatures in the wild (still 0/60k); qknot releases.
- CIMD draft → RFC publication (still -02, expires 2027-01-07; MCP spec still cites -00).
- Cross-process refresh-token lock for multi-process deployments.
- Framework adapters quarterly re-sweep; AG2 invocation-plugin surface.
- Rig Security product detail (docs/demos — weekly until traction verifiable); Ping Identity (monthly); Algedonic early-access customer announcements + USPTO monthly; EVE bi-weekly; Omada+EmpowerID integrated-product watch.
- `asqav` (proprietary) signed-receipt evidence-format ideas only — no code, ever.

## License notes (all checked 2026-10-05)

- **Clean (permissive):** Bernstein **Apache-2.0** (all patterns described, nothing copied); qknot **MIT**; OmniWitness/tessera/rekor-tiles/protobuf-specs **Apache-2.0**; C2SP specs **CC BY 4.0** (spec text — implementation needs no attribution; keep quotations attributed); TUF spec **Community Specification License 1.0**; sigsum-go **BSD-2-Clause**; pacto **Apache-2.0** (method only, no code); Zot **Apache-2.0**.
- **Traps avoided:** `asqav` is **Proprietary** (ideas only, no code); arbitus AGPL-3.0 remains hands-off (not revisited).
- No GPL/AGPL/BSL/proprietary code copied or vendored anywhere in this prospectus. All verdicts describe patterns; build lanes implement from scratch.

## Tree-check commands (run 2026-10-05, base `6cdf5fdd` via shared tree)

```
tail FINDINGS.md → Next free: F427; Open: F426 (matches wave-337 merge)
grep -rn "referrer\|oras" gov/*.py → dozens of hits (transport BUILT — corrects w337 brief)
grep -n "PQ_ENABLED" gov/pq_envelope.py → PQ_ENABLED = False; closed 19-identifier table unchanged
grep -n "audit_agent_coverage\|expect_sdk_tool_name" gov/adapters/openai_agents.py → presence-only audit confirmed (F426 stands)
sed -n '796,797p' gov/egress_proxy.py → wall-clock deadline (R20 instance)
grep -c "getaddrinfo" tests/*.py → socket tests only (R19 gap confirmed)
```
