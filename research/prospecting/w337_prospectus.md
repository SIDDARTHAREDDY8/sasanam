# Wave-337 Industry Prospectus: Bernstein Carried Patterns + New Release, Witness Ops (Minimum Viable), OCI Transport Spec, PQ Ecosystem, Adapter Watch, Tier-1 Delta

**Date:** 2026-10-05 · **Base:** `2f270987` (wave-336 merge) · **Lane:** wave-337 lane 6 (research)
**Method:** primary sources only (repo release notes, advisory text, source-code pages, spec texts, first-party docs, LICENSE files), access date 2026-10-05 for all claims. Tree checked FIRST for every verdict (commands printed). $0 spend.
**Standing rule honored:** prior prospectuses (w335 framework adapters — LANDED in wave-336; w336 CIMD spec, witness §2, OCI §2-carry, PQ, loopers R12) are not repeated — only deltas, the carried items this wave was asked for, and build-ready directions.

## Prior-prospectus avoidance

Covered before (not repeated): CIMD safe-subset build spec (w336 §1, ADAPT — still open, see carry-forward); Rekor witness-network operator design (w336 §2b — this wave goes one level deeper to the minimum viable operations spec); per-tool rate-limit glob scoping (w336 §4a, R8 — still open); refresh-lock convergence (w336 §4b — SKIP, stands); PQ slot design rule (w336 §4c, R9 — re-verified this wave); per-tool budget enforcement (w336 §4d, R12 — still open); Sigstore-bundle OCI referrer carry (w335 §2, w336 R10 — this wave writes the transport spec); TealTiger composition (w336 §4d — adapters lanes are merged, note closed); CIMD draft status (re-checked this wave, no change).

**Headline find:** Bernstein shipped a **new release since the w336 pass** (~2026-10-04/05, **244 changes since v3.20.0**, v3.21.0 milestone was due 2026-10-04) carrying **two HIGH-severity advisories** — GHSA-xw82-w5hr-hrm2 (agent self-issued identity + empty decision file) and GHSA-4r8r-jx5c-w954 (receipt verified against its carried key) — both fixed in #6404. The threat delta is small (we are structurally defended on both classes) but the fix patterns and the release-notes honesty mechanics are steal-worthy. Bernstein R4/R5/R6 remain unbuilt in our tree (re-tree-checked today).

---

## 1. Bernstein: carried patterns re-assessed + new release delta

**Source:** https://github.com/sipyourdrink-ltd/bernstein/releases (top entry, read 2026-10-05); GHSA-594x-5h3g-wj34 fix commit https://github.com/sipyourdrink-ltd/bernstein/commit/06850966d35d1226aa82477214f558415decdd5b; #5053 PR https://github.com/sipyourdrink-ltd/bernstein/pull/6047; #6094 roadmap-date note; #5990 backlog-window governance PR. License: Apache-2.0 (repo metadata, unchanged).

### 1a. New release (since w336): two HIGH advisories, both fixed in #6404

- **GHSA-xw82-w5hr-hrm2 (high, reported privately):** "An agent could write its own identity record and be believed; an empty `<task>.approved` file passed for an operator's decision." Bernstein's fix (per their release notes): "Identity records carry a MAC keyed outside the workdir; gates take only signed, nonce-bound decisions; token scope is checked everywhere; workflow nodes need a trusted workspace; claims are role-bound; receipts need a pinned key; docker mounts only the git dir" (#6404). Every version through 3.20.0 affected.
- **GHSA-4r8r-jx5c-w954 (high, reported by @Trenyx):** "Workflow commands ran repository text in untrusted workspaces, a claim took its role from the request, and a receipt verified against whatever key it carried." Fixed in #6404.
- **Tree check (run 2026-10-05):** both advisory classes are structurally defended in our tree —
  - *Self-issued identity:* `gov/agent_identity.py::register_agent` mints keypairs in the registry (seed never leaves); `key_handle` seals only as the registered agent_id; `verify_message` checks against the registry with a nonce replay cache. `gov/attested_identity.py` (docstring, lines 15–22) explicitly documents the caught spike: "the spike for this lane caught the draft verifying against a key embedded in the presented identity... That shape is structurally impossible here" — the GHSA-4r8r class was found and killed in our own spike before Bernstein's advisory.
  - *Empty decision file:* `gov/approvals.py::decide` requires the F38 keyed-digest verification of the pending record BEFORE recording, re-MACs with the decider bound; empty ids/reasons refuse throughout (`approval_id must be a non-empty string`, `empty_reason` refusals, break-glass non-empty reason).
- **Verdict: SKIP** on the fixes (convergent, already defended). **ADAPT** the cheap regression-pin shapes as low-cost falsifiability (R13): an explicit battery probe per advisory class (self-issued identity record refused; empty decision record refused; key-carrying receipt refused) — the defense exists; the pin proves it stays.

### 1b. Carried R4/R5/R6 — still unbuilt, re-verified buildable

**Tree check (run 2026-10-05):** `find` for `*golden*` → zero hits (no golden receipt artifact); `grep "finding" gov/evidence_verify_offline.py` → zero hits (its 11 typed failure codes are chain/parse/policy only — the w336 §4c assessment stands); `grep -rl "every code.*has.*caller\|no production caller" tests/ evals/` → zero hits (no dead-controls gate). All three remain open.

- **R4 — tamper-negative CI for the offline evidence bundle.** Bernstein's shape (w335 §4c pattern 1): README demo ships a signed run receipt + public key; CI re-verifies the committed receipt on every push AND proves a tampered copy fails. **Build direction (honesty boundaries stated):**
  1. Commit a golden bundle + pinned trust root under `research/prospecting/` or a dedicated `gov/../artifacts/` path: produced once by the sealed sealer, bytes pinned, never regenerated by CI (CI regenerates nothing — regeneration is a forge opportunity; the pin is the point).
  2. CI runs `evidence_verify_offline` over the golden bytes → must exit 0 with the pinned VSA summary hash.
  3. CI flips one byte of the golden bundle (payload, signature, trust-root pin — three tamper variants) → each must refuse with the documented typed code (40-44 family), never exit 0.
  4. The test asserts the refusal is *typed and coded*, not merely non-zero (a crash is not a falsification — the wave-320 green-check lesson applies to CI too).
  5. License: pattern only, Apache-2.0 upstream; no code copied.
- **R5 — findings-weighted verify.** Bernstein's GHSA-594x (commit `0685096`): `audit verify` weighed only chain failures, so a valid signed chain plus a critical grant-sweep finding printed a green panel and exited zero. Their fix asserts three things: (a) valid chain + critical finding ⇒ verdict False, (b) failure panel + finding summary printed, success panel NOT printed, (c) the over-correction guard — a clean sweep still passes. **Build direction:** our `verify()` in `gov/evidence_verify_offline.py` returns a VSA-shaped summary; add a findings channel to the summary (severity-typed, from the witness/grant/policy checks the verifier already runs) and pin the regression pair: (valid chain + critical finding ⇒ `verificationResult != PASSED` / exit non-zero) AND (clean ⇒ PASSED). The Bernstein commit is the template for the test shape — two tests, red-first. Honesty boundary: severity levels are ours (critical/high/medium/low from our finding registry), not imported from Bernstein.
- **R6 — no-dead-security-controls CI gate.** Bernstein #5053 (merged PR #6047): `scripts/check_unreachable_controls.py` — AST reachability over `core/security/` and `core/identity/`, counting only `Name` loads and attribute accesses inside `src/bernstein/` as callers (imports and string literals reach nothing), fixpoint so a symbol called only by an unreached symbol stays unreached; allowlist file with one written reason per entry; a missing reason or a newly-reachable symbol fails the gate. Their release notes add two evolved rules worth adopting now: **(a)** "an orphan security module needs an issue or an expiry" (#5505) — extend the gate from symbols to modules; **(b)** "a `core/` module nobody imports fails CI, and the allowlist can only shrink" (#4645) — monotonicity: the allowlist may never grow silently. **Build direction:** `scripts/check_unreachable_controls.py` analog over `gov/` (decision-code registry ↔ production callers): every registered decision code must have a production raiser OR an allowlist entry with a written reason; the allowlist can only shrink; orphan security modules need a finding number or an expiry date. This is the STEAL of the wave (Apache-2.0, reimplemented, not copied).

### 1c. New steal-worthy honesty mechanics from the new release notes

Bernstein's release-notes format is itself a pattern (their "The question you get asked | Before | Now" table + "The receipts we are not proud of" section — a guard that fails open and leaves a record saying it passed is "the class we hunt hardest"). Steal-worthy mechanics:
- **"no row claims coverage without a test"** (#5569): their compliance-controls coverage table is generated, and no row may claim coverage without a test. **ADAPT (R14):** generate our decision-code registry documentation from `gov/decision_codes.py` and assert no doc row claims enforcement without a battery probe exercising that code.
- **"the panel lists what a run did not cover"** (#5069): the output names its own blind spots. **ADAPT (R15):** extend the offline-verifier VSA summary / our battery reports with an explicit "not verified" list (we already have PASSED != ALLOW; this extends it to per-run coverage honesty).
- **"registry enforcement at the final model choice"** (#6369) + model-registry slice (#6106): fail-closed admission check at the final routing instant, refusals recorded as chain events. **WATCH** — converges with our identity/registry direction; no build until our adapter lanes define the final-choice seam.
- **Run receipts as COSE_Sign1** (#6392), **seal anchors verify offline** (#6272): **WATCH** — envelope-format evolution; our bundle format is v0.3-keyed, no action.
- **"hosted inference and crew handoffs ingest as governed activity"** (#6341, #4965): **WATCH** — relevant to the merged adapter lanes (OAI SDK hosted tools residual, CrewAI); our adapters document residuals, their approach is ingest-as-governed.
- **Solo-maintainer pressure signal:** #5990 ("maintainer approval alone meets the ordinary quorum until 2026-10-05 12:00 UTC") — 100+ PRs sat on a single red quorum check; the backlog window **expired today**. v3.21.0 milestone (due 2026-10-04) slipped; the new release still shipped. Monthly sweep continues (R7).

**Threat delta: none** — Bernstein remains orchestrator-side, deterministic-scheduler, no human-in-the-loop; the new release hardens *their* identity/decision classes that we already defend. Differentiators hold.

---

## 2. Rekor-pattern witness ops (R3) — one level deeper: minimum viable spec

**Industry state re-verified 2026-10-05:**
- Still **no public witness network**: `sigstore/rekor-tiles` CLIENTS.md (updated ~4 days ago — https://github.com/sigstore/rekor-tiles/blob/HEAD/CLIENTS.md) still reads "Future: Witnessing... In the initial launch of Rekor v2, checkpoints will not be witnessed, while we wait for the launch of a public witness network." No launch detected.
- `sigstore/architecture-docs` rekor-v2-spec.md (updated ~52 days ago — https://github.com/sigstore/architecture-docs/blob/HEAD/rekor-v2-spec.md): Rekor v2 **synchronous** witnessing is now specified — the log sends each new checkpoint to witnesses for counter-signatures and **blocks until it receives the co-signed checkpoint**, then returns it to signing clients; verifying clients SHOULD verify co-signatures against the witness keys in their trust root. "Synchronous witnessing like this ensures that consistency verification becomes an automatic client concern" (vs asynchronous, which users treated as an afterthought).
- Witness key discipline (from rekor issue #2062, cited in-repo): for public instances "strongly recommend using ecdsa or ed25519 keys" — RSA is not C2SP-supported (omniwitness/armored-witness interop).
- **Stable-checkpoint requirement** (rekor-spec.md §10.2.1): a checkpoint must remain stable long enough for multiple witnesses to verify the SAME checkpoint, else split-view detection cannot reach consensus — "If the service frequently updates its checkpoint, then the service must publish a 'stable checkpoint' periodically." Direct input to our checkpoint-interval policy.
- Third-party practice (yubi-os/agent-skills sigstore-rekor-v2 SKILL.md, 28 days ago — third-party, cited as practice not authority): private deployments 3-of-5 witness quorum, diverse infrastructure/regions/operators, witness-set rotation every 6 months, witnesses as (Sigstore project, CNCF-hosted, academic).
- Honesty boundary (witnesses.now prior-art page, crawled 1 day ago): "Rekor log witnessing or checkpoint co-signing concerns log consistency; it is distinct from a quorum signature on every individual attestation." Our witness cosigns checkpoints (log consistency), not bundles — say so in the runbook.

**Tree check (run 2026-10-05):** `gov/witness_policy.py` (signed witness-policy artifact), `gov/witness_publish.py` (synchronous cosigning), `gov/witness_monitor.py` (fail-closed loop), `gov/checkpoint_note.py`, `gov/rekor_anchor.py::RekorWitness` (recompute-before-cosign), `gov/witness_rekor.py::anchor_evidence` all present (w321/w336 verified). The remaining gap is still operations design, not crypto.

**Minimum viable witness-network operations spec (R18) — the buildable remainder:**
1. **Witness set:** 3 independent witnesses, quorum 2 (minimum viable; tolerates one witness outage without freezing checkpoint publication). Diverse trust placement (different operators, infrastructure, regions). Keys: Ed25519 (C2SP-compatible, matches our bundle format).
2. **Onboarding/rotation via the signed witness-policy artifact** (already built): threshold-signed updates, overlap-then-retire, N+1 monotonicity; dropping below quorum freezes publication with a coded refusal (never silently publish unwitnessed).
3. **Checkpoint-interval policy** (new, must be written): interval must exceed the slowest witness's verify+cosign round trip by a stated margin (the stable-checkpoint rule) AND budget the synchronous-cosigning availability cost (Rekor's own guidance: ≥20s client timeouts; our `publish_checkpoint` cosigns synchronously — the runbook must state the freeze-on-quorum-loss behavior explicitly).
4. **Witness liveness contract:** persist-before-respond (a witness MUST NOT resume cosigning from the log's current head after losing state); cosignature timestamps bound (reject future-dated per C2SP MAY); monitor's `max_checkpoint_staleness_seconds` bounds staleness.
5. **Red-first battery:** signature-valid-but-root-dishonest checkpoint ⇒ refuse + record equivocation; unknown witness line ⇒ still verify (MUST-ignore rotation); below-quorum ⇒ coded freeze.
6. **What stays out:** per-bundle quorum signatures (witness cosigns checkpoints, not bundles — the honesty boundary above); gossip (w320/w321 SKIP stands).

**Verdict: ADAPT** — the spec above is the runbook+policy+battery remainder. No new crypto to steal; Sigstore hasn't shipped theirs either.

---
## 3. Sigstore-bundle OCI distribution (R10) — transport specifics + build direction

**Industry state (primary sources, 2026-10-05):**
- **OCI Distribution Spec v1.1** (Jan 2024) shipped the Referrers API: `GET /v2/<name>/referrers/<digest>` returns an OCI Index of manifests referencing a digest; manifests carry a `subject` field and an `artifactType` field. Implemented by Zot, Distribution v3, GHCR, ECR, Harbor (liatrio/autogov-workflows `docs/oci-attestation-internals.md`, 6 days ago — https://github.com/liatrio/autogov-workflows/blob/HEAD/docs/oci-attestation-internals.md).
- **The operator flow** (standardizing across the CNCF supply-chain community; in-toto/witness#763, mikebom issue): resolve `<image-ref>` → digest (immutable); push the DSSE envelope as an OCI referrer manifest with `subject` = the digest, `artifactType` = the envelope's payloadType, `layer[0].mediaType = application/vnd.in-toto+json`; print the referrer digest. **Fail-closed if the registry lacks the Referrers API**; the fallback tag scheme (`sha256-<digest>.att`) is out of scope for an MVP.
- **Cosign v3's format is our format:** cosign 3.x stores signatures/attestations as `application/vnd.dev.sigstore.bundle.v0.3+json` via the referrers API (arkeros/senku `oci/distroless/README.md`, 15 days ago — every image ships signature + SLSA provenance + CycloneDX SBOM as v0.3 bundles bound to the image **digest, not tag**; `oras discover` shows `artifactType: application/vnd.oci.empty.v1+json` regardless — discrimination happens *inside* the bundle). Our keyed bundle (w320) is already `v0.3`-shaped — the wire format is the industry's.
- **Harbor caveat (build-direction critical):** cosign v3's referrer-based signatures are NOT displayed by Harbor UI (it only shows legacy `.sig` tags); enforcement (`enable_content_trust_cosign`) still verifies but the UI shows unsigned (goharbor/harbor#22592, #22643). Harbor **2.15.0** "correctly supports and displays these OCI 1.1 artifacts if they are pushed directly or copied via ORAS" — the gap is strictly the **Replication Service**, which ignores OCI 1.1 referrer artifacts on pull-replication (#23210). **Implication for our build:** push our bundles via ORAS-style direct PUTs (not via Harbor replication), and never present Harbor's UI badge as verification — the auditor verifies with our offline verifier, not the registry UI.
- **Digest-as-identity** (transaction-science/open-standards `jouleclaw-oci`, 126 days ago): tags are mutable, digests immutable; attestation contexts SHOULD prefer digests. Canonical `algorithm:hex` form.

**Tree check (run 2026-10-05):** `grep -rln "oras\|referrer" gov/*.py` → zero hits; the w335 §2 ADAPT (`attach_sigstore_bundle` OCI referrer wiring) is still open — no transport code exists.

**Build direction (R17) — `gov/oci_referrer.py` (stdlib `urllib` only, no ORAS dependency):**
1. `attach_keyed_bundle(registry, repo, digest, bundle_bytes, *, transport) -> referrer_digest`: 
   - Resolve `digest` (caller supplies; must be canonical `algorithm:hex`; refuse tags — digest-only by construction).
   - PUT layer blob (`application/vnd.dev.sigstore.bundle.v0.3+json`), then PUT referrer manifest with `subject.digest = digest`, `artifactType` = bundle payloadType constant, `annotations` carrying the bundle's VSA predicate type.
   - `transport` is caller-supplied (the PRM/CIMD no-implicit-I/O architecture): the module builds request bytes, the deployment's transport sends them.
2. `verify_referrer_binding(index_json, digest)`: refuse coded unless every selected referrer's `subject.digest` string-equals the queried digest (a registry that serves referrers for a *different* subject is a confusion attack — fail closed).
3. Discovery: `GET /v2/<repo>/referrers/<digest>`; select by `artifactType`, then verify inside the bundle with `evidence_verify_offline` (bundle interior discrimination, not the index marker).
4. Fail-closed when the registry returns 404/400 on the referrers endpoint (no Referrers API ⇒ refuse, never fall back to the tag scheme).
5. Red-first battery: subject-mismatch, tag-not-digest refusal, missing-API refusal, tampered-layer (digest mismatch) refusal, round-trip attach→discover→verify.
6. **Harbor deployment note:** direct-push only; document the replication-service gap; auditor verification is the offline verifier, never the Harbor badge.

**Verdict: ADAPT** — one module + audit checks, stdlib only, no new dependency. Completes the w320 "sell evidence" distribution story at the transport layer.

---

## 4. PQ ecosystem re-check

**Sources:** https://github.com/adityasharma1307/qknot (README, docs/RESULTS.md, docs/BENCHMARKS.md — updated ~18 days ago, crawled 2026-10-05); PyPI qknot page. License: MIT (verified).

- **qknot status:** still v0.1.1; repo active (18 days). Self-signed releases (hybrid Ed25519 + ML-DSA-87 over its own tarball). The cross-registry audit finding stands: **zero post-quantum signatures across 60,000 sampled artifacts** (HuggingFace/npm/PyPI) — **no ecosystem PQ deployment news found; no rush to enable.**
- **Non-separable rule re-verified (R9 stands):** the naive side-by-side hybrid is broken by JSON-field deletion; qknot's fix — both algorithms sign a value committing to the *algorithm set* — remains the MUST-rule for our future `PQ_ENABLED` flip. Record in `gov/pq_envelope.py`'s docstring (still not done — carry R9 forward).
- **New cost data strengthening the flip case:** qknot BENCHMARKS.md (measured, replicated at two parameter sets): the hybrid costs **+0.31 ms and exactly +64 bytes over ML-DSA-87 alone** — "backward compatibility is nearly free" is now a *structural* claim, not a configuration fact. Signature cost is flat across artifact sizes (36 ms for 1 MiB or 100 MiB — you sign a digest); a 7 GB model's signature is 0.235% of the work. When the flip comes, the cost argument is settled.
- **Sigstore PQ migration:** still aspirational upstream (2025-06-06 blog; no 2026 update found).

**Verdict: ADAPT** (design rule only, no code — the slot stays disabled). No new PQ signatures anywhere in the ecosystem; the posture "early and ready" holds.

---

## 5. Framework adapter watch

**Sources:** https://pypi.org/project/acp-governance/0.2.0/ (crawled 2026-10-05); prior w335/w336 surveys.

- **acp-governance 0.2.0** lists its framework adapters: `acp-crewai` (CrewAI), `acp-langchain` (LangChain/LangGraph), `@agenticcontrolplane/governance-anthropic` (Node, Anthropic Messages API). No new adapters (no AG2, no OpenAI-Agents-SDK). Still a spend-proxy + decorator model, no fail-closed enforcement engine, no offline evidence.
- **No new third-party governance shims** for CrewAI/AG2/OpenAI Agents SDK/LangGraph found since the w335 pass. Our four wave-336 adapter lanes (merged in `2f270987`) remain the most complete fail-closed coverage of those four frameworks.
- New noise, not signal: several "agent-guardrails" repos (CloverAI-Family, roboticforce) are prompt-injection/defense or shell-command-policy tools — different problem (model-output safety / coding-agent blast radius), not execution governance. Noted, not chased.

**Verdict: SKIP** — nothing to steal; our adapter set leads. Re-sweep quarterly.

---

## 6. Tier-1 competitor delta (since the w336 pass)

| Competitor | New since 2026-10-01 | Threat delta | Verdict |
|---|---|---|---|
| Algedonic | Nothing (latest: 9/30 demo PR; whitepaper unchanged) | None — no HITL, no offline evidence, patent claims unverified | WATCH |
| EVE AI Core | Nothing (newest blog 2026-08-31; repos stale 108–139d) | None — HITL gap persists | WATCH |
| Bernstein | **New release** (~10-04/05, 244 changes, 2 HIGH advisories fixed #6404); v3.21.0 milestone slipped | None — advisory classes structurally defended in our tree; differentiators hold | ADAPT (R4/R5/R6 + new R13–R16) + WATCH |

---

## Verdict table

| # | Item | Verdict | One-line reason |
|---|------|---------|-----------------|
| 1 | Bernstein tamper-negative CI (R4) | ADAPT | Still unbuilt; build direction §1b |
| 2 | Bernstein findings-weighted verify (R5) | ADAPT | Still unbuilt; GHSA-594x test shape documented |
| 3 | Bernstein no-dead-controls gate (R6) | STEAL | Still unbuilt; + orphan/expiry (#5505) + shrink-only allowlist (#4645) |
| 4 | Bernstein 2 new advisories (identity self-issue, carried-key receipt, empty decision) | SKIP (+ADAPT pins R13) | Structurally defended (attested_identity spike, F38); add falsifying probes |
| 5 | Bernstein "no row claims coverage without a test" (#5569) | ADAPT | Generated decision-code coverage table (R14) |
| 6 | Bernstein "panel lists what was not covered" (#5069) | ADAPT | Extend VSA summary honesty (R15) |
| 7 | Bernstein model-registry-at-final-choice (#6369) | WATCH | Converges with our registry direction; no build yet |
| 8 | Bernstein COSE_Sign1 receipts / offline seal anchors | WATCH | Envelope-format evolution |
| 9 | Witness-network minimum viable ops spec | ADAPT | R18: 3 witnesses/quorum 2, stable-checkpoint interval policy, red-first battery |
| 10 | Sigstore public witness network | WATCH | Still not launched (CLIENTS.md ~4 days ago) |
| 11 | OCI referrer transport for keyed bundles | ADAPT | R17: `gov/oci_referrer.py`, stdlib, digest-only, Harbor caveats documented |
| 12 | PQ: qknot non-separable rule (R9) | ADAPT | Re-verified; 0 PQ signatures in 60k; +0.31ms/+64B flip-case data |
| 13 | Framework adapter watch | SKIP | Nothing new; our four adapters lead |
| 14 | Algedonic / EVE AI Core | WATCH | Nothing new anywhere |

## Build recommendations (for wave planning)

- **R13.** Bernstein-advisory regression pins: three red-first probes — (a) self-issued identity record refused, (b) empty/malformed decision record refused, (c) key-carrying receipt refused. The defenses exist; the pins keep them falsifiable.
- **R14.** Generated decision-code coverage table: no doc row claims enforcement without a battery probe (Bernstein #5569 shape, Apache-2.0).
- **R15.** VSA summary "not verified" list: the offline verifier names its own blind spots per run (Bernstein #5069 shape).
- **R16.** No-dead-controls gate v2 (extends R6): AST reachability over `gov/` for decision codes ↔ production raisers; allowlist with written reasons that can only shrink (#4645); orphan security modules need a finding number or expiry (#5505).
- **R17.** `gov/oci_referrer.py`: attach/discover/verify keyed Sigstore bundles via the OCI 1.1 Referrers API (stdlib urllib, caller-supplied transport, digest-only, subject-binding check, fail-closed on missing API, Harbor direct-push-only caveat). Red-first battery per §3.
- **R18.** Witness-network minimum viable operations spec → runbook: 3 witnesses / quorum 2, Ed25519 keys, diverse trust placement, stable-checkpoint interval policy with the synchronous-cosigning availability budget stated, witness liveness contract, equivocation red-first battery. No new crypto.
- **R4/R5/R6 (carried).** Tamper-negative CI, findings-weighted verify, no-dead-controls gate — build directions in §1b.
- **R9 (carried).** Record the qknot non-separable hybrid MUST-rule in `gov/pq_envelope.py`'s docstring.
- **R7 (carried).** Monthly Bernstein re-sweep (solo maintainer, weekly cadence; watch the quorum-governance strain post-#5990).

## Carry-forward WATCH list

- CIMD draft → RFC publication (still -02, expires 2027-01-07; MCP spec still cites -00 — watch the numbering on update).
- Sigstore public witness network launch (witness policy via TUF root).
- Bernstein: COSE_Sign1 receipts, offline seal anchors, model-registry enforcement at final choice, crew-handoff ingest; governance strain after the backlog window expiry.
- Cross-process refresh-token lock for multi-process deployments.
- acp-governance-sdks quarterly re-sweep; framework adapters quarterly re-sweep.
- PQ ecosystem: first pure-PQ signatures in the wild (still 0/60k).
- Harbor: Referrers-API replication-service gap; cosign v3 vs Harbor UI visibility.

## License notes (all checked 2026-10-05)

- **Clean (permissive):** Bernstein **Apache-2.0** (all patterns described, nothing copied); qknot **MIT**; IETF CIMD draft (patterns only); OCI Distribution Spec (patterns); Sigstore docs (Apache-2.0 project); yubi-os agent-skills (cited as practice, not authority).
- **Traps avoided:** none encountered this wave (arbitus AGPL-3.0 remains hands-off, not revisited).
- No GPL/AGPL/BSL code copied or vendored anywhere in this prospectus. All verdicts describe patterns; build lanes implement from scratch.

## Tree-check commands (run 2026-10-05, base `2f270987`)

```
grep -rniE "cimd|client.id.metadata" gov/*.py evals/*.py  → (not re-run; w336 §1 stands)
find <tree> -name "*golden*" -not -path "*__pycache__*"   → zero hits
grep -c "finding" gov/evidence_verify_offline.py          → 0
grep -rln "no production caller" tests/*.py evals/*.py    → zero hits
grep -rln "oras\|referrer" gov/*.py                       → zero hits
sed -n '1,50p' gov/attested_identity.py                   → presented identity carries no issuer key (spike-caught)
sed -n '4304,4360p' gov/approvals.py                      → decide() F38 keyed-digest + re-MAC, non-empty refusals
```
