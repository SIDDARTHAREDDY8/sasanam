# WAVE-338 Lane 6 — OCI Referrers API / Registry Support Status

- **Date / access date for all citations:** 2026-10-05 (all claims verified today; $0 spend — public web search + unauthenticated GitHub API only).
- **Scope:** does the registry landscape carry our signed evidence bundles (Sigstore-bundle v0.3-shaped, Ed25519) as OCI 1.1 referrer artifacts — subject-bound, `artifactType`-discriminated, discovered via `GET /v2/<repo>/referrers/<digest>` — and what is the fail-closed distribution story?
- **Spec anchor:** OCI Image + Distribution 1.1.0 (Feb 2024; announcement https://opencontainers.org/posts/blog/2024-03-13-image-and-distribution-1-1/). Referrers API = `GET /v2/<name>/referrers/<digest>` returning an OCI index; registries without it 404 and clients use the spec's tag-schema fallback (`sha256-<digest>` tag → index). Described in https://github.com/oras-project/artifacts-spec/blob/main/manifest-referrers-api.md.

---

## 0. Tree-check — CORRECTION to the brief (transport is BUILT, not unbuilt)

The brief expected zero `referrer|oras` hits in `gov/*.py`. The tree has **dozens** — the transport exists and is committed:

- `gov/oci_distribution.py` (wave-321 lane 2): stdlib-urllib client; `discover_referrers()` uses the Referrers API primary with the spec-mandated 404 → tag-schema fallback; registry treated as UNTRUSTED (digest-addressed pulls, per-blob digest re-hash, subject-digest matching, all client-side); cosign legacy `.sig` tag scheme is SKIP-as-design (fallback lookup only, never primary); Bearer <redacted> via `auth_token=<redacted>
- `gov/evidence_distribute.py` (Wave-191 Lane B): stdlib-only, **client-injected** wire protocol (`push_blob` / `put_manifest` / `list_referrers`); never imports oras-py, never opens a socket; requires the signature referrer in the referrer graph (stripped signature = refusal).
- `gov/decision_codes.py`: coded refusals `oci-referrers-malformed`, `oci-referrers-unavailable`.
- `gov/artifact_pack.py` (W248-7): ORAS/OCI-shaped artifact packaging, deterministic digests.
- `gov/cosign_attest.py`: distribution-signature half of the story.

**Implication for this lane:** the research question is not "can we build transport" but "which registries can the existing transport trust, and which paths must it refuse."

---

## 1. Harbor

### 1.1 Replication-Service referrers gap (#23210) — STILL OPEN, UNFIXED

- Issue: https://github.com/goharbor/harbor/issues/23210 — "OCI 1.1 referrers (Cosign v3 signatures/SBOMs) are not replicated from Artifactory to Harbor".
- State via GitHub API (2026-10-05): **open**, labels `kind/bug`, `area/replication`, `needs/follow-up`; 7 comments; last activity 2026-10-03 ("Still an issue I believe" — a community member kept it alive after the stale-bot marked it on 2026-09-19).
- No PR references or fixes it (GitHub search `repo:goharbor/harbor 23210 type:pr` returns only one unrelated closed PR, #17012).
- Content: replication copies the image + legacy cosign v2.x `.sig`-tag artifacts but silently drops OCI 1.1 referrer artifacts (subject-bound signatures/SBOMs). Direct push and `oras copy --recursive` to Harbor 2.15.0 work and display correctly — the gap is strictly the Replication Service.
- **v2.15.2-rc3 changelog** (https://github.com/goharbor/harbor/releases, crawled 2026-10-05) contains NO referrers-replication fix. Cosign-related entries are test/hardening only: "test(cosign): disable tlog for signing checks (#23280)", "fix(cosign): ignore tlog during verification (#23286)".

### 1.2 UI visibility issues — CLOSED

- https://github.com/goharbor/harbor/issues/22592 ("Harbor sees the signature artifact as type UNKNOWN") — **closed** 2026-02-26.
- https://github.com/goharbor/harbor/issues/22643 ("Cosign does not work in 2.14.0… 'signed' icon stays red") — **closed** 2025-12-15.
- The earlier UI-blindness to cosign-v3 referrer signatures is resolved on the push path; the remaining Harbor gap is replication only.

### 1.3 Referrers-related PRs merged since (all via GitHub API, 2026-10-05)

- https://github.com/goharbor/harbor/pull/22628 "feat(cosign): Support Cosign v3 Bundle signature format" — **merged** 2025-12-15.
- https://github.com/goharbor/harbor/pull/23029 "feat(referrers): switch to OCI referrers API for signature verification" — **merged** 2026-06-29.
- https://github.com/goharbor/harbor/pull/23170 "Add ListReferrers API to registry client and update parseScopes" — **merged** 2026-05-13.
- https://github.com/goharbor/harbor/pull/23237 "Proxy the referrer API to upstream registry with paging and local merge" — **merged** 2026-08-04 (proxy-cache projects now proxy the referrers API).
- https://github.com/goharbor/harbor/pull/23540 "fix: implement signature inheritance for OCI index children" — **merged** 2026-08-13 (multi-arch index children).
- https://github.com/goharbor/harbor/pull/23837 "feat: Add OpenVex VEX format support" — **open** (2026-10-04), VEX document format; not a #23210 fix.

**Harbor verdict:** first-class referrers citizen on the push/copy path; **replication is a silent-drop hazard for evidence carriage — exclude it.**

---

## 2. Zot — full native support (STEAL candidate for self-hosted)

- API docs list the endpoint natively: `GET /v2/{repo}/referrers/{digest}` → "Lists referrers given a digest" — https://github.com/project-zot/project-zot.github.io/blob/HEAD/docs/developer-guide/api-user-guide.md
- Live-probed by a third party 10 days ago: `200` + empty index (i.e. real API, not a 404 shim) — https://github.com/trianalab/pacto/blob/HEAD/docs/evidence-oci-storage.md
- `zot sync` mirrors hub→edge with referrers intact (OCI-native sync, unlike Harbor replication) — https://github.com/kubeswift-io/kubeswift/blob/HEAD/docs/registry/edge-zot.md
- License: **Apache-2.0** (confirmed via GitHub license API, 2026-10-05). No license trap.
- **Zot verdict:** the reference registry for our distribution story — self-hostable, zero-cost, full API, sync preserves the referrer graph.

---

## 3. Registry support matrix (Referrers API)

| Registry | Referrers API | Evidence (accessed 2026-10-05) |
|---|---|---|
| Zot | ✅ Yes | Native endpoint in docs; probed `200` + empty index (pacto) |
| Harbor (push / ORAS copy) | ✅ Yes | 2.15.0 displays referrer artifacts pushed directly or via ORAS; PRs #22628/#23029/#23237 merged |
| Harbor (Replication Service) | ❌ No | #23210 open — referrers silently dropped |
| Docker Hub | ✅ Yes | Probed `200` + empty index (pacto, ~10d ago); cosign v3 referrers verified working on Hub (fabiocicerchia/nginx-lua#279). Note: older 2025/early-2026 reports said no — status changed. |
| GHCR | ❌ No | `404 MANIFEST_UNKNOWN` on referrers endpoint (pacto probe; corroborated by oci-zero README); cosign verify cannot find referrer-stored signatures on GHCR (sigstore/cosign#4641, via netbox-mcp commit) |
| Amazon ECR | ✅ Yes | Vendor docs: "support for OCI v1.1… reference artifacts that are defined by the OCI Referrers API" (https://docs.aws.amazon.com/AmazonECR/latest/userguide/images.html); ECR `ListImageReferrers` API sample response shows `"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json"` — exactly our bundle shape. **Caveat:** ECR returns 405 pushing referrer manifests via `oras copy -r` (https://github.com/aws/containers-roadmap/issues/2783) — direct subject-manifest PUT is the safe path. |
| Azure ACR | ✅ Yes (except CMK) | MS Learn: "The OCI Referrers API is supported by most of the ACR features except the CMK-encrypted registry. ORAS will fall back to use OCI Referrers Tag Schema" (https://LEARN.MICROSOFT.COM/en-us/azure/container-registry/container-registry-manage-artifact) |
| JFrog Artifactory | ✅ Yes | Vendor docs: supported since 7.90.1, `GET <url>/<repo>/<image>/referrers/<digest>` (https://jfrog.com/help/r/jfrog-artifactory-documentation/use-referrers-rest-api-to-discover-oci-references?contentId=OwLY_7WigEwwifk7xESMCg) |
| Quay.io | ✅ Yes | Red Hat announcement of Referrers API availability (https://www.Redhat.com/ko/blog/announcing-open-container-initiativereferrers-api-quayio-step-towards-enhanced-security-and-compliance); implementation PR quay/quay#6385 (`FEATURE_REFERRERS_API` default true, merges the `sha256-<digest>` fallback tag into responses) |
| Google Artifact Registry | ✅ Yes | Google docs "manage metadata with attachments"; marked ✅ in rules_img matrix (https://github.com/bazel-contrib/rules_img/blob/HEAD/docs/registry-support.md, updated ~11d ago) |
| CNCF distribution (`registry:2/3`) | ❌ No | Route absent; `oras discover` reports unsupported (pacto probe) |
| GitLab CR / Sonatype Nexus / others | ❓ Unknown | Not verified today — do not claim; probe before onboarding |

Two independent matrices corroborate: pacto's live-probed table (https://github.com/trianalab/pacto/blob/HEAD/docs/evidence-oci-storage.md) and rules_img's matrix (https://github.com/bazel-contrib/rules_img/blob/HEAD/docs/registry-support.md). They agree everywhere except Docker Hub, where pacto's fresh probe (Yes) supersedes rules_img's "unknown" (their docs link is explicitly a subset).

---

## 4. cosign / ORAS changes affecting attach/discover/verify

### cosign (latest **v3.1.3**, 2026-08-06; maintenance line v2.6.5 same day)

- **v3.1.2 (2026-07-17): "fix: include artifactType in OCI 1.1 signature referrer manifest"** (cherry-picked to v2.6.4) — https://github.com/sigstore/cosign/blob/HEAD/CHANGELOG.md. Referrer manifests written by cosign < v3.1.2 may **lack `artifactType`**. Our discovery filters on `artifactType`: a missing field must be a non-match (fail closed), never a silent pass — and our own attach path must always set it (it does).
- **v3.1.1 (2026-06-09): "Deprecate Flags for v4: OCI Referrers"** (https://github.com/sigstore/cosign/pull/4804, merged 2026-05-21) — the referrers-related legacy flags are deprecated ahead of cosign v4. Exact flags marked deprecated (from the PR diff):
  - `--attachment` (`sign`, `verify`) → "please use OCI referrers"
  - `--attachment-tag-prefix` → "please use OCI referrers"
  - `--replace` (`attest`) → "not needed when OCI referrers become the default behavior"
  - `--sign-container-identity` (`sign`) → "not possible when OCI referrers become the default"
  - `--experimental-oci11` (`tree`, `verify`) → "OCI referrers will be the default behavior in future versions"
  The legacy tag-attachment modes are being deleted upstream, not just deprecated in docs. Our spec tag-schema fallback is unaffected (it is the OCI fallback, not cosign's legacy mode), but nothing we build may depend on cosign writing `.sig`/attachment tags.
- v3.0.x baseline: default `--registry-referrers-mode` is `oci-1-1`; v3.0.6 "preserve per-layer annotations in WriteAttestationsReferrer"; v3.0.3 passes insecure-registry flags through to referrers.
- Ecosystem confirmation: cosign v3 always emits signatures as OCI referrer artifacts (`application/vnd.dev.sigstore.bundle.v0.3+json` — our bundle media type); downstream tools (StackRox, synthorg, trivy-web) have all moved discovery to the referrers API with tag-schema fallback. GHCR remains the hole (sigstore/cosign#4641).

### ORAS CLI (latest **v1.3.4**, 2026-08-27)

- **No referrer/discover behavior changes in v1.3.1–v1.3.4** (release notes scanned via GitHub API, 2026-10-05).
- v1.3.0 (already absorbed): `oras discover` is recursive by default (`--depth` controls), the JSON `manifests` field was renamed to `referrers`, and `--distribution-spec v1.1-referrers-tag` forces the tag-schema path for registries without API support.

**Net effect on our flow:** no changes required. The ecosystem has converged on exactly the attach (subject + artifactType) / discover (referrers API → tag-schema fallback) / verify (client-side, digest-pinned) shape our tree already implements.

---

## 5. Distribution story — fail-closed minimal transport matrix

### IN (can carry referrer evidence end-to-end)

Zot · Harbor (direct push or `oras copy` ONLY) · Docker Hub · Amazon ECR (direct PUT; avoid `oras copy -r` of referrer manifests per the 405 edge) · Azure ACR (non-CMK) · JFrog Artifactory ≥7.90.1 · Quay.io · Google Artifact Registry.

### OUT (must refuse / cannot carry)

GHCR (404 on referrers endpoint) · CNCF distribution `registry:2/3` (no route) · **Harbor Replication Service** (silently drops referrers — #23210) · ACR with CMK encryption (tag-schema only).

### Fail-closed rules (map to existing tree code)

1. **Discovery:** Referrers API primary; 404 → tag-schema fallback; any other status → `oci-referrers-malformed` refusal. (Already in `gov/oci_distribution.py`.)
2. **Empty graph:** no referrer for the subject → `oci-referrers-unavailable` refusal, never "assume unsigned is fine." (Already in `gov/evidence_distribute.py`.)
3. **artifactType matching is exact; missing ≠ match.** Pre-cosign-v3.1.2 artifacts lacking `artifactType` are listed but never selected — a stripped/mismatched type fails closed.
4. **Same-repository pinning:** subject and its referrers must live in the same repository. Never chase referrers across a replication or copy boundary — Harbor #23210 proves the graph does not survive replication silently.
5. **Harbor deployments:** document "push directly or `oras copy`; do not rely on replication for evidence repos" until #23210 closes.
6. **Registry onboarding gate:** probe `GET /v2/<repo>/referrers/<digest>` on an empty subject before trusting a new registry — expect `200` + empty index (the pacto method). Anything else → registry stays OUT.
7. **Registry is untrusted storage, always** (already the tree's trust boundary): digest-addressed pulls, per-blob re-hash, subject-digest match, payload authenticity via the bundle's own signature (`gov.evidence_dsse` / `gov.evidence_sigstore`) — never via registry metadata.

---

## 6. Verdicts

- **STEAL — pacto's live-probe onboarding method.** `GET /v2/<repo>/referrers/<digest>` expecting `200` + empty index vs `404 MANIFEST_UNKNOWN` is a 10-line deployment-time conformance probe. Adopt as the registry onboarding gate (rule 6 above). Source: https://github.com/trianalab/pacto/blob/HEAD/docs/evidence-oci-storage.md (Apache-2.0 repo; method only, no code copied).
- **STEAL — Quay's fallback-tag merge semantics** (quay/quay#6385: on the read path, also resolve the `sha256-<digest>` tag and merge into the referrers response). Reference behavior if we ever harden our own read path; no action now.
- **ADAPT — cosign v3.1.2 `artifactType` lesson.** Our attach path already sets `artifactType`; add a pin test that discovery treats a referrer manifest with *missing* `artifactType` as a non-match (not an error, not a match). Small, test-first, at the existing seam.
- **WATCH — Harbor #23210** (open, `needs/follow-up`; re-check quarterly; unblocks replication-based distribution when fixed). **WATCH — GHCR** (no native API; track sigstore/cosign#4641 and GHCR changelog; GHCR stays OUT until then). **WATCH — cosign v4** (legacy referrer flags being removed; our spec fallback is unaffected but re-verify the deprecation list at v4 release). **WATCH — ECR `oras copy -r` 405 edge** (aws/containers-roadmap#2783).
- **SKIP — cosign legacy `.sig` tag scheme** (already SKIP-as-design in the tree; upstream is deleting it). **SKIP — building/operating our own registry** (Zot is Apache-2.0, single binary, full API — self-host that instead). **SKIP — Harbor replication for evidence carriage** (silent drop; no workaround until #23210 is fixed).

---

## 7. Delta vs the 2026-10-05 pass (what changed)

The earlier pass established: Harbor UI ignores cosign-v3 referrer signatures (#22592, #22643); Harbor Replication ignores referrer artifacts (#23210); Harbor 2.15.0 displays referrer artifacts pushed directly or via ORAS. This pass updates:

1. **UI visibility: RESOLVED.** Both #22592 (closed 2026-02-26) and #22643 (closed 2025-12-15) are closed; PR #22628 (cosign v3 bundle format, merged 2025-12-15) plus #23029 (signature verification via referrers API, merged 2026-06-29) closed the recognition gap. The UI-blindness finding no longer holds on the push path.
2. **Replication gap: CONFIRMED STILL OPEN.** #23210 is open with `needs/follow-up`; the stale-bot nearly closed it 2026-09-19 and a community member revived it 2026-10-03. No fix PR exists. The "only direct-push works" workaround from the earlier pass remains the only safe Harbor path.
3. **Harbor keeps investing in referrers** (proxy-cache referrers proxying #23237, index-children signature inheritance #23540) — the trajectory favors eventual replication support, but it is not here.
4. **Docker Hub flipped to YES** (live-probed `200` + empty index ~10 days ago; cosign v3 referrers verified working there). Earlier reports of "no support" are stale.
5. **cosign v3.1.2 artifactType fix** is new information with a direct bearing on our discovery filter (missing field ≠ match).
6. **Registry matrix widened:** Quay.io (announced + implemented), Google Artifact Registry, and Artifactory ≥7.90.1 are confirmed IN; GHCR and CNCF distribution remain OUT.

## 8. Operator runbook (registry onboarding, fail-closed)

For each registry a deployment wants to carry evidence:

1. **Probe:** `GET /v2/<repo>/referrers/sha256:<64 hex>` on a subject with no referrers, with `Accept: application/vnd.oci.image.index.v1+json`.
   - `200` + `{"manifests": []}` (or `{"referrers": []}`) → candidate IN.
   - `404` (any code: `MANIFEST_UNKNOWN`, `NAME_UNKNOWN`) → tag-schema fallback only; registry is usable ONLY if the fallback tag round-trips in testing, and discovery must still refuse (not guess) when the fallback is absent.
   - Anything else (401/403/405/500) → OUT until resolved.
2. **Round-trip test:** push a subject manifest, attach a referrer with our `artifactType`, discover it, pull it by digest, verify byte-identity and subject match. Delete the test repo afterwards.
3. **Replication audit:** if the registry replicates (Harbor, Artifactory smart-remote, ECR cross-region), repeat the round-trip THROUGH the replication path. Harbor fails this today — that is exactly #23210.
4. **Pin the result:** record the registry + probe outcome in the deployment config. Re-probe on registry upgrades (Docker Hub's flip from NO to YES is the cautionary tale).
5. **Auth:** registries needing auth take a Bearer <redacted> via `auth_token=<redacted> — never anonymous-write; fail closed without a configured token (tree already does this).

## 9. License notes

- **Zot:** Apache-2.0 (GitHub license API, 2026-10-05). Self-hosting Zot as our reference registry introduces no license obligation beyond the standard Apache-2.0 notice/attribution. No vendoring proposed in this lane.
- **pacto evidence-oci-storage doc:** method reference only; no code copied.
- **Quay PR #6385 / Harbor PRs:** behavioral references; no code copied.
- Nothing in this lane's recommendations requires new third-party code in the tree.
