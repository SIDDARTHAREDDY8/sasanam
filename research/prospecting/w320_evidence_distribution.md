# Evidence distribution — what comes after the envelope: prospectus

**Wave-320 lane 5 · research only · $0 spend · public sources only · 2026-10-04**
**Base:** `0cb9c765` (wave-319 follow-up merge). Mission: the evidence-DISTRIBUTION layer — how
evidence bundles get from producer to auditor. The wave-317 prospectus ordered the envelope work as
in-toto re-enveloping (done) → Sigstore-bundle distribution (this lane) → offline verifier (done) →
Rekor-pattern witness (done) → VSA decision packets (done). Distribution was the remaining gap.

Method: four parallel research subagents on primary sources (specs, source code, first-party docs),
all claims cited; STEAL/ADAPT/WATCH/SKIP verdicts per source; license checks (Apache-2.0/MIT
preferred; GPL/AGPL flagged); unverifiable claims recorded as open questions. Raw child reports at
`~/workspace/teams/wave320-prospect/inputs/` (sigstore_bundle.md, oras_oci.md,
rekor_client_patterns.md, offline_handoff.md).

## Headline

**The distribution stack composes, it doesn't need inventing:** Sigstore-bundle shape for
auditor-tooling interop (keyed, non-Fulcio identity — proven verifiable by cosign and sigstore-go)
+ OCI 1.1 referrers for discovery (subject-bearing manifests, tag-schema fallback) + C2SP
signed-note checkpoints for freshness/witnessing (static fetch endpoints, bundle-local offline
verification) + a signed single-file offline export with a custody record for the last mile.
**The registry is untrusted storage in every pattern that works** — digest-address pulls, per-blob
digest checks, subject-digest matching, and signature verification all stay client-side. QR codes
carry the root of trust (a signed checkpoint, ~200–500 bytes), never the payload.

## 1. Sigstore bundle format — interop is real

**Bottom line (from `inputs/sigstore_bundle.md`): yes — Sasanam can emit a spec-valid Sigstore
bundle carrying a NON-Fulcio identity, and standard tooling verifies it.** The Bundle proto
explicitly blesses `VerificationMaterial` form (1) — `public_key` / `PublicKeyIdentifier` — for
self-managed keys ("Form (1) MAY be used with the PGI for self-managed keys," proto comment,
`sigstore/protobuf-specs` main). Keyed bundles verify in **cosign** (`verify-blob-attestation
--key … --bundle … --insecure-ignore-tlog` → `Verified OK`, exit 0, proven by an independent
2026-08-15 spike with `verificationMaterial == {"publicKey": {}}`) and **sigstore-go**
(`verify.WithKey()` exists exactly for "your bundle was signed with a key, and thus does not have
a certificate identity"). Rekor tlog entries and RFC 3161 timestamps are OPTIONAL — a
fully-offline, self-signed-Ed25519 Sasanam export is a conformant bundle.

- **STEAL — the Bundle v0.3 JSON shape** (`mediaType` / `verificationMaterial.publicKey` /
  `dsseEnvelope` / `messageSignature`). Apache-2.0, stable, multiple independent verifiers.
  Field-name trap (sigstore/docs#451): the JSON key is `publicKey`, not `publicKeyIdentifier` —
  verifiers ignore the wrong name, leaving the `content` oneof empty.
- **STEAL — the keyed-bundle pattern** (form 1 + out-of-band key) for our self-signed Ed25519
  keys. Populate `hint` with a hex key fingerprint (OSSF model-signing convention requires it;
  the proto leaves the format out-of-band — propose `hex(sha256(DER(SPKI)))`); keep DSSE `keyid`
  absent/empty so the hint-consistency MUST ("key hints MUST be exactly the same in the
  verification material and in the DSSE envelope") is satisfied by emptiness on both sides.
- **ADAPT — one signature per DSSE envelope per bundle.** The proto is normative: "DSSE
  envelopes in a bundle MUST have exactly one signature… a client MUST reject an envelope if
  the number of signatures is not equal to one." Our multi-signature bundles fan out at export.
  Also adapt: confirm our Ed25519 signatures cover DSSE PAE (`PAE(UTF8(payloadType), payload)`,
  secure-systems-lab/dsse); re-sign at export if they don't. Use a Sasanam-namespaced
  `payloadType` (e.g. `application/vnd.sasanam.evidence+json`) that auditors pin.
- **SKIP — mapping our audit log into `tlogEntries`.** Optional field; `log_id` is defined as a
  Rekor log's key ID. Our hash-chained log is not Rekor — do not dress it up as
  `TransparencyLogEntry`. Anchor receipts stay inside the signed payload, verified by our
  offline verifier. (CVE-2026-22703's binding rule still applies: the receipt must name the
  bundle digest + signature + key.)
- **SKIP — Fulcio keyless identity.** Incompatible with our offline self-signed key model (and
  the wave-310 research already flagged the four 2026 Sigstore CVEs as negative design rules
  for anything we build ourselves).
- **WATCH — sigstore-python as an auditor client.** Keyed-bundle (non-cert) verification support
  could not be confirmed this session; its verifier/policy model is certificate-identity-centric.
  Revisit by reading `sigstore/verify/verifier.py` + `models.py` on main before claiming interop.
- **WATCH — per-tool Ed25519 acceptance.** Pin Ed25519 support per target client (cosign,
  sigstore-go, sigstore-python) before claiming interop; cosign historically defaults to
  ECDSA-P256 but supports Ed25519 keys.

License note: `sigstore/protobuf-specs`, cosign, sigstore-go, sigstore-python are all
Apache-2.0. The DSSE *spec text* is Community Specification License 1.0 — a flag only if we
copy spec prose; our DSSE support is landed independently. Emitting spec-shaped bundles needs
no vendored code.

## 2. ORAS / OCI — the discovery and transport pattern

**Bottom line (from `inputs/oras_oci.md`):** the converged OCI 1.1 model — image manifest +
`artifactType` + `subject` manifest field + referrers API — is the standardized discovery
mechanism for "evidence *about* artifact X," and the wave-307 spike already proved the byte
round-trip. Harbor's content-trust (Cosign) deployment policy is a confirmed registry-side
"only signed pulls" gate (goharbor.io docs).

- **STEAL — OCI 1.1 referrers API + `subject` field** (opencontainers specs, Apache-2.0).
  Evidence bundles (and their signatures) push as `subject`-bearing manifests; consumers
  discover them with `GET /v2/<repo>/referrers/<digest>`. No custom discovery protocol.
  Use the converged OCI image-manifest form, not the legacy
  `application/vnd.cncf.oras.artifact.manifest.v1+json`.
- **ADAPT — the referrers tag-schema fallback.** Spec-mandated: 404 on the API → client falls
  back to the `sha256-<hex>` tag index. Portability story for registries without the API
  (GHCR support is disputed in third-party measurements — the fallback covers it either way).
  Sasanam's client implements "try API, fall back to tag index," mirroring `oras discover`.
- **STEAL — ORAS artifact packaging pattern** (manifest + `artifactType` + per-layer
  `org.opencontainers.image.title`; empty descriptor for metadata-only). Exactly what the
  wave-307 spike validated.
- **ADAPT — deterministic manifests** (Pacto pattern, third-party): build manifests without
  creation timestamps so identical evidence yields identical digests — free deduplication and a
  verifiable "same evidence → same digest" property.
- **ADAPT — cosign's signature *formats*** (SimpleSigning layer
  `application/vnd.dev.cosign.simplesigning.v1+json`, DSSE attestations
  `application/vnd.dsse.envelope.v1+json`, Sigstore bundle
  `application/vnd.dev.sigstore.bundle.v0.3+json` with cosign artifact types). These are the
  interoperable envelopes to attach as referrers under our evidence manifests.
- **SKIP — cosign's `sha256-<digest>.sig` tag scheme as a design.** Legacy, explicitly
  non-standard per cosign's own README, tag-namespace pollution, TOCTOU caveats. Compatibility
  read path only — never the Sasanam-native layout.
- **STEAL — Harbor content-trust (Cosign) deployment policy.** Official docs: "Harbor will
  only allow verified images to be pulled" when the project policy is checked. This is the
  registry-side enforcement hook for "only signed evidence bundles are servable." Pair with
  Harbor tag-immutability rules (max 15/project) for release tags. Operational caveat
  (goharbor/harbor#22650): the policy middleware runs on all manifest GETs and can block
  *signing* workflows that read the manifest — use a staging project or toggle pattern; also
  unverified whether the policy evaluates signatures on non-image custom-`artifactType`
  manifests (docs frame it around images — needs an empirical check).
- **STEAL — Harbor as the distribution registry** (already the flagged direction).
  Apache-2.0, OCI-native, the two policy hooks above, plus replication for multi-site
  distribution. Do not expect Harbor to verify evidence *semantics* — it gates on signature
  presence and tag immutability, not bundle contents.
- **WATCH — cosign CLI as the signing tool.** License-clean, ecosystem default; signing-pipeline
  integration comes later (key custody is Sasanam's own KMS work). cosign v3's default storage
  behavior is disputed between two third-party sources — resolve against source before
  depending on either.
- **SKIP — Notation (Notary v2).** Second signing ecosystem for no evidence-bundle benefit
  over cosign.

**The client-side rule the spec itself establishes** (distribution-spec "Content Verification"
use case): the registry is modeled as *untrusted* — "An untrusted registry returns a manifest.
After each layer is downloaded, the engine verifies the digest of the layer." Digest-address
pulls, per-blob digest checks, `subject`-digest matching on referrers (a malicious registry can
inject extra referrers — the spec authenticates nothing), and cryptographic signature
verification all stay client-side. Tag TOCTOU is defeated by resolving tags to digests once and
speaking digest-only afterward.

## 3. Rekor v2 / Tessera client patterns — the checkpoint fetch shape

**Bottom line (from `inputs/rekor_client_patterns.md`):** Rekor v2's distribution pattern is
`GET /api/v2/checkpoint` → C2SP signed-note checkpoint (text/plain) → client verifies against
the TUF TrustedRoot via checkpoint key ID, reads root/size ONLY from the verified checkpoint,
and recomputes proofs client-side from tiles (`/api/v2/tile/{L}/{N}`). Rekor v2 removed ALL
online verification/search APIs — verification is bundle-local and offline. This maps directly
onto Sasanam's witness_consistency distribution. Three honest caveats: Sigstore's own v2
checkpoints launched *unwitnessed* (the fetch pattern is proven, the witness side is not);
witness discovery is out-of-band everywhere; and **client-to-client gossip has no production
deployment 13 years after RFC 6962 asked for it** (Dahlberg et al. 2019: "no gossip mechanism
is widely deployed").

- **STEAL — the fetch pattern.** Static, cacheable, multi-prefix endpoints for
  checkpoint/tiles/entries; signed-note checkpoint with unknown-signature tolerance (this is
  what enables witness cosigning and key rotation on the same note); no redirects on the
  checkpoint endpoint; low-cache headers. Publish Sasanam's signed checkpoints at a mutable
  endpoint; clients recompute everything else.
- **ADAPT — the C2SP witness protocol shape.** Log→witness `POST add-checkpoint` (old size +
  ≤63 consistency-proof lines + checkpoint); monitors fetch cosigned checkpoints via
  `GET <monitoring-prefix>/<origin-hash>/checkpoint`; cosignatures ride as extra `—`
  signature lines. Composes with our k-of-n cosignature model. Pin the witness set in a
  signed policy artifact (TUF-like) — there is no production-grade *open* discovery to steal
  (transparency-dev's is a community list with human admission; Google's is bilateral and
  closed; Rekor v2 plans TUF-distributed witness policy).
- **SKIP — client-to-client STH gossip as a designed protocol.** The production answer is
  independent monitors + out-of-band comparison + governance (log-list disqualification).
  Do not build STH gossip.
- **ADAPT — the fail-closed monitor-loop exemplar** (MarkovianProtocol/log-monitor,
  Apache-2.0, 2026-08): verify log signature + each pinned witness cosignature, RFC 6962
  consistency from last trusted head, **recompute the root from served leaf bytes**
  ("authenticating the head alone is not enough"), advance the trusted head only on full
  success, alert on frozen checkpoints, daily heartbeat so silence is itself a signal.
- **SKIP — Tessera's fail-open witnessing default** (negative design rule stands, now
  corroborated). Production's actual shape is *split by layer*: fail-open at the log during
  witness-network bootstrap (Tessera PR #634 calls it "temporary"; TesseraCT hard-codes it
  while the public witness network is "experimental"), **fail-closed at every verifier**
  (cosign offline bundles, Chrome's SCT rejection since 2018, Rekor v2 write-path blocking).
  If Sasanam stays fail-closed on the log side too, that is *stricter than production* — the
  availability cost (a witness outage halts checkpoint publication) must be budgeted
  explicitly, not discovered in an incident.
- **STEAL — bundle-local offline verification.** Rekor v2 removed online verify/search; the
  receipt carries the inclusion proof + signed checkpoint; verifiers never call home. This is
  exactly the evidence-envelope direction. cosign's named escape hatch
  (`--insecure-ignore-tlog`) is the pattern for any relaxation: explicit, named, auditable.

## 4. Offline handoff — what auditors actually accept

**Bottom line (from `inputs/offline_handoff.md`):** no compliance regime mandates a specific
last-mile medium. FedRAMP, SOC 2, NIAP/CC, SEC/FINRA, and ISO/IEC 27037 all converge on the
same four transfer requirements: (1) tamper-evident or audit-trailed storage, (2) integrity
provable end-to-end, (3) format readily readable/usable by the examiner, (4) prompt production.
The medium is a site-policy question, not a regulatory one.

- **STEAL — the signed-checkpoint-as-QR-trust-anchor pattern.** QR v40-L byte max = 2,953
  bytes (ISO 18004:2024); a signed checkpoint (digest + Ed25519 sig + witness cosigs,
  ~200–500 bytes) fits one modest QR; a full bundle never does. **QR carries the root of
  trust, never the payload.** Existence proofs: Bitcoin air-gap QR flows (Coldcard BBQR,
  Passport animated QR, SeedSigner MIT-licensed) and BCR-2020-005 UR fountain-coded animated
  QR (CRC32 per part) for arbitrary payloads across an optical air gap.
- **ADAPT — the sign-then-cross ceremony** (OPSWAT-documented): sign inside the governed
  domain, cross the air gap, verify on import, log custody. For auditor handoff no data diode
  is needed — the signature + custody log is the defensible part. NCDSMO "Raise the Bar" and
  DHS push hardware-enforced one-way transfer only when either side is *untrusted*.
- **STEAL — ISO/IEC 27037 custody records.** The one standard that speaks to evidence
  *movement* (identification/collection/acquisition/preservation): every offline handoff
  carries a machine-readable custody note (who handled it, when, what medium, what hash) —
  that is the artifact an auditor trained on 27037 looks for.
- **ADAPT — the SEC 17a-4 production vocabulary.** "Furnish promptly… legible, true, complete
  copies in a reasonably usable electronic format"; WORM *or* a complete time-stamped audit
  trail. FINRA's AI pass condition is literally "selected record + audit trail exported
  promptly in readable, usable form." Write the export runbook in this vocabulary.
- **WATCH — FedRAMP 20x format finalization.** RFC-0014/0024 move the wire format to OSCAL
  JSON (assessment-results) for automated validation. Sasanam already emits OSCAL component
  definitions (wave-174); the evidence container format is what gets standardized — nothing
  about QR/physical handoff.
- **SKIP — Data Matrix** (weaker capacity than QR, no ecosystem) and **QR as the primary
  handoff** (no regime rewards it; lead with the signed bundle). Also SKIP lifting
  gnome-keysign/OpenKeychain code (GPL; solves key-signing, not handoff).

Regime specifics worth building for: SOC 2 auditors demand the **full population first**
(every change/access grant/offboarding in the period), then pick 25–40 random samples —
the *population query* is the hard part, so the export must answer "give me everything"
before "give me these 25." GRC platforms (Vanta/Drata/Secureframe) are the dominant SOC 2
transfer medium: a file bundle dropped into a portal, not a pull API. FedRAMP moves through
secure repositories (USDA Connect.gov) on a monthly ConMon cadence.

## License summary

No GPL/AGPL traps anywhere in this stack. Apache-2.0: sigstore/protobuf-specs, cosign,
sigstore-go, sigstore-python, oras-go, oras-py, Harbor, OCI specs, transparency-dev/tessera,
MarkovianProtocol/log-monitor. The DSSE *spec text* is Community Specification License 1.0 —
a flag only if spec prose is ever copied; Sasanam's DSSE support is landed independently.
C2SP spec license text was not read by one child (protocol adoption only — no code). Two
open questions: the ORAS CLI's own LICENSE file (inferred Apache-2.0, not opened) and
sigstore-python's license-file verification (secondary-sourced as Apache-2.0).

## Direction brief for a future evidence-distribution build lane

Ordered by evidence; each is a bounded lane a parent can dispatch. None of this is product
code — it is the build order.

1. **Sigstore-bundle export** → `gov/evidence_sigstore_export.py` (est. ~300 lines stdlib).
   Emit v0.3 bundles: `mediaType` v0.3 JSON, `verificationMaterial.publicKey` with hex
   key-fingerprint `hint`, one DSSE envelope per signature (fan out at export), DSSE PAE
   check (re-sign at export if the existing Ed25519 sig doesn't cover PAE), Sasanam-namespaced
   `payloadType`, `tlogEntries` absent (our log is not Rekor). Acceptance: cosign
   `verify-blob-attestation --key … --insecure-ignore-tlog` → `Verified OK`; sigstore-go
   `WithKey()` verifies. Do NOT shoehorn the audit log into `TransparencyLogEntry`.
2. **OCI distribution** → evidence bundles as `subject`-bearing manifests with a Sasanam
   `artifactType`; deterministic manifests (no timestamps); client implements referrers-API
   → tag-schema fallback. Acceptance: `oras discover` finds the bundle from the artifact
   digest; byte-identical round-trip; tag-only registries still resolve via the fallback.
3. **Witness checkpoint publication** → publish C2SP signed-note checkpoints at a static
   low-cache mutable endpoint (+ monitoring prefix); witness set pinned in a signed policy
   artifact (TUF-like); clients verify checkpoint sigs and recompute proofs from served
   data. Acceptance: a client with only the policy artifact verifies a fresh checkpoint
   with zero calls to the log.
4. **Monitor loop** → adapt the MarkovianProtocol/log-monitor exemplar: fail-closed head
   advancement, root recomputed from served leaves, frozen-checkpoint + heartbeat alerting.
   This is the production substitute for gossip — do not build client-to-client STH gossip.
5. **Offline export** → three layers: (L1) signed single-file bundle + integrity manifest +
   ISO 27037 custody record; (L2) one-QR cosigned checkpoint as the air-gap trust anchor;
   (L3) optional fountain-coded animated QR transport. Export documented as a *production
   procedure* in SEC 17a-4 vocabulary (prompt, legible, true, complete, reasonably usable
   electronic format). Acceptance: an auditor with the QR + the file verifies the bundle
   offline with no network.
6. **Harbor deployment policy** → content-trust (Cosign) policy + tag-immutability rules on
   the evidence project; empirically confirm the policy evaluates signatures on
   custom-`artifactType` manifests before relying on it (open question from the research).

**Cross-cutting design rules (from the research):**
- The registry is untrusted storage. Digest-address pulls, per-blob digest checks,
  subject-digest matching, signature verification — all client-side, always.
- One signature per DSSE envelope per bundle; fan out at export.
- No Rekor cosplay: our chain is not Rekor; export `tlogEntries` absent.
- No gossip protocol. Monitors + policy-pinned witnesses + log-list-style governance.
- Fail-closed is stricter than production — budget the availability cost explicitly (witness
  outage halts checkpoint publication; say so in the runbook).
- QR = root of trust, never payload. The population query (SOC 2's "give me everything")
  is the hard export problem, not the medium.

## Suggested wave order (parent's call)

- Wave N+1: items 1+2 (bounded, testable, the interop story — this is what makes "sell
  evidence, not the engine" concrete for tooling auditors already run).
- Wave N+2: items 3+4 (checkpoint publication + monitor loop; needs the witness policy
  artifact designed first).
- Wave N+3: item 5 (offline export; mostly procedure + small tooling) and item 6 (Harbor
  policy; needs a live Harbor to verify against).

## Open questions (from the children; not verified — do not treat as findings)

1. sigstore-python keyed-bundle (non-cert) verification support — read
   `sigstore/verify/verifier.py` + `models.py` on main before claiming interop.
2. Per-tool Ed25519 acceptance in keyed bundles (cosign, sigstore-go, sigstore-python).
3. The "Verification using a Bundle" client spec (Google doc referenced in proto comments)
   — unfetched; proto comments + three proven verifiers suffice for the interop claim.
4. cosign v3 default storage behavior — two third-party sources contradict; resolve against
   source before depending on either path.
5. GHCR referrers-API support — contradictory measurements; tag-schema fallback covers it.
6. Whether Harbor's content-trust policy evaluates signatures on non-image
   custom-`artifactType` manifests — needs an empirical check.
7. Status of Sigstore's public witness network — CLIENTS.md says checkpoints were
   unwitnessed at v2 launch "while we wait for the launch of a public witness network";
   no authoritative confirmation of launch found.
8. ORAS CLI's own LICENSE file — not directly opened (inferred Apache-2.0).
9. UR spec (© Blockchain Commons) and C2SP spec license statements — pattern adoption is
   safe; text/code reuse needs a check.
10. No FedRAMP 3PAO physical-transfer guidance found; NIAP physical-media acceptance
    unverified; FedRAMP 20x post-pilot formats pending.
