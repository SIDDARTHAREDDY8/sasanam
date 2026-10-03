# Offline Verifier & Auditor UX — how auditors consume Sigstore bundles and SLSA provenance in the wild

**Wave-310 Lane B research note · 2026-10-03 · research only, $0 spend, public sources only.**
Every factual claim cited (URL + access date). Filed for `research/prospecting/`.

## TL;DR

The offline evidence bundle's next steps (Sigstore-bundle distribution →
offline verifier → VSA decision packets → Rekor-pattern witnessing) are exactly
the places where the ecosystem has already learned the hard lessons. The
stealable core: the **registystack offline-verifier pattern** (pinned verifier,
no skip-options, narrow inputs, zero network, five negative tests), a
**DepGuard-shaped typed failure taxonomy** (11 codes, typed exit codes),
**SLSA v1.2's VSA consumer procedure** (seven mandatory steps; PASSED ≠ ALLOW),
**Witness's trust-roots-inside-signed-policy binding**, **GUAC's evidence
metadata discipline**, and four 2026 Sigstore CVEs as negative design rules
(expired-issuer acceptance, missing entry/artifact binding, optional-by-default
claim checks, crash-path exit-0). No copyleft anywhere in the reviewed surface.

## 1. The registystack offline-verifier pattern

Primary source: registystack/registry-stack dependency-vetting note, dated
2026-07-30 — https://raw.githubusercontent.com/registrystack/registry-stack/HEAD/release/notes/dependency-vetting-sigstore-verify.md (read 2026-10-03).

1. Pin the verifier exactly: `sigstore-verify` pinned to 0.11.0, default features disabled.
2. No options to skip certificate-chain, SCT, transparency-log, checkpoint, inclusion-proof, signed-entry-timestamp, or artifact-signature verification — full set, no knobs.
3. Narrow inputs only: exact canonical payload bytes; inline Sigstore protobuf bundle; a compiled-in production trusted root identified by its reviewed JSON SHA-256 (`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`); exact release workflow identity + GitHub Actions OIDC issuer.
4. No network in the verify path: "constructs `TrustedRoot` and `Bundle` directly from local bytes and calls the synchronous offline verifier."
5. Negative tests reject: altered artifact bytes; wrong certificate identity; wrong trusted root; invalid signing time; corrupted Rekor inclusion proof. Plus a pinned known-good positive (Cosign 3.0.4 release bundle).

Public-side UX mirrors the same discipline: verify one Sigstore bundle first, then every covered payload by checksum (`release/VERIFY.md`); the checksum file *excludes itself and its own bundle/provenance* — closure hygiene to copy.

Honest caveat: the current workspace `Cargo.lock` at HEAD contains no `sigstore-verify`/`sigstore` entries — the pattern evidence is the vetting doc itself; the Rust code has moved out of the workspace since the 2026-07-30 review. Cite the doc, not the code.

## 2. Sigstore offline-verification mechanics

- **TrustedRoot from local bytes:** `sigstore-go` exposes `NewTrustedRootFromJSON(rootJSON []byte)` ("returns a Sigstore trusted root from JSON") plus `NewTrustedRootFromPath`/`FromProtobuf`; the consumer is `NewSignedEntityVerifier(trustedMaterial root.TrustedMaterial, …)`. No network in any constructor. (https://pkg.go.dev/github.com/sigstore/sigstore-go@v0.7.2/pkg/root, read 2026-10-03)
- **Minting a root locally:** `cosign trusted-root create` with `--fulcio/--rekor/--ctfe/--tsa` PEM material + validity windows, or `--with-default-services` to populate from the Sigstore TUF root. (https://github.com/sigstore/cosign/blob/HEAD/doc/cosign_trusted-root_create.md)
- **Air-gap contract:** `cosign verify --offline=true --trusted-root <file> --local-image`. Caveats verbatim: "This section is out of date"; "Most verification workflows require periodically requesting service keys from a TUF repository"; "The contents of this file will change without notification. By not using TUF, you will need to build your own mechanism to keep your airgapped copy of this file up-to-date." (sigstore/cosign README)
- **TUF is not for the air-gapped verifier:** sigstore-go's `Options` docs say `WithForceCache` "is not an optimal control for air-gapped environments. Clients instead should provide a trust root file directly to the client to bypass TUF." (https://pkg.go.dev/github.com/sigstore/sigstore-go@v0.7.1/pkg/tuf) Rotation is a reviewed ceremony outside the verifier: fetch the new root over TUF on a connected machine, review it as a trust-policy change, pin its SHA-256. Never silently fall back to embedded defaults on expiry (documented cosign BYO-TUF footgun: expired local custom roots made clients fall back to Cosign's embedded TUF metadata — https://blog.sigstore.dev/sigstore-bring-your-own-stuf-with-tuf-40febfd2badd/).
- **TUF rotation events:** 2024-03-14 new trust root broke cosign < v2.2.0 and sigstore-rust clients (Sigstore TSC blog, `content/tuf-root-update.md`); 2022-10-18 iteration 5 was backward-incompatible (fulcio README, `ceremony/2022-10-18/repository/5.root.json`); root-signing resigns online keys "at least every three days because of online signature expiry". Lesson: publish a client-compat matrix with every rotation; auditors inherit this control.

## 3. Rekor inclusion proofs, verified offline

From rekor-tiles `CLIENTS.md` (https://github.com/sigstore/rekor-tiles/blob/HEAD/CLIENTS.md, read 2026-10-03):

- Clients must be *given* the inclusion proof and checkpoint inside the bundle — Rekor v2 removed online verification/search APIs.
- **Checkpoint first:** "The root hash and tree size should be parsed from a verified checkpoint, after verifying `TransparencyLogEntry.inclusion_proof.checkpoint`. Do not use the unverified root hash and tree size." The duplicated `inclusion_proof.{log_index,root_hash,tree_size}` fields "should be ignored."
- Log lookup by C2SP checkpoint key ID (`SHA-256(key name || 0x0A || 0x01 || pubkey)[:4]`) matched against local TrustedRoot instances; must handle multiple logs with overlapping validity windows.
- `integrated_time` is always 0 in v2 and "MUST be ignored." Rekor will no longer return SETs; clients fetch RFC 3161 timestamps from a TSA and include them in the bundle.
- Reference API: `VerifyCheckpoint`, `VerifyInclusionProof`, `VerifyLogEntry`, `VerifyWitnessedCheckpoint` (https://pkg.go.dev/github.com/sigstore/rekor-tiles/v2/pkg/verify).
- The sigstore-python#248 lesson: "When verifying inclusion proof, there needs to be a pin on the root hash… verify 1) the signature on the checkpoint and 2) the root hash in the checkpoint matches the root hash from the inclusion proof… Otherwise inclusion proofs don't mitigate attacks where you are served a valid inclusion proof on some random log." (https://github.com/sigstore/sigstore-python/issues/248)

## 4. RFC 3161 timestamps, verified offline

- `VerifyTimestampAuthority(entity, trustedMaterial)` and `VerifyObserverTimestamps` — "In order to be verifiable, a SignedEntity must have at least one verified 'observer timestamp'"; `WithSignedTimestamps(threshold)` verifies timestamps "using the TrustedMaterial's TimestampingAuthorities()" and uses the result to verify short-lived certs. (https://pkg.go.dev/github.com/sigstore/sigstore-go@v0.7.2/pkg/verify)
- Trust material needed locally: TSA CA chains + per-authority `validFor` windows inside trusted_root.json.
- **Authority isolation (sigstore-rust PR #166, TOB-SIGSTORE-11 fix):** each timestamp authority verified in isolation — only that authority's root as trust anchor, only its intermediates, only its leaf as the pinned signer; on success, only that authority's `valid_for` is checked. The pooled-chain + separate-window API was removed as a footgun. (https://github.com/sigstore/sigstore-rust/pull/166)
- **Clock as control:** Fulcio security model — "A verifier should check that the inclusion time in the log was during the certificate's validity period." Sigstore docs — "Time is a critical component of Sigstore." Rekor v1 caveat (verbatim): its timestamp "comes from Rekor's internal clock, which is not externally verifiable, and a timestamp is not a part of the node that goes into the append-only data structure… meaning the timestamp is mutable in Rekor without detection" — Rekor v2 moved to a separate TSA for this reason. (https://github.com/sigstore/fulcio docs/security-model.md; sigstore/docs content/en/cosign/verifying/timestamps.md)

## 5. Failure taxonomies in the wild

- **DepGuard** (`docs/protocol/attestation-v1.md`): 11 typed failures in fixed verification order (`MALFORMED_DSSE`, `INVALID_SIGNATURE`, `UNSUPPORTED_PAYLOAD_TYPE`, `INVALID_STATEMENT`, `UNSUPPORTED_PREDICATE`, `SCHEMA_VALIDATION_FAILED`, `UNSUPPORTED_SCHEMA`, `UNSUPPORTED_METHODOLOGY`, `INVALID_EVIDENCE_DIGEST`, `INVALID_SUBJECT`, `INVALID_ARTIFACT_RELATIONSHIP`); each maps to the step that produced it; JSON `VALID` / `{ "status":"INVALID", "reason":"…" }`; typed exit codes 0/40/41/42/43/44; RFC 8785 canonical JSON; DSSE pre-auth encoding specified byte-for-byte. (https://raw.githubusercontent.com/aiwithllm-ui/depguard/HEAD/docs/protocol/attestation-v1.md)
- **slsa-verifier** `errors/errors.go`: ~40 named errors — envelope/digest (`ErrorInvalidDssePayload`, `ErrorMismatchHash`, `ErrorInvalidSubject`), identity/issuer (`ErrorMismatchBuilderID`, `ErrorInvalidOIDCIssuer`), expectation-mismatch (`ErrorMismatchSource`, `ErrorMismatchTag`, `ErrorMismatchVerifiedLevels`), transparency (`ErrorNoValidRekorEntries`, `ErrorInvalidRekorEntry`), format. **README carries a maintenance banner — the project is no longer actively maintained; `gh attestation verify` is recommended.** Design-by-reference safe; dependency unsafe. (https://github.com/slsa-framework/slsa-verifier)
- **Witness** `cmd/verify.go` (lines 287–329): per-step evidence transcript — `Verification failed` then per step `Step: <name>` with `collection rejected: <name>, Reason: <reason>`; success prints `Verification succeeded` + `Evidence:` with each passed step's evidence reference. (https://github.com/in-toto/witness)
- **registystack**: five named negative tests reading as a minimal taxonomy (altered bytes / wrong identity / wrong root / bad time / corrupted inclusion proof).
- **Observed pattern:** mature verifiers separate (a) parse/decode, (b) crypto, (c) policy/type-unsupported, (d) consistency/binding failures — surfaced as typed constants + human reasons + typed exit codes + JSON output.

## 6. Attestation verifiers and evidence consumption

- **slsa-verifier UX:** auditor brings expectations — `slsa-verifier verify-artifact <files> --provenance-path <intoto.jsonl> --source-uri github.com/org/repo [--source-tag vX.Y.Z] [--builder-id …]`; success prints `PASSED: Verified SLSA provenance`; `--print-provenance` pipes the verified statement into policy engines.
- **Witness policy binding:** signed Witness policy (DSSE, payloadType `https://witness.testifysec.com/policy/v0.1`); trust roots (`publickeys`, `roots`, `timestampauthorities`) travel *inside* the signed policy; single external anchor is the policy-signing key: `witness verify -k policypublic.pem -p policy.signed.json -a build-attestation.json -f hello.txt`. `expires` ISO-8601 — an expired policy always fails. Embedded base64 Rego must output a human `deny` reason. (docs/concepts/policy.md, docs/tutorials/artifact-policy.md)
- **in-toto layout verification:** six checks — layout signed by owner key(s); not expired; each step performed/signed by authorized functionary (threshold); expected commands; materials/products matched rules; inspections. Artifact rules: CREATE/DELETE/MODIFY/ALLOW/DISALLOW/REQUIRE/MATCH — fail closed with a `DISALLOW *` terminal rule. (in-toto README; in_toto/verifylib.go `InTotoVerify` doc)
- **GUAC consumption:** `guacone query vuln purl "pkg:guac/spdx/…"` finds paths from pURL through `IsDependency` edges to any known vulnerability in direct *and indirect* deps, returning the remediation path. Every typed edge carries provenance metadata (`CertifyVuln.metadata`: `timeScanned`, `dbUri`, `dbVersion`, `scannerUri`, `scannerVersion`, `origin`, `collector`). Certifiers continuously enrich; VEX overlay lets analysts override; `NoVuln` singleton attests clean scans. Lesson: auditors want *questions answered* ("is this artifact affected, via which path, what do I update?") with who/when/how on every claim. (https://github.com/guacsec/guac-docs)

## 7. VSA: the consumer contract

SLSA v1.2 verification summary (https://slsa.dev/spec/v1.2/verification_summary, read 2026-10-03): predicateType `https://slsa.dev/verification_summary/v1`; `verifier{id,version}`, `timeVerified`, `resourceUri`, `policy{uri,digest}`, `inputAttestations`, `verificationResult` PASSED/FAILED, `verifiedLevels`, `dependencyLevels`, `slsaVersion`. Seven mandatory consumer steps: (1) envelope signature vs preconfigured roots; (2) subject matches artifact digest; (3) predicateType check; (4) `verifier` matches the signing key's identity; (5) `resourceUri` matches expected; (6) `verificationResult` = PASSED; (7) `verifiedLevels` contains expected value. "Consumers MUST accept only specific (signer, verifier) pairs." "IMPORTANT: A VSA does not protect against compromise of the verifier."

In the wild: Konflux/Conforma consumers verify the VSA with `cosign verify-attestation --key cosign-release.pub --type https://slsa.dev/verification_summary/v1` without repeating 104 policy checks (arewm/slsa-konflux-example); PULSEmech documents the consumer procedure with a BLOCK taxonomy and the principle **"VSA verificationResult = PASSED ≠ automatic ALLOW"** (slsa-framework/slsa#1629); bytemare/slsa "Policy as Executable Code" points the policy URI at the verification script itself with its SHA-256 (no implementation gap); carabiner-dev AMPEL pulls VSAs from git commit notes and verifies against policy.

## 8. Auditor/policy UX and admission enforcement

- **Kyverno verifyImages** (https://kyverno.io/docs/policy-types/cluster-policy/verify-images/): `imageReferences` (static only), `required` (default true), `mutateDigest` (default true — tags rewritten to digests, "prevents spoofing attacks"), `verifyDigest` (default true), `attestors` (count = how many must verify), `attestations` (nested signature verification + `conditions` over arbitrary attestation JSON). Operational caveat: 60-minute TTL cache hides signature changes for an hour. Real CEL policy: kyverno/policies `other/verify-image-ivpol/verify-image-ivpol.yaml` — pins a notary attestor's cert + glob `ghcr.io/kyverno/test-verify-image*`.
- **policy-controller** (sigstore/docs `content/en/policy-controller/overview.md`): admission is AND across all matching `ClusterImagePolicy`, OR across authorities within one; tags resolved to digests at admission; `attestations[].policy` in cue or rego — **if `policy` is omitted, only the existence of the attestation is verified** (documented weak default to never replicate); `no-match-policy` defaults to deny.
- **Real policies pin the triple:** signer identity + predicate type + predicate *content* — Tekton example asserts `predicateType: https://grype.anchore.io/scan` with zero CVEs impactScore > 8.0 (kyverno.io/policies); trivy tutorial asserts vuln-scan freshness ≤ 1h (`time_since('', '{{ metadata.scanFinishedOn }}', '')`).
- **Certificate identity matching:** cosign keyless mode requires `--certificate-identity(-regexp)` and `--certificate-oidc-issuer(-regexp)` (fail-closed by construction). Mismatch error names expected-vs-actual: `none of the expected identities matched what was in the certificate, got subjects [%s] with issuer %s` (pkg/cosign/verify.go). Footguns: the identity carries the ref, so exact-match breaks when `@refs/heads/main` becomes `@refs/tags/v1` — use the regexp form; GitHub Actions certs have an empty subject and a URI SAN, so `subjectEmail`-only policy systems cannot express keyless identity at all; "`--certificate-identity` is the part that makes this mean anything… If you leave it out, cosign refuses rather than checking less."
- **Good failure-message patterns:** expected-vs-actual; aggregate per-authority reasons (`no matching signatures: <each per-signature error joined>`); symptom → remediation mapping ("if `cosign verify` says there is no signature, you are on an older tag"); troubleshooting with fix instructions (`failed to verify timestamps: threshold not met…` → upgrade cosign / `--use-signed-timestamps`). Success prints the itemized check list: "The following checks were performed on each of these signatures:". Never a bare "verification failed".
- **Outage posture:** community rollback playbook — during a Fulcio/Rekor outage, previously-deployed digests keep working ("Tagged releases already have valid Rekor entries — admission continues to work for previously-deployed digests"); only new issuances pause. (secondary)

## 9. Four 2026 Sigstore CVEs as negative design rules

1. **CVE-2026-24122 / GHSA-wfqv-66vq-46rm** (~2026-02-20; cosign ≤3.0.4, patched 3.0.5; CVSS 3.7). Chain verified at the leaf's notBefore; leaf expiry checked against the timestamp — an *issuing* CA expired before the timestamp was still accepted. → Check issuing-CA expiry at the *timestamp's* time.
2. **CVE-2026-22703 / GHSA-whqx-f9j3-ch6m** (~2026-01-19; cosign ≤2.6.1/3.0.3, patched 2.6.2/3.0.4; CVSS 5.5). New-bundle/`--trusted-root` path accepted an embedded Rekor entry that did not reference the artifact's digest, signature, or public key. → Bind the log entry to artifact + signature + key; never accept "a valid entry" alone.
3. **CVE-2026-39395 / GHSA-w6c6-c85g-mmv6** (2026-06-09; cosign 3.0.0–3.0.5, fixed 3.0.6). `verify-blob-attestation` reported false "Verified OK" for malformed payloads / mismatched predicate types when `--check-claims=true` was not set. → Predicate/content checks always on, never opt-in.
4. **CVE-2026-44310** (2026-05-15; gitsign ≤0.15.0). `gitsign --verify` panicked on empty-certificate PKCS7 and exited 0 — exit-code-only callers read failure as success. → Typed exit codes emitted only on the verified path; a crash must never produce a success signal.

## 10. Design rules for our offline verifier

1. Narrow inputs, zero network: canonical envelope bytes, inline bundle, compiled-in/SHA-256-pinned trust root, artifact bytes, expected identity/issuer/policy. No TUF client in the verifier.
2. Ordered, typed failure taxonomy (parse → crypto → unsupported → consistency/binding), typed exit codes, machine+human output on every run.
3. Same-bytes discipline end to end; `keyid` is an unauthenticated hint only.
4. Checkpoint signature first (log key by C2SP checkpoint key ID), root hash/tree size parsed only from the verified checkpoint, then Merkle inclusion path; pin the root hash.
5. Bind the log entry to artifact digest + signature + key (entry's canonicalized body).
6. Bind each RFC 3161 token to its own authority's chain and `validFor`; check issuing-CA expiry at timestamp time; require ≥1 verified observer timestamp for short-lived certs.
7. Name the time source, observed time, and validity window; fail closed with no trusted time.
8. Expiry and thresholds are first-class failures; stale roots fail closed with the refresh instruction — never silently fall back.
9. Auditor pins signer identity + predicate type + predicate content; default deny; existence-only verification labeled, never defaulted.
10. Every check bound to the digest; print the digest verified; refuse tag-only references in policy contexts.
11. Decision packets carry GUAC-style metadata (collector, origin, timestamp); per-check transcript on success, expected-vs-actual + remedy on failure.
12. Ship the five-negative + one-known-good battery with the verifier; checksum files exclude themselves.

## 11. License table

All verified 2026-10-03 from LICENSE files / repo badges. No copyleft in the reviewed surface.

| Codebase | License | Trap / note |
|---|---|---|
| sigstore-go, cosign, rekor-tiles, protobuf-specs, go-tuf, sigstore-python, sigstore-rust | Apache-2.0 | none (sigstore-python LICENSE read verbatim) |
| in-toto/witness, in-toto/in-toto, in-toto/in-toto-golang | Apache-2.0 | witness moved testifysec → in-toto org |
| slsa-framework/slsa-verifier | Apache-2.0 | **unmaintained** — README banner; `gh attestation verify` recommended |
| guacsec/guac | Apache-2.0 | none |
| aiwithllm-ui/depguard | Apache-2.0 | alpha v0.1.0-alpha.1, npm-first — taxonomy only |
| sigstore/policy-controller, fulcio, rekor, root-signing | Apache-2.0 | none |
| kyverno/kyverno, kyverno/policies | Apache-2.0 | none |
| registrystack/registry-stack | Apache-2.0 | pattern from vetting doc; Rust code not in current workspace |
| sigstore/docs | MIT (template boilerplate) | content reuse fine |

Non-license cautions: vendored trust material needs upstream attribution; trust-root pinning is a trust-policy decision; DSSE PAE/keyid spec text in this pass was quoted via secondary notes — verify against secure-systems-lab/dsse `protocol.md` before further envelope work.

## 12. Build-order implications

The recommended order (see PROSPECTUS.md): in-toto Statement v1 re-enveloping → Sigstore-bundle distribution (DSSE + inline witness entry + optional RFC 3161 token) → **offline verifier, registystack pattern** (stdlib-only, the 9-step pipeline, five negatives + known-good positive, zero network by construction) → Rekor-pattern witness (checkpoint-first verification) → VSA decision packets (steal the seven-step consumer procedure; PASSED ≠ ALLOW) → policy layer (triple pinning, digest-first, no-match deny, fail-closed expiry/threshold, documented operational controls).

Recommended auditor's journey: **Receive** (bundle + pinned trust root; freshness/expiry first) → **Verify** (signature, chain, identity, observed time with named source, inclusion proof; `Verification for <digest> —` + itemized checks) → **Policy-check** (identity, predicate type, predicate content, digest binding) → **Verdict** (signed VSA-shaped packet: per-check pass/fail, expected-vs-actual + remedies, all pinned inputs recorded; itself witness-appendable).
