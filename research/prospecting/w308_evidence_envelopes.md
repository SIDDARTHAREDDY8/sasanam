# Evidence Envelopes: DSSE, Sigstore Bundles, and in-toto Statements as the Wire Format for Agent-Governance Evidence

**Date:** 2026-10-03 · **Base:** `57068df1` · **Remote verified reachable at start.**
**Theme:** the exact, implementable mechanics of packaging Sasanam's offline evidence bundle so third-party verifiers (cosign, `gh attestation verify`, policy engines) can consume it *without our engine* — the wire-format companion to wave-307's runtime-attestation verdicts (which set the direction: SLSA-shaped evidence predicates → swtpm verifier loop → Rekor-pattern witnessing → eBPF facts → RCAR admission; see `research/prospecting/w307_runtime_attestation.md`).
**Method:** primary sources only (spec texts, protocol documents, implementer docs). Every factual claim cited (URL + access date 2026-10-03).

---

## 1. in-toto Statement v1 — the claim envelope

The [in-toto Attestation Framework's Statement layer](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) is the middle layer of an attestation: it binds a claim to a subject and unambiguously identifies the predicate type. The schema is four fields:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "<artifact-id>", "digest": { "sha256": "<hex>" } }],
  "predicateType": "<URI>",
  "predicate": { /* type-specific claim */ }
}
```

Semantics that matter for us (from the spec text):

- **`subject` entries MUST have `digest` set; subjects are assumed immutable** — "the artifacts identified by the subject SHOULD NOT change." Our evidence bundle's content digest is already its identity; this is the same idea, standardized.
- **Subjects are matched purely by digest, regardless of content type.** The spec even flags this as a deliberate, called-out property (with a pointer to a discussion issue). Digest-identity end to end — no filename trust.
- **`predicateType` is a URI identifying the claim type; `predicate` is optional** (unset == set-but-empty). The `predicateType` namespace is ours to mint.
- **Custom predicate types are the sanctioned extension mechanism, not a workaround.** The clearest statement of this comes from a project migrating a private record format to in-toto: "This is explicitly allowed and intended by the in-toto spec — custom `predicateType` URIs are the standard extension mechanism" ([wasmagent AEPRecord migration proposal](https://github.com/wasmagent/wasmagent-js/issues/27)). Their rationale is our thesis verbatim: "Every consumer that wants to verify an AEP record must understand wasmagent-specific code. No third-party tool (`slsa-verifier`, cosign CLI, any generic attestation viewer) can verify it out of the box… Any verifier that understands DSSE+Ed25519 can check an AEP record signature without wasmagent-specific code."
- **Upstream publishes the Statement layer as protobuf + prose, not JSON Schema** — one implementer notes they had to write their own statement schema for validation ("The upstream repository publishes the Statement layer as protobuf and prose, not as a JSON Schema"), and that real-world bundles carry both Statement v1 and legacy v0.1 (often wrapping SLSA Provenance v0.2), so a verifier must handle both explicitly ([noru-tech in-toto integration notes](https://github.com/noru-tech/agent-change-control/blob/HEAD/docs/design/in-toto-integration.md); [k2gl/in-toto-attestation](https://github.com/k2gl/in-toto-attestation)).

Precedents of evidence-shaped projects adopting exactly this (all 2026):

- **CHP-0021** (capability-host evidence bundles): "A signed CHP bundle → an in-toto Statement wrapped in a DSSE envelope, signed by the same host ed25519 key over the DSSE PAE… the whole CHP bundle is the predicate, so the attestation round-trips back to a bundle a CHP verifier checks natively… This lets CHP evidence flow into existing tooling (cosign/Rekor/GUAC) without CHP conceding its richer model." ([spec](https://github.com/capabilityhostprotocol/chp-core/blob/HEAD/spec/proposals/0021-intoto-dsse.md)) — "without conceding its richer model" is the key phrase: the standard envelope does not flatten our claims.
- **NLFR** (agent flight recorder): exports proof packets as in-toto statements where "each `digest.sha256` is the value NLFR recorded **when it captured the artifact** — it is **not** recomputed at export time" ([export doc](https://github.com/heyitsalec/nativelink-agent-flight-recorder/blob/HEAD/docs/wiki/how-to/export-in-toto-attestation.md)). Capture-time digests, not export-time recomputation — matches our hash-chained journal semantics exactly.
- **DepGuard attestation-v1**: DSSE + canonical-JSON in-toto Statement + Ed25519, with a **typed verifier failure taxonomy** (`MALFORMED_DSSE`, `INVALID_SIGNATURE`, `UNSUPPORTED_PAYLOAD_TYPE`, `INVALID_STATEMENT`, `UNSUPPORTED_PREDICATE`, `SCHEMA_VALIDATION_FAILED`, …) ([protocol doc](https://github.com/aiwithllm-ui/depguard/blob/HEAD/docs/protocol/attestation-v1.md)). A ready-made model for our standalone verifier's error codes.
- **Vasari**: per-node-type custom predicate URIs (`https://vasari.sh/Intent/v0.1`, `/Plan/v0.1`, …), each node signed, Rekor giving "tamper-evidence for free" ([why-not-just-in-toto](https://github.com/briceicle/vasari/blob/HEAD/docs/why-not-just-in-toto.md)).
- **Pedigree**: AI-authorship predicate (`dev.pedigree/ai-authorship/v1`) with subject = git commit SHA — the closest existing analog to "which agent did what, attested" ([predicate spec](https://github.com/om13rajpal/pedigree/blob/HEAD/docs/predicate-spec.md)).

**Sasanam mapping:** our offline evidence bundle becomes the `predicate` under a `https://sasanam.dev/attestation/<claim>/v1`-style URI; `subject[0].digest.sha256` is the bundle's content digest (capture-time, not recomputed at export); `_type` is the fixed in-toto URI. Standard verifiers then check envelope + signature without knowing our schema; our verifier additionally checks the predicate.

## 2. DSSE v1.0.2 — the signing protocol

The [DSSE protocol spec (v1.0.2, May 10 2024)](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) defines:

```
SIGNATURE = Sign(PAE(UTF8(PAYLOAD_TYPE), SERIALIZED_BODY))
PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
```

where `SP` is ASCII space and `LEN` is the ASCII-decimal byte length with no leading zeros. What this buys, precisely:

- **Type-confusion and truncation attacks are eliminated by construction.** The payload type and both lengths are inside the signed bytes; changing the declared type or truncating the payload breaks the signature. (Explainer with the same construction: [treeship DSSE writeup](https://github.com/zerkerlabs/treeship/blob/HEAD/docs/content/blog/dsse-dead-simple-signing-explained.mdx).)
- **No canonicalization.** DSSE signs the raw serialized bytes — unlike legacy TUF/in-toto signature schemes that rely on canonical JSON. Smaller attack surface; no canonicalizer to get wrong.
- **`payloadType` SHOULD be application-specific** (`application/vnd.in-toto+json`), NOT generic `application/json` — "two different applications could use the same encoding (e.g. JSON) but interpret the payload differently." For us: `application/vnd.in-toto+json` for statements.
- **`keyid` is an unauthenticated hint. It MUST NOT be used for security decisions** — only to narrow which keys to try. (Generalizes to a design rule: unauthenticated selectors narrow the search; they never decide.)
- **Verifiers MUST accept both standard and URL-safe base64.** Interop detail our verifier must implement.
- **The critical verifier implementation rule:** "Implementations MUST ensure that the same SERIALIZED_BODY that is verified is the same sent to the application layer. In particular, implementations MUST NOT re-parse the envelope after verification to pull out the payload." Re-parsing after verification is a named vulnerability class. Our standalone verifier must thread the verified bytes, not re-decode.
- **Multi-signature is a (t, n) threshold over unique keys** — built into the protocol, no extra machinery. Directly useful for our countersignature direction (wave-175's countersigned receipts).
- **Algorithm agility:** `Sign()` "places no restriction on the signature algorithm" — Ed25519 (our existing key type) works as-is.

The [DSSE scope document](https://github.com/secure-systems-lab/dsse/blob/HEAD/governance/02-scope.md) adds: consumers must ignore unrecognized envelope fields (extensibility without breaking verification); JSON is the only recommended encoding today.

A Rust implementation of exactly an "evidence in DSSE" crate shows the verification order to mirror: reject zero signatures → reject payload-type mismatch → constant-time compare the envelope payload against the caller's freshly recomputed expected payload → match keyid → re-validate the signature over the recomputed PAE ([invoicekit `evidence-dsse`](https://github.com/muhdur/invoicekit/blob/HEAD/crates/evidence-dsse/README.md)). Note the discipline: **the caller supplies the freshly recomputed payload; the function does not derive it from the envelope** — the same-bytes rule, enforced by API design.

**License note:** the DSSE specification is under the [Community Specification License 1.0](https://github.com/secure-systems-lab/dsse/blob/HEAD/governance/00-contributor-license-agreement.md) (spec text; includes a patent commitment), with sample/source code under Apache-2.0 ([PR #79 discussion](https://github.com/secure-systems-lab/dsse/pull/79)). Implementing the PAE algorithm from the spec is unaffected; do not copy spec prose into our docs.

## 3. Sigstore Bundle v0.3 — the distribution format

The [Sigstore Bundle](https://github.com/mitchdenny/sigstore-dotnet/blob/HEAD/docs/design-overview.md) (`application/vnd.dev.sigstore.bundle.v0.3+json`, `.sigstore.json` files) is the canonical format for distributing *everything needed to verify*: defined via [protobuf-specs](https://github.com/sigstore/protobuf-specs), serialized as JSON. Contents:

- `VerificationMaterial`: either a public key or an X.509 certificate chain, **plus** `tlog_entries` (transparency log entries with inclusion proofs) and `timestamp_verification_data` (RFC 3161 timestamps). The proto shape, quoted from the spec discussion:
  ```proto
  message VerificationMaterial {
      oneof content {
        PublicKeyIdentifier public_key = 1;
        X509CertificateChain x509_certificate_chain = 2;
      }
      repeated dev.sigstore.rekor.v1.TransparencyLogEntry tlog_entries = 3;
      TimestampVerificationData timestamp_verification_data = 4;
  }
  ```
  ([sigstore/model-transparency#603](https://github.com/sigstore/model-transparency/issues/603), quoting `protos/sigstore_bundle.proto`)
- The signature itself: a DSSE `Envelope` (for in-toto attestations) or a `MessageSignature` (digest + raw signature bytes).
- `TrustedRoot` (the complete set of trusted CAs, logs, TSAs) is distributed separately via TUF.

The client-spec verification pipeline, in order ([sigstore-dotnet README](https://github.com/ozimakov/sigstore-dotnet/blob/HEAD/README.md), following the [Sigstore client spec](https://github.com/sigstore/sigstore/blob/main/docs/client-spec.md)):

1. Parse bundle JSON; reject unknown media types.
2. Bootstrap trust via TUF (`trusted_root.json`).
3. Build/verify the Fulcio certificate chain; validate SCTs.
4. Enforce identity policy (issuer + subject).
5. Validate certificate validity against **Rekor integrated time and/or RFC 3161 timestamps** — the "hybrid model": signatures are validated at the *established signing time*, not wall-clock. (This is how short-lived Fulcio certs verify years later.)
6. Verify the Rekor inclusion proof (Merkle path + signed checkpoint); cross-check `canonicalizedBody`.
7. Verify the artifact signature with the leaf key.

Tooling that consumes this format today: `cosign verify-blob-attestation --bundle <file> --new-bundle-format` ([moat publisher spec](https://github.com/openscribbler/moat/blob/HEAD/website/src/content/docs/spec/publisher-action.md) mandates `--new-bundle-format` for v0.3 bundles); `gh attestation verify <artifact> --repo <owner>/<repo>` against GitHub's stored bundles ([ghx README](https://github.com/rexovasgroup/ghx/blob/HEAD/README.md)); `slsa-verifier verify-artifact` ([SLSA+Sigstore skill](https://github.com/lysxky/codex-skills-portable/blob/HEAD/./skills/verifying-build-provenance-with-slsa-sigstore/SKILL.md)).

**The offline-verifier pattern to steal** comes from a project's dependency-vetting doc ([registystack](https://github.com/registrystack/registry-stack/blob/HEAD/release/notes/dependency-vetting-sigstore-verify.md)): pin the verifier exactly; construct `TrustedRoot` and `Bundle` **from local bytes** and call the synchronous offline verifier — *no trust-root or bundle download, no network in the verify path*; negative tests reject altered artifact bytes, wrong certificate identity, wrong trusted root, invalid signing time, and corrupted Rekor inclusion proofs. This is our standalone evidence-verifier architecture, pre-validated by an independent project: evidence bearer-shaped, verification offline-capable.

**What this means for us:** emitting `.sigstore.json`-shaped bundles (VerificationMaterial + DSSE envelope) makes our evidence bundle verifiable by `cosign`/`gh` with zero Sasanam code. The interop test for the envelope work is literally `cosign verify-blob-attestation --new-bundle-format`. The public-key (non-keyless) VerificationMaterial variant needs no Sigstore PKI dependency.

## 4. Consumption: VSA, policy-controller, Kyverno — evidence at the admission point

**Verification Summary Attestation (VSA).** SLSA v1.2's recommended attestation formats are Provenance and the **Verification Summary** ([spec index](https://slsa.dev/spec/v1.2/)): a signed statement by a *verifier* that "I checked artifact X against policy P at time T with result R." This is "evidence as a token" one level up — instead of shipping all evidence, ship the signed verdict. Our signed decision packets (wave-176) are proto-VSAs; re-expressing them in the VSA shape makes them consumable by third-party policy tooling.

**Admission enforcement.** Sigstore's [policy-controller](https://github.com/sigstore/policy-controller/blob/HEAD/README.md) is a Kubernetes admission controller that validates signatures *and attestations* on container images, resolving tags to digests so "the image being run is not different from when it was admitted," with per-namespace enforcement and `attestations` checked against cue/rego policies ([docs](https://docs.sigstore.dev/policy-controller/overview/)). Kyverno's `verifyImages` is the parallel admit path. Operational lessons from a production writeup ([opensourceom](https://github.com/opensourceom/website/blob/HEAD/src/content/blog/cosign-keyless-sigstore-k8s.md)):

- **Resolve to digest at admission** (`mutateDigest: true`) — a tag verified on create can move before run.
- **Fail closed deliberately:** `validationFailureAction: Enforce` in prod, `Audit` in a bake-in namespace.
- **NTP is a supply-chain control** — nodes more than a few minutes off fail verification (certificate validity windows).
- **Match every pod-controller kind** — enforcing on `Pod` while Helm creates `CronJob`/`Job` is a bypass.
- **Never duplicate signature logic in a homemade webhook** — "duplicating signature logic in a homemade webhook is how you drift from Cosign's verifier." Consume the standard verifier; don't reimplement it. (Directly relevant to our standalone verifier: it should implement the *spec*, tested against the same vectors as the standard tooling, not a parallel invention.)

The Sasanam analog of a ClusterImagePolicy: an *agent-run admission policy* — "admit this agent's outputs / grant this tool capability only if its evidence bundle verifies against policy P." The RCAR-shaped admission handshake (wave-307 #3) is the mechanism; the VSA-shaped verdict is the token.

## 5. SLSA v1.2 Source Track — the vocabulary for "who authored this change"

SLSA v1.2 ([spec](https://slsa.dev/spec/v1.2/)) splits provenance into two tracks: **Build provenance** (existing — how an artifact was built) and **Source provenance** (new — "tracks the creation of source code revisions and the change management processes that were in place during their creation," per the [provenance overview](https://slsa.dev/spec/v1.2/provenance)). The Source Track covers producing source, verifying source, and assessing source-control systems, with higher levels expecting "reliable history, technical controls, and provenance evidence" ([grox research note](https://github.com/vessaxor-spec/grox/blob/HEAD/docs/research/MISSION_SOURCE_PROVENANCE.md)).

Why this matters for agent governance: the industry now has a *standard vocabulary* for "who/what authored this revision and under what change-management controls." Our approval queue, human-approval evidence, review inbox, and bounded journal are source-provenance claims in SLSA's encoding. The grox note's warning is load-bearing: "bind evidence to the resulting source revision and preserve the repository's own change-management controls rather than forcing build-provenance semantics onto Commander authorization." I.e.: use source provenance for *authorization/authorship* claims, build provenance for *build* claims — don't contort one into the other. Our custom predicateTypes should follow the same split.

## 6. Market proof: evidence-bundling is becoming table stakes

- **PyPI / PEP 740:** PyPI accepts and redistributes Sigstore-based attestations for uploaded distributions; each attestation "carries the same verification material as a Sigstore bundle" ([sigstore-go PyPI doc](https://github.com/sigstore/sigstore-go/blob/HEAD/docs/pypi-attestation-verification.md)). Package registries are absorbing attestation distribution as infrastructure.
- **GitHub artifact attestations:** attestations stored as repository-level resources, verifiable via `gh attestation verify`; the new bundle format is the wire shape ([tram
...[truncated 3960 chars]