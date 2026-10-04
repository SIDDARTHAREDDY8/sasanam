# Trusted evidence — what comes after the VSA: prospectus

**Wave-317 lane 4 · research only · $0 spend · public sources only · 2026-10-04**
**Base:** `fe18ad50` (wave-316 merge). Mission: what comes next for the evidence story now that the
envelope order (in-toto → Sigstore bundle → offline verifier → Rekor-pattern witness → VSA decision
packets) is complete. Four questions: (1) consistency proofs + gossip, (2) threshold/quorum signing,
(3) freshness + revocation, (4) what design partners / auditors actually ask for.

Method: primary sources (RFCs, specs, advisories, first-party docs), cited claims, STEAL/ADAPT/WATCH/SKIP
verdicts per source, license checks (Apache-2.0/MIT preferred; GPL/AGPL flagged).

## The 14 primary sources and verdicts

### 1. Consistency proofs and gossip

1. **RFC 6962 (obsoleted by RFC 9162, Merkle constructions materially identical) — Certificate
   Transparency.** Defines the two proofs the wave-314 witness lane does not yet have:
   - *Merkle consistency proof*: given tree sizes m < n, proves the first m leaves are identical in both
     trees — rules out truncation, insertion, reordering, modification with O(log n) hashes.
   - *Gossip*: "All clients should gossip with each other, exchanging STHs at least; this is all that is
     required to ensure that they all have a consistent view," and conflicting Signed Tree Heads for the
     same log are "cryptographic proof of that log's misbehavior."
   → **STEAL (theory)**. This is the formal answer to the wave-314 "no consistency-proof check (Rekor
   parity)" residual: Rekor parity is the *current* design stance, and RFC 6962 is the *upgrade path*
   when the residual becomes a finding. (datatracker.ietf.org/doc/html/rfc6962)

2. **C2SP signed-note + tlog-cosignature (spec, free).** Vendor-neutral checkpoint format:
   cleartext note + `— <key name> base64(keyID || signature)` lines; signature type `0x04` =
   "Timestamped Ed25519 checkpoint cosignatures"; verifiers must ignore unknown keys and reject notes
   with no valid known-key signature. The checkpoint the wave-314 `witness_rekor` module emits should
   eventually speak this shape instead of a bespoke one.
   → **STEAL (pattern)**. (github.com/C2SP/C2SP/blob/main/signed-note.md, read 2026-10-04)

3. **transparency-dev/merkle `VerifyConsistency` (Crosby–Wallach history trees, Apache-2.0).**
   `VerifyConsistency(oldSize, newSize, oldRoot, newRoot, proof)` — the exact primitive a
   `gov/witness_consistency.py` would port. Plus producer-side `ConsistencyProof(oldSize)`.
   → **ADAPT** — Go code, port the pattern to stdlib Python; the wire semantics are the RFC's.
   (github.com/aflock-ai/rookery/issues/193 documents the gap it closes: retroactive-insertion and
   tree-withholding attacks)

4. **Rekor v2 / Tessera witness cosigning (Apache-2.0).** Rekor v2 supports checkpoint co-signing by
   witnesses; the C2SP witness protocol is the shared language. Caveat from the TesseraCT exercise:
   witness cosigning is **fail-open** — the checkpoint is still published when the witness is offline —
   and witnesses cosign *checkpoints for consistency*, not individual entries: "a compromised log
   operator can still issue fraudulent entries before detection."
   → **WATCH**. Keep Rekor parity for now; the fail-open caveat is a negative design rule if we ever
   add witnesses (our witness should fail closed where Tessera fails open).
   (github.com/flammafex/witness/blob/HEAD/docs/comparison.md; github.com/david-cermak/merkle-tree-lab,
   docs/exercises/06_witnesses.md)

### 2. Threshold / quorum signing

5. **FROST — RFC 9591 (IETF, June 2024), "Flexible Round-Optimized Schnorr Threshold Signatures."**
   t-of-n signing with a Distributed Key Generation phase (no trusted dealer): each party generates a
   random polynomial, exchanges shares, and the group public key is aggregated without any party ever
   knowing the group private key. Two signing rounds; output is a **standard Ed25519 signature,
   indistinguishable on the wire** — verifiers need no changes.
   → **STEAL (theory) / ADAPT (pattern)**. Directly answers "t-of-n instead of a single key": the
   evidence bundle's signature could require 2-of-3 operator keys with zero verifier changes.
   Honest costs: FROST **aborts without attributable evidence** on a faulty signer (the coordinator
   decides who cheated; Lin24 adds attribution at the cost of a third round), and it is **not
   post-quantum**. (datatracker.ietf.org/doc/rfc9591)

6. **Shamir's Secret Sharing (1979).** The foundation: degree-(t−1) polynomial, t shares recover the
   secret, t−1 shares reveal nothing. The limitation that matters for us: **the trusted dealer
   problem** — whoever generates the polynomial knows the secret, so threshold security is only as good
   as the setup ceremony.
   → **STEAL (theory)**. (Communications of the ACM, 1979)

7. **HashiCorp Vault Shamir unseal (MPL-2.0 — pattern only, no vendoring).** The production t-of-n
   ops model: `vault operator init -key-shares=5 -key-threshold=3`; no single person can unseal;
   shards distributed across people/locations, PGP-encrypted at rest, rotated with `vault operator
   rekey`; production replaces manual unseal with cloud-KMS auto-unseal (recovery keys for emergencies
   only). This is the ceremony shape for the evidence bundle's signing-key custody.
   → **STEAL (pattern)**. (developer.hashicorp.com/vault/docs/concepts/seal; runbook evidence from
   github.com/seszele64/bike-data-flow/blob/HEAD/docs/vault-unseal-management.md)

### 3. Freshness and revocation

8. **TUF specification (theupdateframework/specification, Apache-2.0).** The freshness machinery:
   - *Timestamp role*: frequently re-signed, short expiry — "If the delivery agent can't obtain fresh
     timestamp metadata … it knows its trust configuration is potentially stale" (freeze-attack
     detection).
   - *Snapshot role*: pins every targets-metadata version atomically (mix-and-match prevention).
   - *Root rotation*: strictly versioned `root.json` chain, each signed by the old root's threshold —
     never an in-place key swap; expiry is a last-resort backstop, "freshness is timestamp.json's job."
   → **STEAL (pattern)**. The pinned-trust-root equivalent of our problem: the offline verifier's trust
   root should be a versioned chain with a freshness signal, not a static file.
   (github.com/theupdateframework/specification/blob/master/tuf-spec.md)

9. **CVE-2026-24122 / GHSA-wfqv-66vq-46rm (cosign ≤3.0.4, patched 3.0.5, CVSS 3.7).** Cosign verified the
   certificate chain at the leaf's notBefore and checked leaf expiry against the timestamp — but an
   *issuing* CA expired before the timestamp was still accepted.
   → **Negative design rule** (extends the wave-310 note): check issuing-CA expiry at the *timestamp's*
   time, not just the leaf's. Any freshness window we add to the witness must apply chain-wide.
   (github.com/sigstore/cosign/security/advisories/GHSA-wfqv-66vq-46rm)

10. **CVE-2026-22703 / GHSA-whqx-f9j3-ch6m (cosign ≤2.6.1/3.0.3, patched 2.6.2/3.0.4, CVSS 5.5).**
    Cosign accepted an embedded Rekor entry that did not reference the artifact's digest, signature, or
    public key — "a valid entry" alone was enough.
    → **Negative design rule** (extends the wave-310 note): bind every log receipt to artifact digest +
    signature + key; never accept a valid receipt alone. Directly constrains any consistency-proof or
    gossip design: proofs must be bound to the same bundle digest the VSA names.
    (app.opencve.io/cve/?vendor=sigstore&product=cosign)

11. **Vendored trusted-root practice (sigstore/root-signing consumers).** DepGuard vendors a Sigstore
    Public Good trusted root as bytes with the commit hash **and** SHA-256 recorded, and treats any root
    update as "deliberately reviewed … together" with the verifier pin; confidential-inference treats a
    new root as "a trust-policy change — review … update its SHA-256 in the policy … do not change an old
    signed release or its trust inputs."
    → **ADAPT**. Our offline verifier should adopt the discipline now: trust root pinned by
    (content-hash, source-commit, review-date); rotation is a policy ceremony, never silent.
    (github.com/aiwithllm-ui/depguard/blob/HEAD/docs/network-mvp.md;
    github.com/confidential-dot-ai/confidential-inference/blob/HEAD/releases/trust/README.md)

### 4. What design partners / auditors actually ask for

12. **SOC 2 Trust Services Criteria — CC7 (System Operations) / CC8 (Change Management).**
    For AI systems, auditors sample CC7.2 (anomaly monitoring: alert rules, alert history, who responded),
    CC7.3/CC7.4 (incidents evaluated through the response process), and CC8.1 (authorization, testing,
    approval of changes — for AI this **includes model versions, system prompts, retrieval settings**:
    "A system prompt or model version change alters behaviour as much as a code change. If it isn't in
    the change log, CC8.1 has a gap."). Type II needs history across the whole period — retention matters
    as much as coverage.
    → **STEAL (requirements)**. Our evidence bundle already carries the decision; CC8.1 says it must
    also carry *what changed the decision-maker* (model/prompt/config versions). Request-level traces
    with version metadata answer all three controls.
    (perimattic.com/products/perimattic-ai-suite/ai-observability-for-soc2/, reviewed 2026-10-01)

13. **NIST SP 800-53 Rev 5 — AU family (FedRAMP baseline).** AU-2 (event logging), AU-3 (content of
    audit records: who/what/when/where/result), AU-6 (audit review, incl. AU-6(1) automated integration
    at FedRAMP High), AU-9 (protection of audit information — "append-only, tamper-evident"), AU-12
    (audit generation). CJIS adds 1-year retention + weekly review on AU-6.
    → **STEAL (requirements)**. AU-9 is exactly the hash-chained ledger we built; AU-3 is the field
    checklist for every evidence record; AU-6(1) is the argument for shipping the offline verifier as
    the auditor's review tool. FedRAMP High makes AU-6(1) mandatory — the verifier is not a nice-to-have
    for that market.
    (csrc.nist.gov/pubs/sp/800/53/r5/upd1/final; control mapping evidence from
    github.com/webbrain-one/nist-800-53-rev-5-to-aws-mapping)

14. **RFC 9943 — SCITT architecture (IETF).** Transparent registries and independently verifiable claims,
    with the explicit stance that it "does not stop an authenticated issuer from making a false claim" —
    the same honesty boundary our project draws.
    → **WATCH / ALIGN**. A SCITT-style transparent claim registry is a plausible future distribution
    surface for evidence bundles (the ORAS-spike direction), but it is adjacent, not next.
    (www.rfc-editor.org/rfc/rfc9943 — via the wave-310 prior-art survey)

**Skipped:** Chainpoint (defunct ~2020–2022, AGPL-3.0 license trap — per the witness comparison doc);
LLM-judge freshness oracles (the wave-315 prospectus already ruled judges out of the enforcement path).

## No GPL/AGPL traps

Nothing vendored. RFCs and C2SP specs are freely usable; TUF/transparency-dev are Apache-2.0 (pattern
use only); Vault is MPL-2.0 (pattern only). Chainpoint's AGPL-3.0 was the one trap and it was skipped.

## Direction brief for future build lanes

Estimated shape per item; none are product code — this is the build order a parent can dispatch.

1. **Consistency proofs + gossip** → `gov/witness_consistency.py` (est. ~400 lines stdlib).
   - Port `VerifyConsistency(oldSize, newSize, oldRoot, newRoot, proof)` from the transparency-dev
     pattern; the witness's checkpoint format moves to the C2SP signed-note shape with `0x04`
     timestamped cosignatures, so third-party witnesses can cosign without bespoke code.
   - Receipts bind consistency proofs to the same bundle digest the VSA names (CVE-2026-22703 rule).
   - Gossip: witnesses exchange STHs; conflicting STHs for one log = cryptographic proof of log
     misbehavior (RFC 6962 §gossip). Our witness should **fail closed** when its witness set is
     unreachable — the Tessera fail-open caveat is the documented anti-pattern.
   - Closes the wave-314 "no consistency-proof check (Rekor parity)" residual. Acceptance: break-first
     battery showing a forked history (two STHs, same size, different roots) fails verification.

2. **Threshold signing** → key-custody ceremony first, group signing second.
   - Step A (ops, no crypto): Shamir t-of-n custody for the evidence bundle's signing key, Vault-style
     (5 shares / threshold 3, PGP-encrypted shards, `rekey` rotation ceremony, recovery keys for the
     cloud-KMS auto-unseal path). This is procedural + key-management code, not threshold crypto.
   - Step B (crypto, later): FROST-pattern 2-of-3 group signing producing standard Ed25519 — zero
     verifier changes. Honest preconditions: an audited Ed25519-FROST implementation or a careful
     stdlib port; an abort-attribution policy (FROST aborts unattributed — decide whether Lin24's
     third round is worth it); a post-quantum migration note (FROST is not PQ).

3. **Freshness + revocation** → `gov/trust_root_refresh.py` (est. ~250 lines) + verifier policy.
   - Versioned trust-root chain (TUF root pattern: strictly N+1, signed by the old root's threshold);
     a freshness signal (TUF timestamp pattern: short-lived, frequently re-signed) the offline verifier
     checks; chain-expiry evaluated at the *timestamp's* time, chain-wide (CVE-2026-24122 rule).
   - Trust-root updates follow the vendored-root discipline: pinned by (content-hash, source-commit,
     review-date); rotation is a policy ceremony.
   - Acceptance: a verifier with a stale trust root refuses with a coded refusal naming the stale root,
     not a generic "invalid."

4. **Design-partner evidence fields** → extend the evidence bundle schema (additive).
   - AU-3 field checklist on every record (who/what/when/where/result); CC8.1 decision-maker versioning
     (model version, system-prompt hash, config snapshot) attached to every decision VSA; retention
     guidance (≥1 year, AU-6/CJIS) for the witness log.
   - This is what turns "sell evidence, not the engine" into a procurement answer: the bundle maps
     1:1 onto the auditor's sampling checklist. No product behavior change — schema + docs.
   - Note: the GTM one-pager and design-partner outreach stay deferred until REALWORLD_BAR is honestly
     met (standing order since 2026-09-29); building the *fields* now is not raising GTM.

## Suggested wave order (parent's call)

- Wave N+1: item 4 (additive schema, no crypto risk) + item 3 (bounded, testable).
- Wave N+2: item 1 (consistency proofs; needs the checkpoint format change first).
- Wave N+3: item 2 step A (ceremony); step B only after an audited implementation exists.
