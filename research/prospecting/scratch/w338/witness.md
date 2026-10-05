# Rekor v2 witness-policy onboarding deep-dive (R18 follow-up)

**Wave:** 338, lane 6 (research scout B) · **Date:** 2026-10-05 · **Spend:** $0
**Method:** primary sources only (spec text, repo docs, first-party sources); access date 2026-10-05 on every citation.
**Base:** R18 pass (2026-10-05) established: Rekor v2 synchronous witnessing is specified (log blocks until witnesses cosign each checkpoint); Sigstore's public witness network has NOT launched as a client-verifiable network; witnesses use Ed25519/ECDSA; checkpoints must be stable for consensus; witnesses cosign checkpoints (log consistency), not individual bundles.

## Tree check — what Sasanam already has

Grep over `/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main` (2026-10-05):

- `gov/witness_policy.py` (677 lines) — **the signed witness-policy artifact already exists**: TUF-style threshold-signed policy, entries = vkeys + operator identity + validity window, version monotonicity (N+1), policy_id continuity, `active_witnesses`, `verifier_inputs` for the quorum gate. This is the greenfield w321 identified, and a later lane built it.
- `gov/witness_consistency.py` (850 lines) — cosignature verification: C2SP `cosignature/v1` 76-byte lines (`keyID(4) || u64BE timestamp(8) || sig(64)`), `require_cosignatures` (≥k valid cosignatures from the policy-pinned set), freshness check, MUST-ignore-unknown-lines, fork detection.
- `gov/witness_log.py` (794 lines) — the transparency log: RFC 6962 Merkle tree, signed checkpoints, inclusion/consistency proofs, checkpoint-first contract.
- `gov/checkpoint_note.py` — C2SP tlog-checkpoint signed-note emission/parsing, vkey strings, keyID rules.
- `gov/rekor_v2_anchor.py`, `gov/rekor_v2_witness.py` — Rekor v2 anchor (hashedrekord only, TSA-separate, self-hosted-only) and the second-witness write path.
- `docs/REKOR_RUNBOOK.md` — anchor-key ceremony runbook.
- **NOT in the tree:** no `add-checkpoint` implementation (log→witness submission client or witness server), no synchronous block-and-collect orchestration, no witness daemon with persisted state. That is the remaining build surface.

## 1. Rekor v2 synchronous witnessing — what the spec says the client MUST/SHOULD do

### 1.1 The synchronous-witnessing contract (rekor-v2-spec.md)

- **§5.3 Witnessing:** "Rekor v2 can be configured to subscribe to a network of log witnesses. Upon creating a new checkpoint, it sends the checkpoint to witnesses for counter-signatures, **and blocks until it receives the co-signed checkpoint which it then returns to signing clients**." (https://github.com/sigstore/architecture-docs/blob/HEAD/rekor-v2-spec.md, accessed 2026-10-05)
- **Verifying clients SHOULD verify the co-signatures against the keys in their trust root for the witnesses.** — the only normative client obligation, at SHOULD level. (same URL)
- §5.3 rationale: "Synchronous witnessing like this ensures that consistency verification becomes an automatic client concern. The converse, asynchronous witnessing … meant that users could treat it as an afterthought." (same URL)
- **§4.4 Batching and Checkpoint Intervals:** checkpoints are updated infrequently enough that "stable checkpoint publishing is no longer needed because the infrequency with which the checkpoint is updated solves the instability issue for potential witnesses needing to reach a consensus on the consistency of a log." Individual submissions may wait **up to 10 seconds** for a response. (same URL)
- **§7.1 Signers:** client waits "on the order of 2–10 seconds" for the response (a `TransparencyLogEntry` containing the latest checkpoint + inclusion proof). (same URL)
- **§7.2 Believers** (offline verification steps): 1) verify the checkpoint signature against the server's public key and expected server name; 2) verify the inclusion proof per RFC 6962 2.1.1; 3) compare the leaf hash with the provided artifact; 4) **"optionally, verifies witness signatures if available."** (same URL) — note the softening from §5.3's SHOULD to §7.2's "optionally": the spec does not force witness verification on believers, only on the trust root's keys being present.

### 1.2 Where cosignatures live and how they are addressed

- **§6.3 Checkpoint Format:** checkpoint follows C2SP Transparency Log Checkpoints; "MAY additionally include witness signatures as specified in the Transparency Log Witness Protocol." (https://github.com/sigstore/architecture-docs/blob/HEAD/rekor-v2-spec.md, accessed 2026-10-05)
- **§7.4 Witnesses:** "Synchronous witnesses are responsible for verifying the consistency of a log. Their co-signatures of a checkpoint are returned to the log for distribution to signing clients to use in their verification material bundle." Split-view mitigation is the stated threat: "Using a diverse network of corroborating witnesses helps to mitigate split-view attacks." (same URL)

### 1.3 Client guidance (rekor-tiles CLIENTS.md — the operational doc the spec defers to)

- **Timeouts:** "Clients need to increase request timeouts when creating entries **to at least 20 seconds**. Rekor now blocks on returning a response until a checkpoint has been published whose tree size includes the newly uploaded entry index. Checkpoint intervals have been increased to reduce the frequency of checkpoint publishing." (https://github.com/sigstore/rekor-tiles/blob/HEAD/CLIENTS.md, accessed 2026-10-05)
- **Witnessing is planned-but-unlaunched in that doc's prose:** "we plan to support synchronous witnessing, where third-party witnesses independently verify the consistency of the log and Rekor provides co-signed checkpoints with each upload response" — and "**In the initial launch of Rekor v2, checkpoints will not be witnessed, while we wait for the launch of a public witness network.** Clients do not need to implement verification of witness signatures initially, but clients should increase request timeouts to account for the additional time to sign checkpoints, **which we estimate to be <10s**." (same URL) — this prose is stale relative to live state: w321 captured a live `log2025-1` production checkpoint carrying three synchronous cosignatures, so the witness network is *operationally* present while the docs still describe it as future.
- **Who chooses the witness set (planned design):** "The log will determine which set of witnesses is trusted and **the M-of-N witnesses to fetch signatures from, and this policy will be distributed by Sigstore's TUF root**." (same URL)
- **Timestamping note:** "Co-signed checkpoints will also be timestamped, so they can serve as an independent signed timestamp instead of an RFC 3161 timestamp." (same URL) — a Sigstore-side plan; we should NOT import this claim for our own witnesses (see §5 honesty boundaries).
- **Bundle hygiene:** root hash and tree size must be parsed from the *verified checkpoint*, never from duplicated copies inside the inclusion-proof envelope ("Do not use the unverified root hash and tree size"); `integrated_time` is always 0 and MUST be ignored. (same URL) — matches our `gov/witness_log.py` checkpoint-first contract.

### 1.4 The C2SP witness protocol (tlog-witness.md v1.0.0 editor's copy) — the wire mechanics

Full protocol: https://github.com/C2SP/C2SP/blob/HEAD/tlog-witness.md (accessed 2026-10-05). Relevant contract:

- **add-checkpoint:** `POST <submission prefix>/add-checkpoint`. Body = `old <size>` line + up to **63** base64 consistency-proof lines + empty line + checkpoint. Each line ends LF. (same URL)
- Witness **MUST** verify the checkpoint signature against its trusted log keys; **MUST ignore signatures from unknown keys**; 404 on unknown origin; **403** if no trusted-key signature is present **or** a name/ID-matching signature fails to verify. (same URL)
- **409 Conflict** when `old size` ≠ witness's latest cosigned size; response body is the witness's stored size (`text/x.tlog.size`) — a conditional-update primitive. A client that doesn't know the witness's size **MAY** send `old 0` to discover it. (same URL)
- **422** on: size-zero checkpoint with non-empty-tree root, unverifiable consistency proof, or same-size-different-root. (same URL)
- **On success the witness MUST update its record and MUST persist the new checkpoint before responding; check-and-persist MUST be atomic** — the spec documents the rollback race explicitly (two concurrent requests can roll the stored size backward). (same URL)
- The cosignature **MUST NOT omit the timestamp** (MUST NOT be zero); witnesses **SHOULD use ML-DSA-44 cosignatures**. (same URL) — spec-recommended; practice is still Ed25519 cosignature/v1 (OmniWitness returns `cosignature/v1`; live Rekor v2 checkpoints carry Ed25519 lines).
- The client **MUST ignore cosignatures from unknown keys**; may concatenate the response to the checkpoint and verify with its trusted witness keys. (same URL)
- Keep-alive: clients SHOULD use it, witnesses SHOULD support it. (same URL)
- **Monitor retrieval:** a witness SHOULD serve a recent checkpoint at `GET <monitoring prefix>/<origin hash>/checkpoint` (origin hash = SHA-256 of log origin, lowercase hex); 404 if never cosigned; MAY delay updates up to 1 hour. (same URL)
- **Key material protection:** "If exposing the machine holding the witness key material directly to the Internet is undesirable, operators MAY use a **bastion**." (same URL)
- **cosignature/v1 wire shape** (from the w321 live capture, matches our tree): one line per cosignature starting with `—` (U+2014), 76-byte blob = `keyID(4) || u64BE timestamp(8) || Ed25519 sig(64)`, signed over the domain-separated statement `cosignature/v1\ntime <ts>\n<origin>\n<size>\n<root hash>\n`.

### 1.5 The policy grammar (tlog-policy.md) — what a witness set looks like on paper

https://github.com/C2SP/C2SP/blob/HEAD/tlog-policy.md (accessed 2026-10-05):

- A policy = set of known logs + set of known witnesses + quorum rule. **Only the quorum is mandatory** (`quorum none` = no cosigning).
- `log <vkey> [<url>]`, `witness <name> <vkey> [<url>]`, `group <name> all|any|<k> <members...>`, exactly one `quorum <name>` line. Group refs must be defined on preceding lines (no cycles); each name contributes at most once.
- vkey = `<name>+<hex keyID>+base64(sigType || pubkey)`; **two vkeys wrapping the same key are duplicates even if names/IDs differ**; log vkey's key name MUST match the log's origin line.
- No URLs needed for offline verification; a witness URL, if present, SHOULD be the submission prefix.
- Implementations should support ≥32 logs / 32 witnesses / 32 groups.
- **Critical gap for onboarding: the C2SP policy file is unsigned, unversioned, and has no expiry.** Authentication comes entirely from the distribution channel. This is exactly why Sigstore planned "distributed by Sigstore's TUF root" (CLIENTS.md §Future: Witnessing) — and why our own `gov/witness_policy.py` wraps the grammar in a threshold-signed, versioned artifact.

## 2. Witness-set onboarding in practice — publication, rotation, updates

### 2.1 Where the witness key set is published (Sigstore's plan vs reality)

- **Plan (CLIENTS.md):** "The log will determine which set of witnesses is trusted and the M-of-N witnesses to fetch signatures from, **and this policy will be distributed by Sigstore's TUF root**." (https://github.com/sigstore/rekor-tiles/blob/HEAD/CLIENTS.md, accessed 2026-10-05)
- **Reality at HEAD (2026-10-05):** `TrustedRoot` in sigstore/protobuf-specs has **no witness-key field**. The message carries `certificate_authorities` and `timestamp_authorities`; `TransparencyLogInstance` carries `base_url`, `public_key`, `log_id`, `checkpoint_key_id`, `operator` — no witnesses, no M-of-N. (https://github.com/sigstore/protobuf-specs/blob/HEAD/protos/sigstore_trustroot.proto, accessed 2026-10-05). So the distribution mechanism is specified in prose but **not yet representable in the trust root schema** — w321's finding stands.
- **What the proto DOES mandate for rotation (the overlap-then-retire precedent):** "The embedded transparency logs, CT logs, CAs and TSAs **MUST include any previously used instance** — otherwise signatures made in the past cannot be verified. … Clients **MUST accept instances that overlaps in time** … To be able to manage planned rotations … **clients MUST accept lists of instances where the last instance have a 'valid_for' that belongs to the future**." (same proto URL) — i.e., rotation = add successor with a future-dated `valid_for`, keep overlapping windows, never drop the old instance until it expires. This is the concrete rule to copy for witness-key rotation.
- **How the TrustedRoot is populated is intentionally unspecified** ("can be a combination of many sources such as TUF repositories, files on disk etc."), so a private deployment may pin the witness set from its own signed policy artifact rather than waiting for a proto field. (same proto URL)

### 2.2 The deployed threshold-signed update ceremony (Sigstore root-signing)

The only *deployed* example of a threshold-signed trust-metadata update in this ecosystem is `sigstore/root-signing` (https://github.com/sigstore/root-signing/blob/HEAD/README.md, accessed 2026-10-05):

- **5 current keyholders** (Lance Ball, Joshua Lock, Bob Callaway, Marina Moore, Santiago Torres-Arias); "All changes to artifacts or metadata require cryptographic signatures from Sigstore keyholders" — changes to `trusted_root.json` and even to *repository configuration (current keyholders, signature thresholds)* happen via **signing events**: PRs where keyholders sign with **personal hardware keys**.
- Key rotation of the *metadata itself* is online-signed with KMS keys **at least every three days** ("online signature expiry"); every non-trivial change is tested first in the `root-signing-staging` repo, then published through `tuf-repo-cdn.sigstore.dev` after automated client tests.
- **Takeaway for witness-policy updates:** the shape is (1) threshold-signed policy artifact, (2) keyholder ceremony with hardware keys for set changes, (3) staging repo for rehearsal, (4) automated client-acceptance tests before publishing. Our `gov/witness_policy.py` implements (1) and version monotonicity; (2)–(4) are procedure, not code.

### 2.3 TUF root rotation — the dual-threshold rule (the canonical onboarding grammar)

From the TUF specification §5.3 (https://theupdateframework.github.io/specification/latest/, accessed 2026-10-05):

- Version N+1 **MUST be signed by (1) a THRESHOLD of keys specified in trusted root N, AND (2) a THRESHOLD of keys specified in the new root N+1** — one signature per unique KEYID. This is the rule that lets a policy rotate its own authority without self-authorization.
- Version MUST be **exactly N+1** (rollback protection); the client MUST walk intermediate versions and **persist each new root to non-volatile storage**.
- Root keys MUST be kept offline; a sub-threshold compromise is recovered by normal rotation; a threshold compromise requires out-of-band recovery ("safely recovering from it is nearly impossible" — §2.1.1).

**Mapping to witness-policy onboarding:** the threshold-signed witness-policy artifact should use the same dual-threshold rule at policy-id handover: a policy update that changes the *policy-signer set itself* must carry threshold(old set) + threshold(new set); ordinary witness-set membership changes (add/remove witness keys) are authorized by threshold(current policy signers) on a strictly-newer version. Our tree's `check_policy_update` enforces N+1 + policy_id continuity; it should additionally enforce the dual-threshold on signer-set changes (currently: verify).

### 2.4 Overlap-then-retire — the concrete rules, assembled

No single doc states "witness rotation" end to end; the rules compose from four primary sources:

1. **Add before remove, overlapping validity:** from the TrustedRoot proto rule above — the successor witness key enters the policy with a `valid_for` starting in the future, the predecessor stays until its window closes; clients MUST accept overlapping instances. For witnesses this means: a rotated witness key looks like an "unknown cosigner" to stale clients, so the overlap window must cover the policy propagation delay.
2. **Verifier MUST-ignore-unknown-signatures** (C2SP signed-note; tlog-witness "The client MUST ignore cosignatures from unknown keys") — rotation is non-breaking by construction *iff* the verifier implements MUST-ignore. Verifiers that reject notes with extra lines break on rotation.
3. **Same-key-different-name = same witness** (tlog-policy "duplicate" rule) — pin the (name, keyID, key) vkey tuple, never the name alone.
4. **Witness state discipline** (tlog-witness): a witness MUST persist-before-respond with atomic check-and-persist. Corollary (w321 + C2SP): a witness that loses state MUST NOT resume cosigning from the log's current head — it would destroy the anti-equivocation guarantee. Recovery = re-bootstrap from an operator-supplied trusted checkpoint (TOFU only at first init per transparency-dev/witness README), never from the untrusted log.
5. **Key drop authorization:** a witness key removal is just a threshold-signed strictly-newer policy version — the threshold signature IS the drop authorization (already the rule in `gov/witness_policy.py`'s `check_policy_update`).

### 2.5 Below-quorum behavior — what the sources say

- **Rekor v2 spec §5.3:** the log "blocks until it receives the co-signed checkpoint." Fail-closed by specification: no quorum → no checkpoint → no client responses. (architecture-docs rekor-v2-spec.md)
- **CLIENTS.md:** clients must set ≥20s timeouts precisely because of this blocking. The cost of fail-closed is paid in client latency. (rekor-tiles CLIENTS.md)
- **Tessera's escape hatch (private deployments):** `tessera.WitnessOptions{FailOpen: true}` publishes the checkpoint "and whatever valid witness signatures were obtained for it, **regardless of whether the obtained signatures satisfy the specified witness policy**" — explicitly described as a **"temporary mechanism"** "as it develops and matures" (https://github.com/transparency-dev/tessera/pull/634, 2025-05). The 2025 summit slides add: "*Eventually, once the witness network is more robust, this will fail closed by default" (https://transparency.dev/pdfs/summit2025/tessera.pdf, crawl 2026). Whether the default has flipped as of 2026-10 is **unverified** (w321 open question stands).
- **Rekor v2 production today:** the live checkpoint w321 captured carries 3 synchronous cosignatures — i.e., production currently *satisfies* quorum; there is **no published incident of a fail-closed quorum monitor halting on unreachable witnesses** (w321 incident corpus). The below-quorum path is therefore specified but operationally unexercised at Sigstore scale.
- **For our 2-of-3:** below-quorum MUST be a declared policy choice, not an accident. Recommended: fail-closed (no checkpoint published; clients keep the last cosigned head; alert fires), with the availability cost budgeted in the runbook. Tessera's FailOpen is explicitly temporary — do not copy it as a steady state.

## 3. Private-deployment witness runbooks — sources, costs, traps

### 3.1 What operators actually run

- **OmniWitness** (transparency-dev/witness, Apache-2.0 — LICENSE verified 2026-10-05): "the witness is an HTTP service that stores checkpoints it has seen from different verifiable logs in a **sqlite database**. This is a very lightweight way to help detect or even prevent split-view attacks." "Most users wanting to run a witness will simply deploy the OmniWitness, **which is preconfigured to witness all known logs**." First checkpoint may be TOFU from the log. (https://github.com/transparency-dev/witness/blob/HEAD/README.md, accessed 2026-10-05)
- **ArmoredWitness:** dedicated hardware devices running the same code; the `distributor` project publishes witnessed checkpoints (e.g. Android Pixel binary-transparency checkpoints carrying ArmoredWitness cosignatures). Hardware-backed witness keys are the production answer to the "bastion" concern. (same README)
- **Tessera log-side wiring:** `tessera.NewAppendOptions().WithWitnesses(witnesses, Opts)` where the policy is parsed from the C2SP tlog-policy grammar (`NewWitnessGroupFromPolicy`); witness keys are vkeys parsed as ML-DSA-44 first, falling back to `cosignature/v1` Ed25519 (`NewWitness` in witness.go). License: Apache-2.0 (source header verified). (https://github.com/transparency-dev/tessera/blob/HEAD/witness.go, accessed 2026-10-05)
- **witness-network.org:** the public network's working directory; README status is literally **"Work in progress"** (https://github.com/transparency-dev/witness-network/blob/HEAD/README.md, accessed 2026-10-05). Its `logs/v0` list grammar (vkey/origin/qpd/contact) is unsigned and pre-production per w321. There is no published onboarding runbook with acceptance criteria beyond the sigsum meeting notes: for a test witness, "it is enough that the witness operator expresses an intention to keep it running for an extended period of time, at least for several months" — and reputation-staking via an official about page on the operator's own domain (https://github.com/sigsum/sigsum/blob/HEAD/archive/2025-10-14--meeting-minutes.md, accessed 2026-10-05).
- **The third-party 3-of-5 practice:** Sigsum's own deployed policy (FOSDEM 2025 slides): `group Corps 3 Cyberdyne Encom Faro Frobozz Octan` / `quorum Corps` — 3-of-5 across five named witnesses (https://git.glasklar.is/nisse/fosdem-sigsum-2025/-/raw/3966d24ac426ef347346187993cdb078906292f4/slides.pdf?inline=true, accessed 2026-10-05). License: sigsum-go is BSD-2-Clause (LICENSE verified 2026-10-05).

### 3.2 Cost numbers — honest statement

**No primary source publishes dollar figures for running a witness.** The qualitative evidence is consistent:

- Sigsum FOSDEM slides: "Witnesses are light… **Modest storage, processing and bandwidth**. A witness can serve many transparency logs." (same slides URL)
- transparency-dev/witness README: sqlite + a small HTTP service. (same README URL)
- The dominant costs are **key custody** (tlog-witness: operators MAY use a bastion; production uses hardware devices / HSMs) and **24/7 availability** (Sigstore reference: 99.5% SLO), not compute. Witness bandwidth scales with checkpoint cadence, not log size — a witness stores one checkpoint per log, not the log.
- For OUR 3-witness quorum the honest budget line: three small always-on instances (or one operator + two independent parties for real diversity) + hardware-backed keys + monitoring. No credible primary-source $/month figure exists; any number in a build plan must be labeled an estimate, not a sourced fact.

### 3.3 Operational traps (each with a source)

1. **Stale-key ledger / shared state:** a witness MUST persist-before-respond atomically; concurrent add-checkpoint requests can roll state backward (spec's own race example). (tlog-witness.md)
2. **State loss → must not re-baseline:** a state-lost witness resuming from the log's head silently voids the anti-equivocation guarantee. (tlog-witness.md + witness README TOFU note)
3. **Name-pinning:** pin the (name, keyID) vkey tuple; name-only pinning breaks on rotation. (tlog-policy duplicate rule; w321)
4. **Verifiers that reject unknown signature lines** break rotation and cosigning alike — MUST-ignore is load-bearing. (tlog-witness.md; rekor-v2-spec §6.3)
5. **Checkpoint stability:** witnesses need consensus on a *stable* checkpoint; Rekor v2 solves this by infrequent checkpoint updates (§4.4). A deployment that publishes a checkpoint per entry will thrash its witnesses.
6. **Fail-open creep:** Tessera's FailOpen is a documented temporary measure; shipping it as the steady state publishes unwitnessed checkpoints that *look* witnessed (they carry partial cosignature sets). (PR #634)
7. **Monitor/witness confusion:** only logs and sometimes monitors talk to witnesses; clients never do. A client that fetches cosignatures itself is doing the async pattern the spec deliberately replaced. (tlog-witness.md intro; rekor-v2-spec §5.3)
8. **Cosignature `time` is not a timestamp authority:** cosignature timestamps are the witness's claim; CLIENTS.md's "independent signed timestamp" line is Sigstore's plan, not a property we can assert for our own witnesses. (rekor-tiles CLIENTS.md)

## 4. Cheapest honest path for OUR envelopes (build-lane spec)

Scope: operator-run 3-witness / quorum-2 network for Sasanam evidence checkpoints, reusing the tree's existing pieces. **New code is only the submission path and the witness daemon.**

### 4.1 Reuse (already in tree — do not rebuild)

- Signed witness-policy artifact: `gov/witness_policy.py` (`seal_policy`, `verify_policy_document`, `check_policy_update`, `active_witnesses`, `verifier_inputs`). **Gap to close:** enforce TUF dual-threshold (threshold(old)+threshold(new)) when the *policy-signer set* changes.
- Checkpoint note wire format: `gov/checkpoint_note.py` (3-line body, `—` lines, keyID rules).
- The log: `gov/witness_log.py` (RFC 6962 tree, signed checkpoints).
- Verification: `gov/witness_consistency.py` (`require_cosignatures`, freshness, fork detection). It already implements the Rekor v2 §7.2 believer steps + the §5.3 SHOULD.

### 4.2 Build (the missing pieces, minimal)

1. **Witness daemon** (one small process per witness; stdlib only):
   - State: `{origin → (size, checkpoint_bytes)}` in sqlite (OmniWitness pattern; Apache-2.0 reference).
   - Endpoint: `POST /add-checkpoint` implementing the C2SP status table: 404 unknown origin / never-seen, 403 bad-or-missing log signature, 400 `old > size`, **409 with stored size on mismatch**, 422 on bad proof / same-size-different-root, 200 with cosignature lines after **atomic persist**.
   - Key: Ed25519 key, loaded from file/HSM; cosignature/v1 76-byte lines (`keyID(4) || u64BE unix time || sig(64)`); keyID recomputed per signed-note (`SHA-256(name || 0x0A || 0x01 || pubkey)[:4]`).
   - Optional `GET /<origin-hash>/checkpoint` monitor surface (origin hash = lowercase hex SHA-256 of origin), ≤1h delay acceptable.
   - First checkpoint: operator-supplied bootstrap (pinned), never blind TOFU in production.
2. **Log-side submission client** (in the checkpoint publisher):
   - On each checkpoint tick, `POST` to all 3 witnesses: `old <witness-last-size>` + ≤63 consistency-proof lines + blank + checkpoint; on 409, rebase `old` to the returned size and retry once; keep-alive connections (SHOULD per spec).
   - **Block publication until ≥2 valid cosignatures collected** (Rekor v2 §5.3 semantics, fail-closed). Timeout per witness: policy input, default **10s** (spec's "<10s" estimate, CLIENTS.md), total client-facing budget **≥20s** (CLIENTS.md rule).
   - Below quorum → no checkpoint published, head stays, alert fires. This is the declared policy, budgeted in the runbook (cf. §2.5).
3. **Policy inputs** (all inside the signed witness-policy artifact — zero log calls for a verifier holding it):
   - witness entries: `witness <name> <vkey>` + operator identity + `valid_for` window;
   - `quorum`: 2-of-3 (group threshold; C2SP `group … 2 …` grammar);
   - checkpoint cadence: e.g. every 60s or every N entries — infrequent enough for witness consensus (§4.4 stability rule);
   - per-witness timeout (default 10s), freshness bound (reject checkpoints older than X; C2SP defines no bound — it is our policy addition);
   - policy `version` (N+1 monotonic), `policy_id` continuity, threshold-signed.
4. **Verification contract** (auditor holding only the policy artifact):
   1. Verify checkpoint signature against the policy's log key (signature first; sizes/roots ONLY from the verified note).
   2. Verify ≥2 cosignatures from policy-pinned witness vkeys; **ignore unknown signature lines**; a configured witness's bad signature is a hard refusal.
   3. Freshness: `auditor_now − max(cosignature times)` ≤ policy bound; reject future-dated times.
   4. Inclusion proofs recomputed against the verified root (existing `verify_inclusion`).

### 4.3 Key format (concrete)

- Witness vkey: `<name>+<hex keyID>+base64(0x04 || 32-byte Ed25519 pubkey)` — sigtype byte `0x04` = cosignature/v1 (existing tree convention).
- Checkpoint lines: log's own `— <origin> <base64(0x01||sig)>`; witness lines `— <witness-name> <base64(0x04||keyID(4)||time(8)||sig(64))>` — 76-byte blobs, byte-for-byte C2SP.

### 4.4 Honesty boundaries (what we are NOT claiming)

- We do **not** interop with Sigstore's public witness network; our witnesses are operator-run. Their quorum, their keys, our policy artifact.
- Witnessing proves **checkpoint consistency (anti-equivocation)** — not bundle content truth, not entry authorization, not signature correctness, not wall-clock time. (Rekor layering: digest-existence-only; witness layering: consistency-only.)
- We do **not** claim cosignature timestamps as an RFC 3161 substitute (that is Sigstore's plan for *their* network, CLIENTS.md).
- Fail-closed availability cost is explicit: during a witness outage or quorum shortfall, the trusted head freezes and newer checkpoints refuse. No silent FailOpen.
- ML-DSA-44 cosignatures: spec SHOULD, practice Ed25519 — we ship Ed25519 and note the PQ upgrade path; we do not claim PQ today.
- No dollar cost figures are sourced; the runbook carries estimates labeled as estimates.

## Verdicts

- **STEAL:** C2SP `add-checkpoint` wire protocol (request shape, 63-proof-line cap, 404/403/400/409/422/200 table); atomic persist-before-respond; MUST-ignore-unknown-signatures; cosignature/v1 76-byte line format; keyID recomputation rule; TUF dual-threshold N+1 rotation; TrustedRoot overlap rule (overlapping `valid_for`, future-dated successor, never drop old instances); ≥20s client timeout + ~10s witness budget; root-signing ceremony shape (5 keyholders, hardware keys, staging repo, ~3-day online re-signing); OmniWitness sqlite witness as the daemon template; Sigsum 3-of-5 group grammar as the quorum example.
- **ADAPT:** C2SP tlog-policy line grammar → wrapped in our threshold-signed, versioned, expiring policy artifact (`gov/witness_policy.py` already does this; add dual-threshold on signer-set change); Tessera `WithWitnesses` M-of-N wiring → our submission client, but **FailOpen=false** (their fail-open is explicitly temporary); keep-alive SHOULD.
- **WATCH:** ML-DSA-44 cosignatures (spec SHOULD, zero deployed practice found); Sigstore public witness network + TrustedRoot witness-key slot (proto has no field at HEAD); Tessera FailOpen default flip; witness-network.org production list; `sign-subtree` (OPTIONAL, not needed).
- **SKIP:** sign-subtree for v1; client-to-witness direct fetching (async pattern the spec replaced); witness gossip protocols (w321 SKIP stands); RSA in witness keys (no C2SP slot); any hosted third-party witness as the default trust dependency.

## Licenses (checked this pass unless noted)

- C2SP specs (tlog-witness.md, tlog-policy.md): CC BY 4.0 for spec *text* (carried from w321; direct LICENSE check 404'd this pass — re-verify before quoting text; **implementation needs no attribution**, keep quotations attributed in docs).
- sigstore/architecture-docs (rekor-v2-spec.md): Community Specification License 1.0 (carried from w321 — implementable, don't copy text unattributed).
- sigstore/rekor-tiles (CLIENTS.md): Apache-2.0 (carried from w321; not re-read this pass).
- sigstore/protobuf-specs: Apache-2.0 (source header verified 2026-10-05).
- transparency-dev/tessera: Apache-2.0 (source header in witness.go verified 2026-10-05).
- transparency-dev/witness: Apache-2.0 (LICENSE verified 2026-10-05).
- sigsum/sigsum-go: BSD-2-Clause (LICENSE verified 2026-10-05).
- TUF specification: Community Specification License 1.0 (carried from w321).
- sigstore/root-signing README: used for procedural facts only.

## Open questions

1. TrustedRoot witness-key slot: planned ("distributed by Sigstore's TUF root") but absent from the proto at HEAD — extension proposal or intentionally bilateral?
2. Live Rekor v2 witness quorum: 3 cosignatures observed on `log2025-1`, but the M-of-N threshold and full roster are unpublished; the "staging"-prefixed Google witness name is unexplained (carried from w321).
3. Tessera FailOpen default as of 2026-10 — unverified; summit-2025 says "eventually fail closed by default."
4. CLIENTS.md witnessing prose is stale (describes witnessing as future while production checkpoints are cosigned) — which doc is authoritative for client implementers?
5. No primary-source dollar figures for witness operations exist anywhere found.
6. C2SP LICENSE direct verification failed (404) — re-check before any spec-text quotation.
7. `gov/witness_policy.py` dual-threshold on signer-set changes — flagged as to-verify/implement in §2.3.
