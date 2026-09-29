# Rekor Transparency Anchoring — Production Runbook (private v1)

Wave-194 lane D. This runbook is for the OPERATOR who runs Sasanam's
self-hosted Rekor v1 log. It states what Rekor is, what it is not,
and what production actually requires. Nothing here is aspirational:
every "not in v1" is marked.

## 1. What Rekor is in Sasanam (the layering contract)

A Rekor entry is a **digest-existence proof only**:

- It proves "this SHA-256 digest existed no later than
  `integratedTime`" — nothing more.
- It is **never** an authority proof. Authority stays with Sasanam's
  own signed checkpoints (`gov/log.py` format-2, Ed25519 threshold)
  and witness cosignatures (`gov/rekor_anchor.py::RekorWitness`,
  wave-183 ritual).
- The product enforces this in code: `present_as_authority()` always
  raises `RekorLayeringError`; every receipt carries
  `evidentiary_grade="digest-existence-only"` and
  `authority_proof=False`.
- **Auditors must use verify-semantics or leaf recomputation, never
  raw GET-entry proofs.** Live Rekor v1 has been observed returning
  STALE inclusion proofs (`rootHash` != current checkpoint
  `rootHash`) while `rekor-cli verify` succeeded. The product's
  `verify_inclusion()` fetches the current checkpoint and REFUSES
  stale proofs. Any auditor tooling that trusts a stored proof
  without the fresh-checkpoint comparison is broken by construction.

The Rekor server is **availability, not truth**: if the log is wiped,
the bundled evidence (offline proof bundles,
`build_offline_bundle()`) still verifies. The server being down is an
availability incident, not an integrity incident.

## 2. Self-hosted only (non-negotiable)

Sasanam anchors to an **operator-run** Rekor v1 log. The product
client (`gov/rekor_anchor.py::SelfHostedRekor`) takes the operator's
`url` + `log_id` as REQUIRED pins and REFUSES the Sigstore
production values outright — a deployment can never silently become
a hosted-service trust dependency ($0 posture, no external trust).

## 3. What production requires (the honest list)

The dev/test topology (local binaries, plaintext localhost, throwaway
keys) proves the protocol, not the deployment. Production needs ALL
of the following; each is a launch blocker, not a nice-to-have:

1. **KMS-backed signing.** The Rekor checkpoint signing key and the
   anchor key live in a KMS/HSM (never on the log host's disk).
   Rekor v1.5.x signs checkpoints with the `--rekor_server.signer`
   key; losing it means losing checkpoint continuity, leaking it
   means an attacker can sign equivocating checkpoints.
2. **TLS everywhere.** Rekor API, Trillian RPC, MySQL, Redis — all
   with real certificates. The dev stack is plaintext localhost.
3. **Authentication on the Rekor API.** v1.5.4's write path has no
   auth by default: anyone who can reach the API can submit entries
   (log bloat) — put it behind mTLS / API gateway auth, and never
   expose the write API to the open internet.
4. **HA / leader election.** Trillian's signer needs
   `--force_master`-style single-master discipline or proper
   election; two active signers fork the tree. Run the log server
   behind a load balancer with one elected signer.
5. **Durable database + attestation storage.** MySQL/Postgres with
   replication for Trillian storage and the search index; the
   attestation bucket (`file://` in dev) must be durable object
   storage with versioning.
6. **Backup and restore, TESTED.** `mysqldump` of the Trillian DB +
   operator keys + attestations, with a documented restore
   procedure that has actually been rehearsed (the wave-193 spike
   rehearsed wipe-then-restore on the dev stack: the server failed,
   bundled evidence still verified offline, restore brought service
   back).
7. **Monitoring + checkpoint freshness.** Alert on: Rekor API
   errors/latency, Trillian signer lag (checkpoint `treeSize`
   stall), disk growth, and — critically — **checkpoint freshness**:
   an auditor-side monitor should fetch `/api/v1/log` on a cadence
   and alarm if the tree stops advancing or the root stops matching
   independently recomputed roots (witness duty, automated).
8. **Rate limiting.** A fresh signature over the SAME artifact
   creates ANOTHER entry (the spike proved identical re-upload
   dedupes, but re-signing does not) — without rate limits an
   attacker (or a bug) bloats the log and the DB. Limit writes per
   key/IP and alarm on submission spikes.

## 4. The anchor-key ceremony (operator-owned)

`gov/rekor_anchor.py` takes the anchor signature as
**operator-supplied bytes** — the ceremony lives here, not in code:

- Generate the anchor key in the KMS (P-256 ECDSA recommended;
  spike-proven live against Rekor v1.5.4 as `ecdsa-p256-sha256`).
  Ed25519 anchor keys MUST use the `ed25519ph-sha512` shape —
  **raw Ed25519 is rejected by real Rekor v1.5.4** (F203:
  `unsupported hash algorithm: "SHA-256" not in [SHA-512]`).
- The anchor signature is a **raw sign over the 32-byte digest**
  (Rekor verifies with the digest pre-computed —
  `sigstore/signature` `WithDigest`). With OpenSSL that is
  `openssl pkeyutl -sign -inkey <key> -in digest.bin` (raw ECDSA);
  **`openssl dgst -sha256 -sign` over the digest double-hashes and
  the entry is rejected** (`invalid signature when validating ASN.1
  encoded signature` — measured live 2026-09-29). The KMS
  equivalent is the raw-sign (not digest-sign) operation.
- Only the digest crosses the transparency boundary; record
  contents stay local (the digest is the sole artifact-derived
  input, enforced structurally in `submit`).
- Rotate on a schedule; the old public key stays published for
  auditors verifying old entries.
- The existing `gov.anchor_backend.RekorBackend` still submits RAW
  Ed25519 and is broken against real Rekor (F203, OPEN) — do not
  use it until F203 is closed.

## 5. Auditor verification procedure

1. Take the Sasanam evidence bundle (the offline proof bundle if
   the log is unreachable).
2. For each anchored artifact: `verify_inclusion(receipt,
   anchor_hash, client=...)` — this fetches the CURRENT checkpoint,
   enforces the stale-proof guard, and recomputes the RFC 6962
   root. A `STALE` refusal means: re-fetch the entry
   (`client.get_entry(uuid)`), rebuild the proof, verify again.
   Never override a STALE refusal.
3. Check witness cosignatures: `verify_witness_cosignatures` with
   the OUT-OF-BAND witness registry and the deployment's quorum.
   Same-size/different-root at a witnessed size is equivocation —
   treat it as a security incident, not a verification hiccup.
4. Remember the grade: even a fully-verified receipt is
   digest-existence evidence. The AUTHORITY decision still comes
   from Sasanam's checkpoint signatures + witness quorum.

## 6. Incident playbooks

- **Log server down:** availability incident. Serve auditors the
  offline proof bundles; they verify with zero server contact.
  Restore from backup (rehearsed procedure); the tree is
  content-addressed, so a restored DB either matches the last
  checkpoint or it doesn't — verify before re-opening writes.
- **Stale proofs observed:** expected during signer lag; the
  product refuses them. If staleness persists past the signer
  interval, investigate the Trillian signer.
- **Equivocation (same size, different root):** SECURITY INCIDENT.
  Quarantine the log, preserve the DB, rotate the checkpoint
  signing key, and investigate key compromise. Witness records
  (`equivocations_seen`) are the forensic starting point.
- **Database loss without backup:** the log cannot be rebuilt
  (leaves are gone). Bundled evidence still verifies offline, but
  no NEW proofs can be served for old entries. This is why
  backup/rehearsal is a launch blocker.

## 7. What private v1 explicitly does NOT have

- No KMS integration in the anchor path (operator ceremony, §4).
- No TLS/auth/HA in the product client (operator deployment, §3).
- No ECDSA verification of the Rekor checkpoint's operator
  signature in the product (no ECDSA in the tree — same boundary
  as wave-72's SET handling; carried, not verified).
- No log-bloat protection in the client (server-side rate
  limiting, §3.8).
- `gov.anchor_backend.RekorBackend` remains broken against real
  Rekor (F203 OPEN) — the self-hosted client in
  `gov/rekor_anchor.py` is the supported path.
- STALE-refusal race (known, fail-closed direction): `verify_inclusion`
  fetches the checkpoint *after* the entry, so on a live growing log a
  legitimately fresh proof is refused whenever the tree grows between
  the two fetches. Recourse is a re-fetch loop (fetch entry, verify,
  retry on STALE); never override a STALE refusal. There is no
  consistency-proof path to adjudicate same-size/different-root —
  that case stays a loud EQUIVOCATION (witness) / refusal (client).
