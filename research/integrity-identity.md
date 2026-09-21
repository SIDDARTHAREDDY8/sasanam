# Integrity & Identity Research — Agent Governance

Research date: 2026-09-21. Covers: tamper-evident logging, agent identity/attestation,
log verification/replay tooling, and secrets/PII handling in logs.
Grounds: current `gov/log.py` (plain SHA-256 hash-chained JSONL + `verify_chain()`
replay), `gov/identity.py` (self-described `agent_id/role/run_id/principal` dataclass),
`gov/executor.py` (agents pass their own identity in; content already excluded from
result summaries).

---

## 1. Tamper-evident logging: hash chains, Merkle trees, CT, Rekor

### 1.1 Certificate Transparency (RFC 6962)

Certificate Transparency solves "the log operator might lie" for TLS certificate
issuance. Key mechanism (per RFC 6962, rfc-editor.org; superseded by RFC 9162 in
2021 per the linked GitHub issue, but the Merkle constructions are materially the
same):

- **Merkle Tree Hash (MTH)** over ordered log entries — the root commits to the
  entire ordered log.
- **Inclusion proofs** ("Merkle audit proofs"): prove a specific entry is in the
  log in O(log n) hashes (`ceil(log2(n)) + 1` nodes max).
- **Consistency proofs**: given an old tree of size m and a new tree of size n,
  prove the first m entries are identical in both — rules out truncation,
  insertion, reordering, modification with only O(log n) hashes. The 1f916-ai
  issue on this topic notes the crucial point: verification against a *linear*
  hash chain is O(n) — you must rehash every row — while a Merkle consistency
  proof needs ~15 hashes even for a 20,000-entry log.
- **Signed Tree Heads (STH)**: periodic operator-signed commitments (root hash +
  tree size + timestamp).
- **Gossip**: clients exchange STHs; two conflicting STHs for the same log are
  *cryptographic proof* of operator misbehavior (split-view attack detection).

Sources: https://www.rfc-editor.org/info/rfc6962/ ,
https://datatracker.ietf.org/doc/draft-ietf-trans-rfc6962-bis/04/ ,
https://github.com/1f916-ai/1f916/issues/16

Threat model it defeats: a log operator (or attacker with write access to the log
store) who tries to add, remove, reorder, or rewrite historical entries — as
long as verifiers hold an old STH. It does **not** defeat suppression-at-emit
(events that never reach the log in the first place), and split-view attacks are
only detectable via gossip, not prevented.

### 1.2 Sigstore / Rekor

Rekor is Sigstore's transparency service: "a tamper-evident, verifiable,
append-only log to publicly record the existence of signing events, taking
inspiration from Certificate Transparency (RFC 6962)" (sigstore/architecture-docs,
rekor-spec.md). Each record is a Merkle leaf; the service provides **inclusion
proofs** and **consistency proofs**, supports **offline verification**, and
returns a signed entry timestamp (`integratedTime`) per entry — a temporal proof
that the signing event happened while the (short-lived, 10-minute) Fulcio
certificate was valid.

What Rekor's model adds on top of CT mechanics:
- **Non-repudiation**: the signer cannot later deny signing; the entry is
  auditable evidence.
- **Key-compromise detectability**: unexpected signatures under an identity show
  up in the log; monitors watch for them.
- **Keyless signing compatibility**: because the *event* is timestamped and
  logged, the signing certificate doesn't need to remain valid for verification.
- **Private Rekor option** (self-hosted Trillian + Rekor) when entries are
  commercially sensitive — the mechanism doesn't require a public log.

Sources: https://github.com/sigstore/architecture-docs/blob/HEAD/rekor-spec.md ,
https://github.com/sbomify/sbomify.com/blob/HEAD/content/posts/2024-08-12-what-is-sigstore.md ,
https://github.com/ai-governance-curriculum/security-learning/blob/HEAD/lessons/mod-104-data-and-model-lineage-security/02-cosign-sigstore-model-artifact-signing.md

### 1.3 What a plain hash chain gives you (what we have now)

A SHA-256 hash chain (`hash = SHA256(prev_hash || canonical(entry))`) detects
**modification of any stored entry** and **reordering/insertion/deletion of
interior entries** — but only via full O(n) replay, and only if the verifier
holds an independent copy of a later chain head. It does **not** defeat:

- **Tail truncation**: deleting the last N entries leaves a perfectly
  self-consistent shorter chain. (The emf_project ADR on tamper-evident audit
  storage lists exactly this limitation: "deletion of the final record or an
  entire final suffix" and "replacement or rollback of the complete database"
  are not detected by a local hash chain.)
- **Truncate-and-rebuild**: an attacker with write access recomputes the whole
  chain — it verifies cleanly. ("A truncate-and-rebuild by a writer who deletes
  both anchors, with no external anchor published. The rebuilt chain is
  perfectly self-consistent." — netresearch/t3x-nr-vault audit evidence docs.)
- **Suppression-at-emit**: an event that never gets written can't be detected by
  replaying what *was* written. (initializ/forge audit-signing threat model:
  signing "does NOT detect suppression-at-emit — a signing failure, marshal
  failure, or sink drop that prevents an event from being written at all.")
- **Authorized-but-malicious events**: valid hashes on fabricated entries.

Source: https://github.com/gouldopfl/emf_project/blob/HEAD/docs/architecture/ADR-028-tamper-evident-security-audit-storage.md ,
https://github.com/netresearch/t3x-nr-vault/blob/HEAD/Documentation/Security/AuditEvidence.rst ,
https://github.com/initializ/forge/blob/HEAD/docs/security/audit-signing.md

### 1.4 Recommendation: HMAC-chained log + external checkpoints (stdlib-only)

For a **local-first** agent audit log, the right upgrade is **HMAC-SHA256 with a
local key**, not plain hashing, not ed25519, and not full Merkle proofs (yet):

- **Why HMAC (stdlib `hmac` module)**: turns the chain into an *authenticated*
  chain. Anyone can still read the JSONL, but only the key holder can produce a
  valid chain — defeating truncate-and-rebuild by anyone who compromised the log
  *file* but not the key store. Zero dependencies, one-line change to
  `_entry_hash`.
- **Why not ed25519 now**: asymmetric signatures give non-repudiation and
  third-party offline verification (anyone with the public key verifies; only
  the key holder signs) — the right choice the moment an *external auditor* must
  verify without being trusted with a secret. But ed25519 needs a dependency
  (PyNaCl / `cryptography`), and for a local-first product the verifier is
  normally the same operator who holds the key anyway. The sentenz cryptography
  guidance puts it cleanly: "Asymmetric signature architectures (such as
  Ed25519) should always be favored over symmetric architectures for
  *distributed offline validation engines*" — and we're not distributed yet.
  (KeyRack's FOSS core ships exactly this as the upgrade path: Ed25519+BLAKE3
  signed/chained audit events.)
- **Why not Merkle inclusion proofs now**: they shine when you need per-entry
  proofs for third parties, O(log n) verification of huge logs, or gossiping
  roots across mutually-distrustful operators. With local-first logs of modest
  size, full replay is cheap; the valuable, cheap piece to steal from CT is the
  **Signed Tree Head / checkpoint** concept, not the tree itself.
- **How to defeat tail truncation cheaply**: periodically write a signed
  checkpoint — `{seq, head_hash, timestamp}` HMAC'd (or later signed) — into an
  *independent* store (a second file outside the run dir, or appended to a
  separate append-only checkpoint log). Verification asserts the chain's head
  matches the latest checkpoint; a truncated chain fails. The emf_project ADR
  prescribes exactly this: "periodically preserve the latest chain head and
  record count in an independent, access-controlled system."
- **Key hygiene**: per-log "key epoch" bound into the MAC (as t3x-nr-vault
  does: the epoch selector itself is hashed, closing the downgrade path);
  rotate via epoch bump; keep old keys for verification of old epochs. Key
  source: env var or OS keyring, never in the repo; `0600` file if stored.

Concretely: keep the SHA-256 chain (compatibility), add `chain_mac =
HMAC-SHA256(key, prev_mac || canonical(entry))` per entry, plus a
`gov/checkpoint.py` that seals `{seq, head}` every N entries / at run close,
and a `verify` that checks both. ed25519 becomes the migration when external
auditors need to verify.

---

## 2. Agent identity: SPIFFE/SPIRE ideas and real AI-agent identity work

### 2.1 SPIFFE/SPIRE concepts

SPIFFE (Secure Production Identity Framework for Everyone) is an open standard
for workload identity; SPIRE (SPIFFE Runtime Environment) is its CNCF-graduated
implementation. Core ideas:

- **SPIFFE ID**: a URI like `spiffe://trust-domain/path/to/workload`, carried in
  the URI Subject Alternative Name of an X.509 certificate (not a custom OID).
- **SVID (SPIFFE Verifiable Identity Document)**: short-lived X.509 cert (~1
  hour), automatically rotated — rotation *replaces* revocation in the common
  case. A JWT-SVID variant exists where mTLS isn't available.
- **Attestation-based issuance (two layers)** — the key insight over passwords:
  - *Node attestation*: the SPIRE agent proves the *machine* to the server
    (TPM, cloud instance identity document, K8s projected token).
  - *Workload attestation*: the workload presents **nothing**; the local agent
    interrogates the kernel (caller PID from socket peer credentials, UID,
    namespace, service account, container image) and matches those observed
    selectors against registration entries. "The workload proves identity by
    what it is — which it cannot forge and cannot leak."
  - The workload generates its own private key locally; the agent signs only the
    CSR.
- This solves the **secret-zero problem**: no first secret to protect.

Sources: https://ypeavler.github.io/blog/learn/in/a/hurry/2026/03/05/workload-identity-in-a-hurry.html ,
https://github.com/koherenc3/protocol-academy/blob/HEAD/content/protocols/spiffe/flows/x509-svid-issuance/content.mdx ,
https://fixmycert.com/guides/spiffe-spire

### 2.2 What transfers to software agents making tool calls

- **Identity as a URI, not a bare string**: `spiffe://gov.local/run/<run_id>/agent/<agent_id>`
  (or a DID-style URI) gives a namespaced, delegable, log-grepable identity.
  Even without SPIRE running, the *shape* is valuable: trust domain + path.
- **Issued, not self-claimed**: the governance layer (executor/launcher) must
  *assign* identities; today's `call()` accepts an `AgentIdentity` the caller
  constructs — that's like accepting a self-signed "I am admin" badge. The
  SPIFFE lesson is that the authority mints the identity and the agent merely
  carries it.
- **Attestation ~ capability manifest**: SPIRE's selectors become, for agents,
  the signed manifest of *what the agent is authorized to be*: role, allowed
  tools, model identity, code/prompt version hash. (The speculative EAIP spec
  circulating on GitHub proposes exactly this: a "capability manifest" — a
  signed list of tools the dispatcher permits the executor to invoke. Note: EAIP
  is a non-authoritative community doc, useful for vocabulary, not as a
  standard.)
- **Short-lived, scoped identities per run/task**: an agent's identity should
  expire with the run — matching SPIRE's sub-hour SVIDs and the NCCoE
  task-specific-identity option.

### 2.3 Real, verifiable AI-agent identity work (not invented)

- **NIST NCCoE concept paper (Feb 5, 2026)**: "Accelerating the Adoption of
  Software and Artificial Intelligence Agent Identity and Authorization" —
  identifies **four focus areas**: Identification, Authorization, Access
  Delegation, Logging and Transparency; calls out OAuth/OIDC, SPIRE, ABAC as
  building blocks, and flags auditable logging and delegation trails as
  critical. Comments were due April 2026; an NCCoE demonstration project is
  planned. Source: https://www.pulse.bot/cybersecurity/news/nist-concept-paper-explores-identity-and-authorization-controls-for-ai-agents-61708c5c-0239-4715-82e8-b83d3e7e2ff4/
- **GSA TTS agentic-coding-playbook (federal)**: operationalizes the NCCoE
  areas; non-repudiation section requires: audit logs on an **append-only store
  the agent cannot modify**, integrity protection (hashing, signing, or
  chaining), the **delegation token used for each action must be logged** so the
  chain is verifiable after the fact, and **"Agents MUST NOT have write access
  to their own audit logs."** Source: https://github.com/gsa-tts/agentic-coding-playbook/blob/HEAD/docs/AGENT-IDENTITY.md
- **audit-forge/mark-sentinel AI-AGENT-005**: pass criteria for agent action
  logs — tool calls with params/response/timestamp/session, logs tamper-evident
  and **stored separately from application data**, entries include the reasoning
  or plan step that triggered the action.
  Source: https://github.com/audit-forge/mark-sentinel/blob/HEAD/checks/AI-AGENT.md
- **mishrasanjeev/grantex NIST comment**: recommends agent-specific identity
  standards (persistent cryptographic identities, DIDs), action-level
  tamper-evident append-only logs, sub-second revocation with cascade across
  delegation chains. Source: https://github.com/mishrasanjeev/grantex/blob/HEAD/docs/standards/nist-nccoe-comment.md

What I could **not** verify as a real, adopted standard: any ratified
AI-agent-identity RFC/spec (the Medium "AIT" JWT spec and GitHub EAIP docs are
community proposals, not adopted standards). Say so in product docs.

---

## 3. Log verification & replay tooling: what a credible audit trail needs

From the sources above plus the forge/emf threat models, a credible audit trail
needs:

1. **Offline verifier**: a standalone, dependency-free tool that verifies the
   chain (hashes, HMACs, checkpoints, sequence monotonicity, timestamp
   ordering) with no network, no running service. (Rekor spec explicitly
   requires the transparency service to support offline verification; the AEGIS
   marketing doc ships a 245-line offline verifier — the pattern is standard.)
2. **Canonical serialization**: verification must re-derive identical bytes;
   sorted keys + fixed separators (already done in `_canonical`) — keep it, and
   freeze the format with a `format_version` field per entry.
3. **Chain-of-custody properties**:
   - Write separation: the agent being audited cannot write to (or even
     influence the write path of) its own log (GSA rule). In our design, only
     `ToolExecutor`/`ActionLog` hold the file handle; agents go through
     `executor.call()`.
   - Append-only file discipline: mode that refuses modification of existing
     bytes (open `"a"`, never `"r+"`); file ownership/permissions locked down
     (`0600`, separate owner where possible).
   - Checkpoints as custody transfers: each checkpoint is a signed custody
     record — "at time T the chain was at seq N with head H, attested by K."
4. **Export**: `export` that bundles the JSONL + checkpoints + verifier +
   a manifest (format version, key epochs, checkpoint list) so an auditor can
   re-verify on an air-gapped machine. Include a per-entry "audit receipt":
   `{seq, entry_hash, chain_head_at_export, hmac}` — verifiable without the
   whole log *only* if Merkle inclusion proofs exist; otherwise the receipt is
   "entry X is at position seq in a chain whose head is H," verifiable given
   the full log. Be honest about that in docs.
5. **Tamper-evidence reporting**: verifier returns structured verdicts —
   OK / broken-at-seq-N / tail-mismatch-vs-checkpoint / gap-in-sequence —
   with the first failing entry, not just a boolean.
6. **Suppression-at-emit mitigation**: emit must be fail-closed — if the log
   append fails, the tool call must fail (never silently proceed unlogged).
   Monotonic `seq` persisted in the checkpoint store lets the verifier detect
   gaps between checkpoints.

---

## 4. Secrets & PII in logs and tool outputs

### 4.1 Standard detection approaches

- **Yelp `detect-secrets`** (the original, widely copied): plugin architecture —
  `Base64HighEntropyString` / `HexHighEntropyString` (Shannon entropy over
  charset-filtered strings above a length/entropy threshold),
  `PrivateKeyDetector` (PEM headers), `BasicAuthDetector` (URLs with embedded
  credentials), `KeywordDetector` (assignment to names like
  `password|secret|api_key|token`). Baseline + inline allowlist pragmas.
  Source: https://github.com/crazydevice/detect-secrets (mirrors of Yelp's repo)
- **gitleaks**: regex rule library (named patterns per provider: AWS, GitHub
  PAT, etc.) + optional Shannon-entropy thresholds per rule (`entropy = 4.5`
  over `[a-zA-Z0-9]{32,}`), composite rules, global and rule-scoped allowlists.
  Source: https://github.com/tomevault-io/tomes/blob/HEAD/./rohunj--claude-build-workflow/skills/secrets-gitleaks/SKILL.md
- **Standard remediation when a true positive lands in a log**: rotate the
  credential immediately; redact/purge from history. (Since our logs are
  append-only, "purge" means checkpoint-and-replace the chain, which is itself a
  logged custody event — design for it now.)

### 4.2 How to audit without logging secrets

Detection is the backstop; the primary control is **never emitting secrets into
the log in the first place**:

1. **Field allowlist per tool** (preferred over denylist): each tool declares
   which arg/result fields are loggable (`path`, `url`, `endpoint`,
   `status`, `bytes`) — everything else is excluded. Executor already does
   this for result `content`; extend to args.
2. **Redact-before-log transform** on args: pattern library of ~15 common
   credential formats applied to every string arg and to result summaries:
   `sk-live`/`sk-ant`/`sk-...` keys, `ghp_/gho_`, `AKIA`, `xox[bap]-`,
   `-----BEGIN .*PRIVATE KEY-----`, `password=`, `Authorization: Bearer`,
   basic-auth in URLs (`://user:pass@`), PEM blocks, JWT-looking segments.
   Replace with `[REDACTED:secret:<rule-id>]` — keep the rule id so auditors
   know *why* it's redacted without seeing the value.
3. **Entropy tripwire**: for any string arg ≥ 24 chars with Shannon entropy ≥
   4.5 bits/char (base64/hex alphabets), redact even if no pattern matched.
   Stdlib-implementable in ~10 lines (`math` + `collections.Counter`).
4. **PII masking**: email/phone patterns → masked (`s***@example.com`);
   full file `content` in args never logged verbatim — log `{path, bytes,
   sha256_prefix}` only. This matters for `write_file` content, which today
   is logged in full in `args`.
5. **Human-approval queue copies** get the same redaction pass — the approval
   record currently stores raw `action` (args); an approver reviewing a queue
   shouldn't need the plaintext secret either.
6. **Log the redaction**: an entry records `redactions_applied: [rule-ids]`
   so a verifier can distinguish "no secret present" from "secret was present
   and redacted" — without storing the secret.

---

## DESIGN RECOMMENDATIONS FOR THIS PRODUCT

Concrete, implementable, stdlib-only items (ordered by value/effort):

1. **Upgrade the chain to HMAC-SHA256 with a local key** (stdlib `hmac`).
   `chain_mac = HMAC(key, prev_mac || canonical(entry))`; keep the existing
   unkeyed `hash` field for backward compatibility. Key from env
   (`GOV_LOG_KEY`) or OS keyring; never in the repo. Defeats truncate-and-rebuild
   by anyone holding the log file but not the key. One-line-ish change to
   `_entry_hash`; `verify_chain()` gains an HMAC check.
2. **Add a `key_epoch` field bound into the MAC** (hash the epoch in with the
   payload, as t3x-nr-vault does). Rotation = bump epoch, keep old keys for
   verification of old segments. Closes the silent-downgrade path.
3. **Add checkpoints (STH-style)** in `gov/checkpoint.py`: every N entries and
   at run close, seal `{seq, head_hash, head_mac, ts}` into an independent
   append-only file outside the run dir (or a second JSONL). Verification
   asserts the chain head matches the latest checkpoint — this is the cheap
   fix for tail truncation, the biggest real weakness of the current design.
4. **Make log emission fail-closed**: if `ActionLog.append()` raises, the tool
   call must not execute (wrap `call()` so a logging failure aborts with an
   error, never a silent unlogged execution). Add a test that kills the log
   path and asserts the tool did not run.
5. **Freeze the canonical format**: add `format_version: 1` to every entry;
   document the canonicalization (sorted keys, `separators=(",",":")`,
   `ensure_ascii=True`) as a contract the verifier depends on.
6. **Build the offline verifier** (`gov/verify.py`, stdlib only): checks
   seq monotonicity, hash links, HMACs, timestamp ordering, checkpoint
   consistency; emits structured verdicts
   (`OK | BROKEN_AT seq=N | CHECKPOINT_MISMATCH | SEQ_GAP`), the failing
   entry, and a machine-readable JSON report. This is the artifact auditors
   actually run — treat it as a product feature, not a test helper.
7. **Add `gov/export.py`**: bundle JSONL + checkpoints + `verify.py` + a
   manifest (format version, epochs, checkpoint list) into one directory for
   air-gapped re-verification. Document honestly that per-entry receipts are
   "position + chain head" proofs until Merkle inclusion proofs exist.
8. **Defer ed25519 and Merkle proofs explicitly**: record the trigger
   conditions in docs — ed25519 when an *external* auditor must verify without
   holding the secret key; Merkle inclusion proofs when logs get large or
   third-party per-entry proofs are required. Don't add the dependency now.
9. **Issue identities; don't accept them**: change `ToolExecutor.call()` (and
   the agent SDK surface) so the executor/launcher mints `AgentIdentity` from
   a registry — agents never self-declare `agent_id`/`role`/`principal`.
   Self-claimed identity in the log is theater, and it's the current design's
   weakest point after tail truncation.
10. **Adopt URI-shaped identities**: `spiffe://gov.local/run/<run_id>/agent/<agent_id>`
    (or `did:`-style URIs). Trust domain + path is greppable, delegable, and
    aligns with the NCCoE/SPIFFE vocabulary auditors are converging on.
11. **Log the delegation chain**: add `parent_agent_id` / `delegation` to
    identity — which agent spawned this one, under what grant. The GSA
    playbook requires the delegation token per action be logged so the chain is
    verifiable after the fact; the NCCoE paper lists delegation as a focus
    area and grantex calls for cascade revocation across chains.
12. **Redact-before-log** in `executor.py`: per-tool field allowlists for args;
    pattern library (~15 credential formats) + Shannon-entropy tripwire
    (≥24 chars, ≥4.5 bits/char) applied to every string arg and result
    summary; `write_file` content logged as `{bytes, sha256_prefix}`, never
    verbatim. Emit `redactions_applied: [rule-ids]` per entry.
13. **PII masking rules**: emails/phones masked in logged args and summaries;
    never log `send_email` bodies verbatim — log `{to_domain, subject_prefix?}`
    policy decision. (Note: `to` itself is PII — log domain only by default.)
14. **Separate the writer from the audited**: enforce at the filesystem level
    that only the executor process's UID can append to the log
    (`0600`, created by the launcher); document the GSA rule "agents MUST NOT
    have write access to their own audit logs" as an enforced invariant, and
    add a startup self-check that refuses to run if the log is writable by
    the agent's UID.
15. **Approval records carry redacted copies**: run the same redaction pass on
    the queued `action` stored by the approval system, so the human review
    queue never becomes a secret store either. Log the approval decision
    (`approved_by` principal identity + reason) as its own chained entry —
    non-repudiation for the human side too.

Deliberately out of scope for now: a transparency-log *server* (Rekor-style),
gossip protocols, and any public anchoring — those solve distrust of the
operator, which a local-first product doesn't have yet. Revisit when logs
leave the machine.
