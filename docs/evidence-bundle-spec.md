# Evidence Bundle v1 — Spec (signed export bundle + standalone verifier)

**Status:** spec, not implementation. **Date:** 2026-09-24.
**Track:** v1 ship sprint (Track 3), private v1.0, deadline 2026-10-31.
**Scope parent:** `workstreams/architect/SHIP_PLAN.md` §2 (v1 evidence product surface:
"one signed, timestamped, auditor-readable export bundle (decisions + approvals +
retention manifest)… Export only — no managed service, no auditor blessing claimed").

**Requirement:** the signed bundle + verifier is the non-negotiable evidence item;
per SHIP_PLAN it is the only scope item that opens a budget line (founder strategy:
"sell evidence, not the engine").

**Honesty contract (inherited from `gov/evidence_exports.py`, non-negotiable):**
fail-closed; never invent fields — fields no log entry can supply are emitted as
`null` with `operator_must_supply: true`; every rendered field carries provenance
(`{"kind": "log", "seq", "hash", ...}` or `{"kind": "operator_must_supply"}`);
the generator refuses to render when the log chain does not verify.
The bundle reuses the existing machinery (`gov.log` chain + `prove_inclusion` /
`verify_inclusion_bundle`, `gov.merkle`, `gov.signing`, the
`evidence_exports.py` sealing pattern, the `gov/safeguard_bundle.py` §5 transport
pattern) — **no parallel scheme**.

---

## 1. Problem Statement

An auditor (or a design partner's security reviewer) asks the deployer: "prove
that these governance decisions happened, under this policy, with these
approvals, with this evidence integrity." Today the answers exist but are
scattered: the chained audit log (`gov/log.py`), the approval queue records
(`gov/approvals.py`), the safeguard assessment report (`gov/safeguard_benchmark.py`),
citation-provenance checkpoints (`gov/eval_integrity.py`), the KMS runbook
(`docs/KEY_CUSTODY_RUNBOOK.md`), and the §5 bundle transport (`gov/safeguard_bundle.py`)
each prove one facet. There is no single, signed, auditor-readable artifact
whose verification an outsider can run without the repo installed and without
trusting the deployer. Without it, the "sell evidence" bet has no product to
sell.

## 2. Solution

A v1 **evidence bundle**: one deterministic directory per export containing a
canonical payload (`evidence.json`) with the seven required sections, a seal
manifest (`manifest.json`) binding the payload to the verified hash-chained log
via Merkle inclusion bundles, an operator Ed25519 signature over the payload
digest, and a **standalone verifier CLI** (stdlib-only, no repo install) that
replays the full verification chain with explicit exit codes and a
machine-readable verdict. Export only: no service, no auditor blessing, no
external anchoring in v1.

---

## 3. User Stories

1. As an external auditor, I want a single directory I can verify with one
   command and no repo install, so that I don't have to trust the deployer's
   tooling.
2. As an external auditor, I want every number in the bundle to name the log
   entries it came from, so that I can re-derive claims instead of believing them.
3. As an external auditor, I want the verification procedure to say plainly
   whether authorship was checked (pinned key) or only self-consistency, so
   that I never mistake an intact bundle for the operator's bundle.
4. As a security reviewer, I want tampering (edited/dropped/reordered entries,
   stripped signatures, swapped keys) to fail the bundle closed, so that the
   verification result means something.
5. As the operator, I want bundle generation to refuse when the log chain does
   not verify, so that a broken chain can never produce a signed artifact.
6. As the operator, I want the bundle to name its signing key id and custody
   provider without embedding key material, so that key provenance is auditable.
7. As the operator, I want key rotation to not invalidate old bundles, so that
   historical evidence keeps verifying under the key it was sealed with.
8. As the compliance owner, I want the bundle to embed safeguard-benchmark
   verdicts and citation-provenance outcomes, so that eval integrity is part of
   the evidence story, not a sidecar.
9. As the compliance owner, I want EU AI Act Art. 73-shaped incident material
   to be expressible from the same bundle primitives, so that regulator-shaped
   artifacts are a rendering of evidence, not a separate truth.
10. As the ship coordinator, I want every seam the spec assumes to be marked
    "exists" or "W3 prerequisite", so that the build plan has no hidden work.
11. As a red-team engineer, I want an explicit tamper battery (edit / drop /
    reorder / signature strip / key swap) with MUST-detect criteria, so that
    "trustworthy" is a tested property, not a claim.
12. As the user, I want the spec to state honestly what the bundle does NOT
    prove, so that no sales motion can overclaim it later.

---

## 4. Implementation Decisions

### 4.1 Bundle format

**Transport layout.** Mirror the proven `gov/safeguard_bundle.py` §5 transport —
one directory per export, deterministic (byte-identical for identical inputs),
with the sealed artifacts never rewritten by the assembler. Do not invent a
second layout.

```
<evidence-bundle>/
  VERSION                  bundle format + evidence schema versions
  evidence.json            canonical payload (the seven sections, §4.1.1)
  manifest.json            seal manifest (digest, chain state, inclusion
                           bundles, checkpoints, signing block)
  log_slice.jsonl          the chained audit-log window, entries as stored
  checkpoints.jsonl        signed checkpoint heads covering the window
                           (CT-style STHs; extracted from manifest bundles)
  receipt.json             the bundle's own chained export receipt entry
  keys/operator_ed25519.json   {key_id, public_key_hex} — manifest seal key
  keys/checkpoint_keys.json    [{key_id, public_key_hex}] — checkpoint sig keys
  VERIFY.txt               human-readable verification procedure pointer
  BUNDLE_DIGEST.sha256     transport checksum over (relative path, content)
                           — NOT a signature
```

Rationale for the layout choice: `gov/safeguard_bundle.py` already solved
deterministic assembly, the digest transport check, and the self-asserted-key
honesty problem (F151 — see §4.3). Reusing the pattern keeps one verification
vocabulary across the SAR and the evidence bundle.

**New module (one seam, highest possible):** `gov/evidence_bundle.py`
(builder + assembler + seal). It composes existing seams — `gov.log`
(chain/inclusion), `gov.signing` (Signer), the sealing pattern from
`gov/evidence_exports.py::IncidentReport.seal` and
`gov/safeguard_benchmark.py::SafeguardAssessment.seal` — and does not
reimplement chain mechanics. Preferred existing seams in order:
`gov.log.verify_chain` / `prove_inclusion` / `signed_checkpoints`;
`gov.approvals` record payloads; `gov.policy` / `gov/executor.py`
`policy_loaded` events; `gov.eval_integrity` checkpoint events;
`gov/safeguard_benchmark.py` seal manifest; `gov/kms*.py` `describe_key`.

**Canonical serialization** (no exceptions): `json.dumps(obj, sort_keys=True,
ensure_ascii=True, separators=(",", ":"))` encoded UTF-8 — the same canonical
form as `IncidentReport.canonical` (`gov/evidence_exports.py`) and
`_canonical_body` (`gov/signing.py`). `BUNDLE_DIGEST.sha256` is computed over
relative paths + file contents exactly as `compute_bundle_digest` does in
`gov/safeguard_bundle.py`.

**Deterministic identity:** `bundle_id = "EVB-" + sha256(canonical(evidence
without bundle_id))[:16]` — mirrors the SAR's deterministic `report_id`
(`docs/safeguard-benchmark-spec.md` §2). Two exports of identical inputs are
byte-identical, which is what makes bundles from different deployments
comparable (the spec's fragmentation argument as a product property).

#### 4.1.1 Payload sections (`evidence.json`)

All fields carry provenance per the honesty contract. `null` +
`operator_must_supply: true` wherever the log cannot supply a value — never
synthesized, never defaulted.

1. **`bundle_meta`.** `bundle_version` (`"evidence-bundle/1.0"`),
   `evidence_schema_version` (`"evidence-schema/1.0"` — bumped if the schema
   ever changes; never silently re-interpreted), `generator`
   (`gov/evidence_bundle.py` + version), `exported_at` (UTC ISO-8601),
   `operator_id` (provenance: `operator_must_supply`), `window`
   (`from_seq`, `to_seq` — default: the full verified chain), `bundle_id`
   (deterministic, above).
2. **`log_slice`.** The chained window itself: `entry_count`, `from_seq`,
   `to_seq`, `tip_hash`, plus per-entry inclusion coverage —
   `{"seq", "hash", "has_bundle": bool, "unavailable_reason": str|null}`.
   (Full entry dicts ship in `log_slice.jsonl`; the payload section carries
   the coverage accounting.) Inclusion bundles require Ed25519-signed (v2)
   checkpoints — exactly the `evidence_exports.seal` rule: a log with
   HMAC-only checkpoints yields entries that name their
   `unavailable_reason` instead of implying coverage. This is a deployment
   property, not a generator defect.
3. **`policy`.** `policy_version` (from `gov/policy.py` config `"version"`,
   `"unversioned"` if absent), `policy_hash`, `policy_path`, `pinned`
   (whether `GOV_POLICY_HASH` was set), sourced from the latest
   `policy_loaded` event in the window (the `gov/executor.py` record shape:
   `policy_id: "policy-pin"`, `policy_hash`, `pinned`, `reason`).
   Plus `policy_change_events`: every `policy_pin_mismatch` /
   `policy_pin_absent` event in the window, with seq/hash. If no
   `policy_loaded` event exists in the window, `policy_version` is `null`
   with `operator_must_supply: true` — the bundle never guesses which policy
   governed the window.
4. **`decisions`.** Decision records of the window: every entry carrying a
   `decision` field (executor records decisions on `tool_call` entries;
   construction-seam and capability-gate decisions carry `policy_id`
   labels), summarized as `by_event: {event: count}` with per-entry
   `(seq, hash)` references, and the full entries available in
   `log_slice.jsonl`. Verdict vocabulary is the log's own (`stopped`,
   `break`, `error`, policy decisions as recorded) — the bundle does not
   re-grade.
5. **`approvals`.** Approval records: `approval_decision`,
   `approval_decision_attempt`, `approval_late_decision`,
   `approval_break_glass`, `approval_batch_abort`, `ticket_consumed`,
   `quorum_opened`, `post_review_resolved` (the event vocabulary of
   `gov/approvals.py`), each with `(seq, hash, record digest)`.
   **Honesty note:** approval queue MACs (`approval_digest_ok` /
   `record_digest` in `gov/approvals.py`) are keyed by the queue's own keys;
   a third-party verifier without those keys cannot re-run them — the
   approvals' integrity in the bundle flows from the chained log +
   inclusion bundles, not from re-verified queue MACs. The verifier checks
   presence, shape, and chain binding; it does not claim to re-authenticate
   the queue's internal digests.
6. **`citations`.** Citation-provenance verdicts: the chained
   `eval_integrity` / `signal: "citation_check_completed"` records from
   `gov/eval_integrity.py::accept_report` (`n_citations`,
   `n_self_planted`, `verdict_counts`, `accepted`), plus
   `self_planted_citation` violation records from
   `report_eval_integrity_violation`. Per-URL verdict detail is whatever the
   log captured — the bundle derives verdicts from the chained checkpoint
   records only (the verdict vocabulary is `SELF_PLANTED` / `UNKNOWN` /
   `INDEPENDENT` from `gov/citation_provenance.py::verify_citation`;
   `UNKNOWN` is the honest default and is never presented as a clean bill).
   **Honesty note:** `accept_report` is opt-in — "nothing in gov/ routes
   through this function unless the deployment calls it" (F141 closure).
   The bundle reports which eval sessions have citation checkpoints and
   which do not; absence of a checkpoint is evidence of absence of the
   check, not evidence of clean citations.
7. **`benchmark`.** Safeguard-benchmark results: the v1 bundle embeds the
   `SafeguardAssessment` **seal manifest's verdict section** — `schema_version`
   (`safeguard-assessment/1.0`), `report_id`, `aggregate_verdict`
   (`SUFFICIENT` / `INSUFFICIENT`), per-category `{stop_rate,
   severity_weight, meets_threshold}`, the published `thresholds`, and the
   taxonomy label (`provisional-v1`, from `gov/safeguard_taxonomy.py`).
   The full SAR travels as its own §5 bundle when present; the evidence
   bundle cross-references it by `report_id` and carries the seal digest.
   The `safeguard_benchmark_sealed` receipt must be in the window for the
   section to be "sealed"; otherwise the section is marked
   `seal_status: "unsealed"` explicitly.
8. **`kms_attestation`.** Key-custody attestation — provider name (the
   `KeyProvider.provider_name`: `"env"`, `"file"`, `"envelope-kms"`; and the
   KMS provider behind it, e.g. `"vault"` from
   `gov/kms_vault.py::VaultKmsProvider`), the active `key_id`, the key
   epoch, and the `describe_key` output (`KeyDescription`: key_id,
   provider, enabled). **No key material ever enters the bundle.**
   The attestation is an operator-signed statement ("the log window
   `[from_seq, to_seq]` was keyed by provider P, key id K, epoch E,
   provisioned per `docs/KEY_CUSTODY_RUNBOOK.md`"), signed with the same
   operator key that signs the manifest. It is a **claim about the
   provisioning story, not cryptographic proof of hardware custody** —
   see §7 (honest boundaries).
9. **`retention_manifest`.** Operator-supplied retention record: the
   retention policy in force, the window's coverage (e.g. "window covers
   the full retention period" or explicit gaps), and archive locations.
   **W3 prerequisite (P3):** `gov/retain.py` does not exist (SHIP_PLAN §1.4
   names retention as operator-owned). For v1 the manifest is an
   operator-supplied JSON document with a fixed schema; the verifier
   checks presence and schema only, never truth. If no manifest is
   supplied, the section is `null` with `operator_must_supply: true` and
   the bundle is still sealable — the absence is labeled, not hidden.

#### 4.1.2 Manifest (`manifest.json`)

Mirrors `IncidentReport.seal` / `SafeguardAssessment.seal` exactly:

- `kind: "evidence_bundle_manifest"`, `generator`, `generator_version`,
  `bundle_id`, `bundle_version`.
- `export_sha256`: sha256 of canonical `evidence.json`.
- `window`: `from_seq`, `to_seq`, `tip_hash`, `entry_count`.
- `chain_verified`: result of `gov.log.verify_chain` on the source log at
  build time (plus `chain_broken_seq`); the builder **refuses to seal**
  when the chain does not verify — same as `evidence_exports.seal`.
- `inclusion_bundles`: per-entry `prove_inclusion` bundles (with
  `unavailable_reason` where signed checkpoints are absent);
  `inclusion_coverage: {entries, with_bundle, note}`.
- `checkpoints`: the signed heads covering the window (shipped as
  `checkpoints.jsonl`).
- `export_receipt`: the chained receipt of this export
  (`event: "evidence_bundle_sealed"`, `export_sha256`, digest prefix) —
  appended via the existing `log_export_receipt` pattern
  (`gov/evidence_exports.py`), so the export itself is auditable in the
   same chain. The receipt's `prev_hash` equals the slice tip hash; see
   §4.3 V12.
- `signing`: `{scheme: "ed25519", key_id, public_key_hex,
  signature_hex, signed_bytes: "domain-separated manifest digest",
  domain: "evidence-bundle/v1"}`. **There is no `"none"` option in v1** —
  an unsigned evidence bundle is not an evidence bundle (unlike the
  incident-report export, which tolerates HMAC-anchored-only manifests).
  A missing/invalid signature fails the bundle closed.

### 4.2 Signing

**What signs.** The operator's Ed25519 key via the existing
`gov.signing.Signer` interface — specifically an `Ed25519Signer` built
from the seed resolved by `gov/anchorer.py::resolve_anchor_key`
(precedence: explicit hex seed > `GOV_ANCHOR_KEY` > `GOV_ANCHOR_KEY_FILE`
with 0600 enforced by `gov/keyfiles.py::require_private_key_file`;
unconfigured raises loudly, never falls back). This is the only existing
operator-held Ed25519 seed seam with a fail-closed provisioning idiom,
and the KEY_CUSTODY runbook (§0) already treats the anchor seed as the
operator's signature key domain.

**Domain separation (decision).** The anchor seed also signs transparency
anchors. Signing two artifact classes with one seed is a hygiene smell, so
the evidence signature is computed over a domain-separated body:
`b"evidence-bundle/v1\x00" + export_sha256_bytes`. If the coordinator
prefers a distinct key domain (`GOV_EVIDENCE_KEY` via the same
`resolve_anchor_key` idiom), the manifest's `domain` field and key-id
accounting already support it — this is the one signing decision left to
the coordinator (see W3 prerequisite P5), and either choice keeps the
verifier unchanged.

**Algorithm.** Ed25519, `gov/ed25519.py` (vendored RFC 8032; `verify`
never raises on malformed input). 64-byte signatures, hex-encoded in the
manifest. Wire format is standard, so signatures verify across
implementations.

**What the signature covers.** The domain-separated `export_sha256` of
canonical `evidence.json` — which transitively commits to every section,
the window bounds, the tip hash, and the inclusion-coverage accounting —
plus the manifest's own `chain_verified` and checkpoint list via their
inclusion in the signed bytes: the signed body is
`domain || export_sha256 || canonical({"window", "chain_verified",
"checkpoints_digest"})`, where `checkpoints_digest` is sha256 over the
canonical checkpoint heads. A signature that covered only the payload
digest would let an attacker swap the chain-verification claim; the spec
binds the claim into the signature.

**Key rotation.** The manifest records `key_id` =
`ed25519_key_id(public_key)` = `sha256(pub).hexdigest()[:16]` (the same
key-id convention as `gov/signing.py` and `gov/keys.py`). Rotation:
publish the new public key out-of-band; old bundles keep verifying under
the key shipped in their own `keys/` envelope. The verifier **pins by
full public key, never by key_id alone** (F151 lesson: pinning by key_id
checks the label; the bundled key for that id is still self-asserted).
The verifier accepts a rotation history (`--pin-operator-pubkey` may
repeat); a bundle verifies under whichever pinned key matches its
envelope. Threshold (k-of-n) checkpoint signing (`gov/signing.py`
`verify_threshold` / A5 roster) is supported in the envelope for the
checkpoint keys; the operator's manifest signature is single-key in v1 —
multi-operator manifest signing is deferred to v2.

**What signing does NOT do.** It does not prove the log's HMAC key
custody (that's the `kms_attestation` claim, §4.1.1(8)); it does not
time-stamp (v1 has no trusted timestamp authority — see §7); it does not
replace the hash chain (a valid signature over a forged-but-consistent
payload is still detected by the chain/inclusion checks).

### 4.3 Verifier

**Form.** A single-file CLI, `tools/evidence-verify` (shipped as a
`pyproject.toml` entry point, e.g. `gov-evidence-verify`), **stdlib-only,
runnable with the repo NOT installed** — the auditor runs
`python3 evidence-verify <bundle-dir>` from any machine. Prior art:
`gov/verify.py` (`python -m gov.verify`) is the offline-log-verifier
precedent, but it imports `gov.*` and therefore cannot serve auditors;
the evidence verifier must not.

**W3 prerequisite (P1):** the verifier needs Ed25519 verification plus
Merkle inclusion-bundle verification (`verify_inclusion_bundle` path in
`gov/log.py`) without importing `gov`. `gov/ed25519.py` is pure Python
and vendoring-friendly (218 lines, no dependencies); the extraction of
`ed25519.verify` + the minimal inclusion-verify logic into the
single-file verifier does not exist yet and must be built and tested
against the RFC 8032 vectors (`tests/test_crypto_gov.py`) in W3.

**Inputs.**
- `bundle_dir` (positional): the bundle directory — the SOLE data input
  (same contract as `bundle_verify` in `gov/safeguard_bundle.py`).
- `--pin-operator-pubkey HEX` (repeatable): the operator's Ed25519 public
  key(s), bound out-of-band (published key directory, transparency log,
  or authenticated delivery channel). **Pin the full public key, not the
  key_id** — F151.
- `--pin-checkpoint-key-ids` (optional, repeatable): expected checkpoint
  signer key ids; when given, the checkpoint keys in the envelope must
  match exactly.
- `--log PATH` (optional): the source audit log, if the auditor has a
  copy. Enables the receipt-existence cross-check (V12b); without it the
  receipt is checked for self-consistency and tip linkage only.
- `--format json|text` (default `text` for humans; `json` for pipelines).

**Verification steps, in order** (any failure fails closed — later steps
do not run against a bundle that failed an earlier one, except where
noted):

- **V1 — version gate.** `VERSION` parses; `bundle_version` and
  `evidence_schema_version` are recognized. Foreign versions fail closed
  — the schema is never silently re-interpreted (same rule as
  `bundle_verify` B1).
- **V2 — required files.** All nine layout entries present (§4.1).
- **V3 — transport digest.** Recompute `BUNDLE_DIGEST.sha256` over
  relative paths + contents; must equal the stored value (tamper-evidence
  for the directory itself).
- **V4 — payload digest.** Recompute `sha256(canonical(evidence.json))`;
  must equal `manifest.export_sha256`.
- **V5 — key envelope.** `keys/operator_ed25519.json` and
  `keys/checkpoint_keys.json` present and well-formed: 32-byte pubkeys,
  `key_id == sha256(pub).hexdigest()[:16]` for every key (the envelope
  cannot mislabel its own keys).
- **V6 — authorship pinning.** If `--pin-operator-pubkey` given: the
  envelope's operator pubkey must byte-equal a pinned key, else FAIL
  closed (and §V7+ do not run against the wrong operator's keys — the
  F151 rule). If no pin given: the check is recorded as
  `not_applicable` and the final verdict is capped at
  `SELF_CONSISTENT` (exit 2) — an unpinned PASS means "internally intact",
  never "the operator's".
- **V7 — operator signature.** Ed25519-verify the manifest signature over
  the domain-separated body (`domain || export_sha256 || window digest`,
  §4.2) with the envelope's operator pubkey.
- **V8 — checkpoint signatures.** Every checkpoint head in
  `checkpoints.jsonl` verifies against the bundled checkpoint keys
  (single-key or A5 k-of-n roster threshold via the vendored
  `verify_threshold` path); `require_signed`-style: any unsigned head
  fails closed.
- **V9 — log-slice integrity.** (a) `log_slice.jsonl` entries have
  contiguous seqs `from_seq..to_seq` matching the manifest window;
  (b) `prev_hash` linkage is consistent across the slice (each entry's
  `prev_hash` equals the previous entry's `hash`, anchored at the slice
  start); (c) every entry's inclusion bundle verifies
  (`verify_inclusion_bundle` path) against a V8-verified checkpoint head.
  Entries without bundles are tolerated only where the manifest names an
  `unavailable_reason`, and then the final verdict notes reduced coverage
  explicitly.
- **V10 — manifest completeness.** Every payload section named in
  `evidence.json` is accounted in the manifest's coverage records;
  `entry_count` matches the slice; inclusion coverage math is consistent
  (`with_bundle` ≤ `entries`); no section claims seqs outside the window.
- **V11 — policy-version consistency.** The payload `policy` section's
  `(policy_version, policy_hash, pinned)` equals the values in the
  slice's `policy_loaded` events; no `policy_pin_mismatch` event appears
  in the window without being listed in `policy_change_events`; if the
  policy section is `operator_must_supply`-null, the verdict notes
  "policy unattested" rather than passing silently.
- **V12 — export receipt.** (a) `receipt.json`'s `prev_hash` equals the
  slice tip hash and its `export_sha256` equals the manifest digest —
  the receipt chains onto the exported window. (b, only with `--log`):
  the receipt entry exists in the provided log's chain at the recorded
  seq (re-run `verify_chain`-equivalent on the copy).
- **V13 — citation/approval cross-consistency.** Every
  `citation_check_completed` record with `accepted: true` has
  `n_self_planted == 0`; every `verdict_counts` sums to `n_citations`;
  approval records' shapes match the `gov/approvals.py` vocabulary
  (unknown event names are flagged, not coerced).

**Exit codes.**
- `0` — `VERIFIED`: all checks pass, authorship pinned, signature valid.
- `1` — `FAILED`: any integrity, signature, pinning, or consistency
  check failed. The JSON/text output names the first failing check and
  lists all failures found.
- `2` — `SELF_CONSISTENT`: all checks pass but authorship was not pinned
  (no `--pin-operator-pubkey`, or manifest signed `scheme: "none"` —
  which cannot occur for v1 bundles but is handled explicitly). The
  output states in plain language: "this bundle is internally intact;
  it is NOT established as the operator's."
- `3` — usage/config error (bad bundle path, malformed flags, unreadable
  files). Never a verdict.

**Output format.**
- Machine-readable (`--format json`): `{"verdict",
  "bundle_id", "exit_code", "authorship": {"pinned": bool,
  "key_id": str|null}, "checks": [{"id": "V1", "name": ...,
  "ok": bool, "status": "pass|fail|not_applicable", "detail": str}],
  "failures": [...], "coverage": {"entries": n, "with_bundle": m},
  "what_this_does_not_prove": [...]}` — the honesty footer is part of
  the JSON, not just the text.
- Human summary (`text`): the VERIFY.txt procedure pointer, one line per
  check (PASS/FAIL/N-A with detail), then a fixed "What this proves /
  what this does not prove" block drawn from §7. The summary never
  prints `VERIFIED` for an unpinned run.

---

## 5. Testing Decisions

**What makes a good test here.** Only external behavior at the public
seams: `build()` output shape and honesty-contract properties,
`seal()` refusal on unverifiable chains, the assembler's byte-determinism,
and the standalone verifier's verdicts/exit codes on crafted bundles.
Never test implementation details (canonical-string internals, private
helpers). Deterministic, synthetic, $0 — the existing corpus's
conventions (`TMPDIR=/tmp/gov-run`, venv `~/workspace/.gov-venv`,
`tests/run_tests.py` canonical gate).

**Modules under test.** The new `gov/evidence_bundle.py` (build/seal/
assemble), the standalone `tools/evidence-verify` (verdict matrix), and
the receipt seam (`evidence_bundle_sealed`). Prior art:
`tests/test_evidence_exports.py` (build/seal honesty-contract tests),
`tests/test_safeguard_bundle.py` (determinism + `bundle_verify` layers),
`tests/test_w82_evidence_demo.py`, and the F-break battery convention
(`evals/f*_*.py`: pre-fix BREAK → post-fix CLOSED/CONTROL, deterministic).

**Red-team acceptance battery (MUST-detect).** W3 writes a break battery
in the `evals/f*_*.py` convention that crafts bundles (or mutates genuine
ones) and asserts the verifier's verdict. Every case below MUST be
detected — i.e. the verifier exits non-zero (1, or 2-with-explicit-cap
where noted), never 0:

- **T1 — log edit.** Flip one byte in a `log_slice.jsonl` entry's payload.
  → inclusion bundle fails (leaf hash changes); V9 fails.
- **T2 — record drop.** Remove one entry from the slice. → seq gap +
  `prev_hash` linkage break + count mismatch; V9/V10 fail.
- **T3 — reorder.** Swap two adjacent entries. → `prev_hash` linkage
  breaks (order is committed by the chain); V9 fails.
- **T4 — signature strip.** Delete the `signing` block or replace the
  operator pubkey with garbage. → V5/V7 fail closed; a bundle with
  `scheme: "none"` can never reach `VERIFIED`.
- **T5 — key swap.** Replace the envelope operator key with the attacker's
  key and re-sign. → pinned verification (V6) fails closed; the attacker's
  bundle verifies at most `SELF_CONSISTENT` unpinned — the F151 property.
  Companion control: the genuine bundle with the genuine pin exits 0.
- **T6 — payload digest tamper.** Edit `evidence.json` (e.g. inflate an
  approval count). → V4 `export_sha256` mismatch.
- **T7 — checkpoint forgery.** Forge a checkpoint head binding the mutated
  slice. → V8 Ed25519 failure against the bundled checkpoint keys;
  inclusion bundles referencing the forged head fail.
- **T8 — truncation / window shift.** Cut the slice tail or move
  `from_seq`. → receipt `prev_hash` ≠ tip hash (V12); inclusion coverage
  inconsistent (V10).
- **T9 — authorship confusion (unpinned).** Present a forger's
  self-sealed bundle to the verifier without pins. → MUST exit 2
  (`SELF_CONSISTENT`) with the explicit not-operator's-baggage language;
  MUST NOT exit 0. (F151 regression.)
- **T10 — policy substitution.** Swap the policy section's hash to a
  different policy's. → V11 mismatch against the slice's
  `policy_loaded` events.

**Benign controls.** A genuine bundle verifies exit 0 (pinned) and exit 2
(unpinned, with the capped language); a bundle built from a log with
HMAC-only checkpoints verifies with explicitly reduced inclusion coverage
(not a failure); a bundle whose SAR section is `unsealed` verifies with
the section labeled, not silently dropped.

**Gates.** Unit tests for the new module live in `tests/` and run under the
canonical gate (`tests/run_tests.py`, venv `~/workspace/.gov-venv`); the
tamper battery follows the `evals/f*_closure.py` convention (deterministic,
break-first) and must be green before the W3 milestone closes. Red halts W3
per the ship plan's gate protocol. No HIGH/CRITICAL found in the window
ships without closure.

---

## 6. Out of Scope

- **Auditor certification claims.** The bundle is evidence, not a
  certificate. Nothing in v1 claims any auditor, regulator, safety
  institute, or lab accepts it — the claim is only that it is shaped to
  be ingestible (same stance as the safeguard benchmark spec §5).
- **Live Rekor/Sigstore anchoring.** v1 ships hash-chained + checkpointed
  logs with the `FakeTransparencyLog` seam documented
  (`gov/anchor.py`); external anchoring is a v2 milestone per SHIP_PLAN
  §2 OUT. The manifest records that no external anchor exists — it does
  not imply one.
- **Legal or regulatory determinations.** Incident classification under
  EU AI Act Art. 73 (or any regime) stays `operator_must_supply`, exactly
  as in `gov/evidence_exports.py`. The bundle carries the machine-readable
  severity grades (S1–S4, `provisional-v1` taxonomy from
  `gov/safeguard_taxonomy.py`); mapping them to filing obligations is the
  operator's legal determination.
- **Completeness of the export against exporter misbehavior.** The K-060
  honest scope applies (`gov/log.py::export_bundle`): the bundle proves
  authenticity of INCLUDED entries, not that the exporter omitted nothing.
  Protection against a misbehaving exporter is the transparency-anchor
  story (K-049, v2), not this bundle's.
- **Multi-operator manifest signing / threshold operator signatures.**
  The envelope supports A5 rosters for checkpoint keys; the manifest
  signature is single-operator in v1.
- **Metering, services, or managed pipeline.** Export only. v1 meters
  nothing (SHIP_PLAN §2 OUT).
- **Re-verifying approval queue MACs.** See §4.1.1(5): third-party
  re-authentication of `gov/approvals.py` internal digests needs the
  queue keys and is out of scope; chain + inclusion binding is the v1
  integrity story for approvals.
- **New enforcement primitives / new incident classes.** The core is in
  sustaining/break-fix per the B5 cap; the bundle consumes the log as it
  is.

---

## 7. Honest Boundaries — what the bundle does NOT prove

This section is normative: the verifier's human summary and JSON footer
must carry these, and no sales or docs copy may contradict them.

1. **Recorded events, not unrecorded ones.** The bundle attests to what
   the log recorded in the window. Anything that happened off-log — a
   tool call the executor never saw, an approval granted outside the
   queue, an unregistered agent (`gov/discovery.py` candidates the
   deployment never inventoried) — is not in the bundle and the bundle
   does not claim otherwise.
2. **Integrity ≠ truth (garbage-in limits).** If entries were recorded
   under a compromised HMAC key, or the deployment's policy was wrong,
   the bundle faithfully attests to false or misguided events. The
   bundle proves the record is intact and attributable to the key
   holders; it does not prove the record is true.
3. **Key custody is claimed, not proven.** The `kms_attestation` is an
   operator-signed statement about the provisioning story (provider,
   key id, epoch, runbook reference). It is not cryptographic proof of
   HSM custody, and in v1 the operator signing key itself is a
   software-file key (0600) unless the deployment did better — the
   bundle says which.
4. **Timestamps are operator wall-clock.** Entry `ts` values and
   `exported_at` come from the operator's clock (`gov/log.py::_utcnow`).
   v1 has no trusted timestamp authority and no external anchor
   (FakeTransparencyLog only) — the bundle does not claim independent
   time attestation.
5. **Unpinned bundles prove self-consistency only.** F151 stands: a
   forger's self-sealed bundle is internally intact. Authorship requires
   the out-of-band key pin; the verifier's exit-2 path exists precisely
   to make this unmissable.
6. **UNKNOWN citations are not clean citations.** The citation section
   reports the log's verdicts; `UNKNOWN` (the default when no plant
   record matches) is labeled as "no evidence either way", never as
   exoneration. Sessions without `accept_report` checkpoints are listed
   as unchecked.
7. **Retention and operator-supplied fields are assertions.** The
   retention manifest, `operator_id`, and any `operator_must_supply`
   field are the operator's statements, carried with provenance labeled
   as such — the verifier checks their presence and schema, not their
   truth.
8. **Single-tenant scope.** The bundle describes one deployment's log.
   Cross-deployment or cross-tenant claims are out of scope (SHIP_PLAN
   v1 is single-tenant by decision).
9. **Thresholds and taxonomy are ours.** Safeguard sufficiency is graded
   against thresholds declared in the report; severity bands are the
   provisional taxonomy (`gov/safeguard_taxonomy.py`, explicitly
   provisional — "no agreed incident severity levels exist anywhere
   yet"). The bundle versions both so future regimes can map them,
   without implying agreement.

---

## 8. Further Notes

### 8.1 W3 build prerequisites (seams that do not exist yet)

Every item below was checked against the current tree; none is assumed.

- **P1 — standalone verifier.** `gov/verify.py` imports `gov.*` and
  requires the repo installed; it cannot serve auditors. W3 must build
  the stdlib-only single-file verifier, vendoring `ed25519.verify`
  (from `gov/ed25519.py`, pure Python, RFC 8032) plus the minimal
  Merkle inclusion-bundle verification path (the
  `verify_inclusion_bundle` logic in `gov/log.py`). Test the vendored
  crypto against the RFC 8032 vectors (`tests/test_crypto_gov.py`).
- **P2 — custody attestation record.** No attestation artifact exists:
  `VaultKmsProvider.describe_key` returns `(key_id, provider, enabled)`
  only, and nothing binds a custody statement to a bundle. W3 needs the
  attestation format + operator signing of it (§4.1.1(8)).
- **P3 — retention manifest.** `gov/retain.py` does not exist (SHIP_PLAN
  §1.4: retention is operator-owned). W3 decision: ship the
  operator-supplied JSON schema in v1 (spec §4.1.1(9) already allows
  this), or defer the section. Either way the absence must stay labeled.
- **P4 — citation verdict export.** `check_citations` returns in-memory
  verdicts; only the `accept_report` chained checkpoints
  (`citation_check_completed` records) and `self_planted_citation`
  violation records persist. The bundle derives per-URL detail solely
  from those log records — no separate collector seam exists, and none
  is proposed: the log is the source of truth.
- **P5 — evidence signing key domain (coordinator decision).** The spec
  reuses `gov/anchorer.py::resolve_anchor_key` (`GOV_ANCHOR_KEY` /
  `GOV_ANCHOR_KEY_FILE`) with domain separation (`evidence-bundle/v1`
  prefix in the signed body). If the coordinator wants a distinct
  `GOV_EVIDENCE_KEY` domain instead, it follows the same idiom; the
  verifier is unchanged either way.
- **P6 — KMS-backed Ed25519 signing.** `VaultKmsProvider` wraps data
  keys only; no "sign via KMS transit" adapter exists. In v1 the
  operator key is software-file custody (0600, per `gov/keyfiles.py`) —
  stated in the bundle, not hidden.
- **P7 — bundle export receipt.** `log_export_receipt` exists for
  incident reports (`gov/evidence_exports.py`); the evidence bundle
  needs its own `evidence_bundle_sealed` receipt on the same pattern
  (small new seam, highest point: reuse the pattern, new event name).

### 8.2 What could not be grounded

- **Auditor acceptance.** No auditor has reviewed any bundle format in
  this repo; "ingestible" is a shape claim, verified only against our
  own verifier and the safeguard spec's §4 procedure. Flagged, not
  assumed.
- **Real-Vault KMS posture at seal time.** The Vault adapter is validated
  against a live dev server (`tests/test_kms_vault_live.py`, 20/20),
  but production Vault provisioning steps in `docs/KEY_CUSTODY_RUNBOOK.md`
  are marked UNTESTED where not exercised. The attestation must reflect
  the deployment's actual tested posture.
- **Thresholds for "sufficient".** The SAR's sufficiency thresholds are
  our declared policy (`DEFAULT_THRESHOLDS`), not an agreed bar — the
  bundle carries them so a consumer can re-grade, not so the grade is
  authoritative.

### 8.3 Relation to existing artifacts

- `docs/safeguard-benchmark-spec.md` §4/§5: the SAR's third-party
  verification procedure and §5 transport are the direct ancestors of
  this spec's verifier and layout; the evidence bundle generalizes the
  §5 bundle from "one assessment" to "the deployment's governed window".
- `gov/evidence_exports.py`: the Art. 73 incident-report exporter remains
  the regulator-shaped rendering; the evidence bundle can carry an
  incident report's sealed manifest as an additional section in v2 —
  v1 does not duplicate it.
- `demo/make_report.py`: the human-readable report precedent for the
  verifier's text summary.
