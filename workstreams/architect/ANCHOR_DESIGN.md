# Haber–Stornetta Anchoring for the Audit Chain — Wave-72 Design

**Status:** design lane (wave-72). Implements the founder-authorized anchor half of the
evidence bet.

## 0. The guarantee (load-bearing sentence)

> "no undetected rewrite of history prior to the last anchor" — history after the last
> anchor is soft, and the anchor cadence is the security parameter.

Every mechanism below is graded against that sentence. Anything that weakens it is a
finding; anything that restates it is not.

## 1. The gap (precise)

The HMAC-SHA256 chain proves ordering and outsider tamper-evidence, but:

1. **The key-holder can rewrite from genesis** — with the HMAC key, the whole chain
   (plus checkpoints, plus per-entry Ed25519 sigs if the signer key is also held) can be
   reforged. Nothing outside the operator's trust domain contradicts the forgery.
2. **No wall-clock binding** — entries carry `ts`, but no external party ever attests
   *when* a chain head existed. A backdated rewrite is undetectable.

The 1991 insight (Haber–Stornetta, "How to Time-Stamp a Digital Document," *Journal of
Cryptology* 1991): periodically publish the chain head to an **external witness the
operator cannot rewrite**. After that, any rewrite of pre-anchor history contradicts a
third party's signed, timestamped, Merkle-committed record.

`gov/anchor.py` (K-049, earlier wave) anchors v2 *signed checkpoints* into a transparency
log and refuses equivocation — but it embeds the whole checkpoint, has no epoch concept,
no checkpoint policy, no async/failure semantics, no receipt chaining, and its external
side is design-only. This wave builds the Haber–Stornetta half as specified below; the
K-049 module is left untouched (its `FakeTransparencyLog` keeps its own tests).

## 2. Backend decision

**Chosen: (a) Ed25519 anchor-signing key + Sigstore Rekor (v1 API).**

- Rekor is FREE, permissionless, and reachable from this environment — verified
  2026-09-22: `GET https://rekor.sigstore.dev/api/v1/log/publicKey` → HTTP 200 with the
  production shard's ECDSA P-256 public key (see §8 for the pinned key and log id).
  No new dependencies: stdlib `urllib` only.
- hashedrekord entries need a signature; we sign with **Ed25519** via the existing
  pure-Python `gov/ed25519.py`. This advances the standing Ed25519 roadmap item
  (MEMORY.md): the anchor-signing key is the second production Ed25519 key in the
  system after the checkpoint signer.
- **(b) RFC 3161 TSA rejected:** a TSA gives trusted time but no *public* commitment —
  the operator picks (or runs) the TSA, so a key-holder + cooperative TSA rewinds time
  silently. Rekor gives public auditability *and* witness time in one primitive.
  Auditors knowing RFC 3161 does not stop operator rewrite; a public log does.
- **(c) Local append-only anchor log** ships as `LocalAnchorLog` behind the same
  interface for airgapped deployments — **honestly labeled NOT a witness** (same trust
  domain as the operator; it proves the anchor *format* and the verification *path*,
  nothing more). It is the fallback, not the story.

The deterministic suite uses `FakeWitness` (in-process, deterministic clock); no
network in tests. **The REST mapping was NOT validated against live Rekor**:
no `POST /api/v1/log/entries` was ever submitted from this environment, and
no Rekor entry UUID for an anchor statement exists. What actually validated
the mapping:

1. The pinned-key GET above (reachability + the production shard's key and
   log-id binding) — re-verified at wave-72 closeout (2026-09-22): the live
   key still matches the pin byte-for-byte and `sha256(DER)` still equals
   the published log id.
2. The hashedrekord 0.0.1 envelope shape read from the Rekor v1 API
   documentation — request: `kind` / `apiVersion` / `spec.signature.content`
   / `spec.signature.publicKey.content` / `spec.data.hash.{algorithm,value}`;
   response: uuid-keyed entry carrying `body` (base64 canonical entry),
   `integratedTime`, `logIndex`, `logID`, and
   `verification.{inclusionProof,signedEntryTimestamp}` (recorded in
   `research/intake-wave72-2026-09-22.md`).
3. The recording-transport test (`test_rekor_outbound_bytes_are_hash_only`),
   which intercepts the exact outbound bytes and pins them to that schema
   (hash + digest signature + pubkey only — the privacy pin).

A live submission is the remaining gap: until one succeeds, `RekorBackend`'s
wire path is schema-conformant by construction and by test, not by live
exercise. (The previous revision of this paragraph claimed "exactly one live
Rekor submission validates the REST mapping" — that was false; corrected at
closeout. A faked validation claim is worse than an honest gap.)

**Positioning (2026-09-22):** Rekor anchoring is table stakes in our niche now —
authensor and trust_chain both ship it — so no differentiation is claimed on the anchor
mechanism itself; the graded claims are the composed implementation, the adversarial
battery, and residuals honesty.

## 3. Design answers

### (a) Epoch binding

**What "epoch" means:** a checkpoint-bounded segment of the chain —
entries `(prev_close_seq, close_seq]`. `epoch_id = "e%08d" % first_seq`, i.e. the seq of
the epoch's first entry. Derivable, unique, monotonic, no extra state file.

**Field layout (entry):** new reserved chain field, stamped by `ActionLog.append`:

```json
{"seq": 123, "ts": "2026-09-22T18:00:00+00:00", "epoch_id": "e00000123",
 "prev_hash": "…", "key_epoch": "…", "format_version": 1, …event fields…, "hash": "…"}
```

Reserved like `seq`/`ts`/`prev_hash`/`key_epoch`: caller-supplied `epoch_id` is
overwritten, never trusted. `ActionLog.close_epoch()` closes at the tail and advances
the in-memory id; on reopen the id is derived from the tail entry (a close that was
never submitted is forgotten — harmless, see §3f).

**Canonicalization:** unchanged `_canonical` (`sort_keys=True`, `separators=(",",":")`,
`ensure_ascii=True`). `epoch_id` is included in the canonical payload whenever present —
so the HMAC input is `key_epoch || prev_mac || canonical_json(…epoch_id…)` and
backdating / reordering / cross-epoch moves without the key break verification.
Legacy entries without `epoch_id` canonicalize byte-identically (no format bump, old
logs verify unchanged — the wave-49/50 lesson: no legitimate-behavior breakage).

**Checkpoint binding (deliberately NOT in `_checkpoint_mac`):** changing the checkpoint
MAC input would break verification of pre-existing checkpoints. Instead the epoch binds
at three points that need no MAC-format change: (1) every entry's HMAC binds
`epoch_id`; (2) the anchor *statement* (§3c) binds
`(epoch_id, seq, start_seq, head_hash, merkle_root, epoch wall window)` under the
anchor Ed25519 key; (3) the auditor replays the chain to `seq` and compares.

### (b) Checkpoint policy

`AnchorPolicy(records_per_epoch=100, seconds_per_epoch=3600, anchor_on_close=True)`.
An epoch closes (and is submitted) when **either** threshold trips; a run close always
anchors the tail epoch.

Tradeoff (this IS the security parameter): shorter cadence ⇒ smaller soft window
(§3f) ⇒ more witness traffic and more permanent public-log entries. Defaults rationale:
100 records ≈ a busy agent-hour of tool calls; 3600 s caps the window for quiet
periods; `anchor_on_close` covers short runs that would otherwise never anchor.
Deployments tune these; the report renders the effective cadence so the residual window
is never implicit.

### (c) `AnchorBackend` interface

```python
class AnchorBackend(abc.ABC):
    def submit(self, anchor_hash: str) -> dict:
        """Submit an anchor hash; return the witness receipt."""

    def verify_receipt(self, receipt: dict, *, anchor_hash: str
                       ) -> tuple[bool, str | None]:
        """(ok, reason): is this receipt a valid witness attestation FOR anchor_hash?"""
```

`submit` takes ONLY the anchor hash — never the statement. The privacy pin is
structural: the signed statement (epoch wall window, key id, pubkey,
checkpoint binding) stays local, chained in the HMAC log's receipt record.
The Rekor envelope's protocol-minimum digest signature and public key come
from key material supplied at `RekorBackend` construction (executor-side
custody), not from the statement. `verify_receipt` takes `anchor_hash` as a
keyword: binding the receipt to the statement hash is what makes check (iii)
expressible.

**Receipt** = inclusion proof + witness time (+ backend identity):

```json
{"backend": "rekor-v1", "url": "https://rekor.sigstore.dev", "uuid": "…", "log_index": 12345, "log_id": "…",
 "anchor_hash": "…", "integrated_time": 1758566400,
 "inclusion_proof": {"hashes": ["…"], "root_hash": "…", "tree_size": 99999,
                     "log_index": 12345},
 "body": "<base64 canonical entry>", "signed_entry_timestamp": "<base64>",
 "set_verified": false, "submitted_at": "…"}
```

Backends: `FakeWitness` (deterministic test double, controllable clock and down-mode),
`LocalAnchorLog` (honest non-witness fallback), `RekorBackend` (real v1 REST).

### (d) Receipt chaining

Receipts are appended **as chained records in the same `ActionLog`** — they inherit the
HMAC chain, the F25/F126 append lock, and fsync. Exact shapes:

```json
{"event": "anchor_receipt", "epoch_id": "e00000123", "checkpoint_seq": 222,
 "head_hash": "…", "anchor_hash": "…",
 "statement": {…signed statement, self-contained for the auditor…},
 "receipt": {…}, "backend": "rekor-v1", "grade": "anchored"}

{"event": "anchor_epoch_unanchored", "epoch_id": "e00000123",
 "checkpoint_seq": 222, "reason": "backend-down|retry-exhausted",
 "detail": "…", "grade": "operator-attested-only"}
```

The receipt record links to its checkpoint via `checkpoint_seq` (+ `head_hash` belt and
braces); the statement embeds the checkpoint's `(seq, head_hash)`. The auditor walks
**checkpoint → receipt → witness**: replay chain to `checkpoint_seq` ⇒ head hash H;
find the `anchor_receipt` with that `checkpoint_seq`; check `statement.head_hash == H`
and `statement.seq == checkpoint_seq`; verify the statement Ed25519 signature;
`backend.verify_receipt(receipt, anchor_hash=…)`; check witness time in the epoch
window (§3e-iv).

### (e) Auditor verification path

`audit_anchors()` lives in `gov/anchorer.py` (mechanism owner); `python -m gov.verify
--anchors` is the CLI surface (delegates; no HMAC key needed for the witness half).
Per epoch, newest first:

1. **(i) internal chain integrity** — delegate to `gov.log._verify` (needs the HMAC key;
   without it, marked `needs-key`, never claimed).
2. **(ii) receipt inclusion proofs against the witness** — `backend.verify_receipt`:
   body parses and `body.spec.data.hash.value == anchor_hash`; RFC 6962 inclusion proof
   (`sha256(0x00‖leaf)`, `sha256(0x01‖l‖r)` — implemented in the backend, NOT reused
   from `gov.merkle`, whose domains are gov-specific) verifies against the receipt's
   `root_hash`; `log_id` equals the pinned Rekor log id; `integrated_time` sane
   (0 < t ≤ now + 300 s).
3. **(iii) anchored head == chain head at checkpoint** — replay to `checkpoint_seq`,
   compare to `statement.head_hash` (needs the HMAC key; keyless auditors get the
   statement signature + checkpoint-sig checks instead, marked accordingly).
4. **(iv) witness time within the claimed epoch window** —
   `epoch_start_wall − skew ≤ integrated_time ≤ epoch_close_wall + skew`
   (skew default 300 s, explicit).

`demo/make_report.py` renders an **Anchor status** section: per-epoch table
`(epoch_id, seq range, grade, witness time, backend)`, the effective cadence, and the
guarantee sentence with the residual window stated numerically. New optional
`anchor_summary=None` parameter — legacy callers render "not provided", never a claim
(wave-49/50 discipline).

### (f) Failure semantics

- Anchoring is **host-side / executor-side, async, never in the enforcement path, never
  from inside the sandbox** (deny-all egress — the sandbox has no network by design;
  the anchor client lives executor-side only; §5 pins the layering by test).
- `Anchorer.maybe_anchor()` (called at run close / timer tick) only closes the epoch
  and enqueues — no network, returns immediately. A single daemon worker thread does
  all backend I/O.
- **Backend down → the chain continues appending; the epoch is loudly marked
  `anchor_epoch_unanchored` (chained record + stderr warning) and the job enters a
  bounded retry queue** (5 attempts, exponential backoff, then the unanchored grade
  stands until an operator runs `recover()`, which requeues epochs that have an
  unanchored record but no later receipt).
- Per-epoch evidence grade: **`anchored`** (a receipt passes (i)–(iv)) vs
  **`operator-attested-only`** (no receipt, or any check fails — loud, never silent).
- Enforcement-path latency proof: `maybe_anchor()` performs no I/O beyond the
  existing checkpoint append; the break battery asserts append latency is unaffected
  while a 3-second backend submit is in flight.

### (g) Privacy — exact bytes that cross the boundary

For Rekor v1, one HTTPS POST to `/api/v1/log/entries` with body:

```json
{"kind": "hashedrekord", "apiVersion": "0.0.1",
 "spec": {"data": {"hash": {"algorithm": "sha256", "value": "<anchor_hash hex>"}},
           "signature": {"content": "<base64 Ed25519 sig over the 32-byte anchor_hash>",
                         "publicKey": {"content": "<base64 PEM SPKI of anchor pubkey>"}}}}
```

where `anchor_hash = sha256(_ANCHOR_STMT_DOMAIN ‖ canonical_json(statement-without-sig))`.
**That is all.** No record contents, no event names, no principals, no arguments, no
timestamps beyond the epoch window already inside the statement (which itself never
leaves — only its hash does). The FakeWitness interception test pins the submitted key
set; anything beyond the allowlist fails the suite.

## 4. Anchor-signing key custody

`resolve_anchor_key()` (in `gov/anchorer.py`, keyprovider-idiom):

1. `GOV_ANCHOR_KEY` — hex 32-byte Ed25519 seed. 2. `GOV_ANCHOR_KEY_FILE` — 0600 file.
3. Non-production (`staging`/`dev`/`test` per `resolve_deployment_mode`) **with** the
   double opt-in (`GOV_DEV_KEYS=1` + in-code enable) → ephemeral dev anchor key, loud
   warning, `key_id="dev"`. 4. Production without a configured key → **refuse loud**
   (`NoAnchorKeyError`); anchoring is disabled, the chain continues as
   `operator-attested-only` — never silently unanchored.

`key_id = sha256(pubkey).hexdigest()` (mirrors `log_id` in `gov/anchor.py`). The
statement carries `key_id` + `pubkey_hex`; Rekor entries carry the PEM pubkey, so old
receipts verify under retired keys with no local key history. **Rotation:** generate a
new key → new `key_id`; receipts are self-contained (pubkey in the entry body). The
HMAC key and the anchor key SHOULD differ in deployment (separation is what makes the
key-holder threat two keys instead of one); the mechanism does not enforce it —
documented, not a finding (deployment hygiene).

## 5. Threats addressed / explicitly not

Addressed (pinned by break-first tests): operator rewrite of pre-anchor history with
the HMAC key (detection, not prevention — the sentence promises detection);
wall_time/seq/epoch tampering without the key (HMAC break); checkpoint-head mismatch;
witness-time games (outside epoch window, backdated, far-future); receipt forgery
(inclusion proof); cross-epoch entry moves.

**Explicitly not / boundaries (never findings):**
- The **anchor-interval residual**: history after the last anchor is soft — pinned by
  test, not filed. It is the designed security parameter (§3b).
- `set_verified: false` on Rekor receipts: the SET's ECDSA P-256 signature is carried,
  not yet verified (no ECDSA in the tree; inclusion proof + pinned log_id + TLS is the
  verified core). Wave-73 question: implement P-256 SET verification or move to the
  Rekor v2 Ed25519 shard.
- **Closeout adjudication (2026-09-22) — the self-attested Rekor root, NOT filed.**
  `RekorBackend.verify_receipt()` verifies the inclusion proof against the `rootHash`
  *carried inside the receipt*, and the pinned `log_id` check is also receipt data;
  an offline auditor therefore never touches a cryptographically authenticated Rekor
  tree root (no STH signature check, no consistency proof). Adjudicated NOT a finding
  (next free number F129 stays free), because the `anchored` grade is conjunctive —
  `statement_sig` (anchor key) + `anchor_hash_bind` + `head_match` + `statement_chain`
  + `receipt` + `witness_binding` + `witness_time_window` must ALL hold — and the
  crown-jewel attacker (HMAC key, no anchor key) is stopped at `statement_sig`
  before the root ever matters (pinned by probes
  `redteam.anchor_w72.keyholder_rewrite_after_anchor_detected`,
  `...checkpoint_head_mismatch_detected`, `...rekor_backend_two_leaf_proof_verifies`).
  The self-attested root only becomes load-bearing under anchor-key compromise, which
  the design already treats as total (the anchor authority IS the attacker; key
  custody via KMS/production-refusal is the control, §4). The residual that remains
  is third-party verifiability: a third party with only the log file cannot
  independently authenticate the Rekor root. That is the same wave-73 hardening item
  as the SET question above, not a wave-72 break.
- `LocalAnchorLog` is not a witness (same trust domain as the operator).
- The anchor key holder can refuse to anchor (liveness) — the unanchored grade makes
  refusal visible; prevention is operational.
- Sandbox layering: the anchor client (`urllib`) is imported only by
  `gov/anchor_backend.py`, imported only executor-side; `gov/sandbox.py` must not
  reference anchor/rekor/urllib (static pin in the suite). The sandbox's deny-all
  egress is the wave-25-pinned mechanism; this wave pins the composition.

## 6. What "done" means for wave-72

Design (this doc) → `gov/log.py` epoch field → `gov/anchor_backend.py` (interface +
3 backends) → `gov/anchorer.py` (policy, async worker, retry queue, audit,
key resolution) → `gov/verify.py --anchors` → `make_report.py` anchor section →
break-first battery (operator-rewrite-after-anchor MUST fail verification; residual
window pinned; privacy pinned; async-failure pinned; sandbox layering pinned) →
registry `redteam.anchor_w72.*` probes → gates green → BUILD_LOG/REALWORLD_BAR/
FINDINGS/intake.

## 7. Rekor v1 REST mapping (normative for `RekorBackend`)

- `POST {url}/api/v1/log/entries`, `Content-Type: application/json`, stdlib `urllib`.
- Request: hashedrekord 0.0.1 as in §3g. The Ed25519 signature is over the 32 raw bytes
  of `anchor_hash` (hashedrekord signs the digest — the type exists for exactly this).
  `publicKey.content` = base64 of the PEM SPKI text (RFC 8410; DER inside the PEM is
  `302a300506032b6570032100 ‖ 32-byte key`).
- Response: `{ "<uuid>": {"body": b64, "integratedTime": int, "logIndex": int,
  "logID": hex, "verification": {"inclusionProof": {"logIndex","rootHash","treeSize",
  "hashes":[]}, "signedEntryTimestamp": b64}} }`.
- `GET {url}/api/v1/log/publicKey` → pinned key (below), for the `log_id` binding.

## 8. Pinned Rekor production key (captured 2026-09-22)

SPKI PEM (from `GET /api/v1/log/publicKey`, HTTP 200):

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
```

`REKOR_LOG_ID = sha256(DER).hexdigest()` — computed in code and cross-checked against
the published id `wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=` (base64). Rotation note:
if Sigstore rotates the shard key, this constant must be re-captured; mismatch fails
closed (receipts rejected, chain unaffected).
