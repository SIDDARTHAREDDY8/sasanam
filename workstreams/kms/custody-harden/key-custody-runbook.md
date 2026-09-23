# Key Custody Runbook — production provisioning (DRAFT)

Stream 2 draft for central integration review. Covers provisioning the
governance log's HMAC data keys under real key custody, two ways:
**(a)** HashiCorp Vault via the upcoming `VaultKmsProvider`, and
**(b)** AWS KMS via `EnvelopeKmsProvider` plus an operator-built AWS
adapter. Also: rotation, what breaks when keys are lost, and explicit
non-goals.

**Status: DRAFT.** Every step that has not been exercised against a live
backend is marked **UNTESTED**. The only tested path in this repo is the
synthetic rehearsal with `FakeKmsProvider` (unit-tested; zero production
security). Do not treat UNTESTED steps as verified.

**Background (verified in-tree):** wave-81 deleted the dev key, the
dev-key provider, and every dev-key opt-in from `gov/`. Key resolution
is configured env key → configured keyring file → loud
`NoKeyConfiguredError` in every mode. There is no fallback. An
unprovisioned deployment does not start a chain — it refuses. (Audit:
`workstreams/kms/custody-harden/AUDIT.md`.)

## 0. Key domains — know which key you are provisioning

These are separate compromise domains. Losing one never implies the
others, and provisioning one does not provision the rest:

| Domain | Module | What it signs | Provisioning |
|---|---|---|---|
| Log HMAC data keys (per epoch) | `gov/kms.py` `EnvelopeKeyRing` / `gov/keys.py` `KeyRing` | every action-log entry | this runbook |
| KMS master key | Vault transit key / AWS KMS key | wraps the data keys (envelope) | this runbook |
| Anchor Ed25519 seed | `gov/anchorer.py` `resolve_anchor_key` | timestamping receipts | `GOV_ANCHOR_KEY` / `GOV_ANCHOR_KEY_FILE` (0600) |
| Recovery / halt keys | `gov/recovery.py` | halt + recovery ops | explicit constructor args in production |
| Lineage run key | `gov/lineage.py` | infection-lineage sidecar HMACs | auto-created per tracker dir (see audit G1/N) |
| Custody root seed + shares | `gov/custody.py` | rosters, ceremony tips | offline ceremony (`workstreams/kms/CEREMONY_RUNBOOK.md`) |

This runbook covers the first two rows. The rest are named so an
operator does not mistake "KMS is set up" for "all keys are managed".

## Conventions

- `ENVELOPE=/etc/governance/log-envelope.json` — the envelope keyring
  file (wrapped blobs + metadata ONLY; safe to copy, never holds
  plaintext). Created 0600 by `EnvelopeKeyRing.save`.
- `LOG=/var/lib/governance/actions.jsonl` — the action log.
- Python snippets assume the repo is importable (`PYTHONPATH=<repo>`).
  There is no ceremony CLI; operators script the Python API.

---

## A. HashiCorp Vault path (via the upcoming `VaultKmsProvider`)

> `VaultKmsProvider` does not exist in the repo yet. It is an
> operator-built `gov.kms.KmsProvider` subclass backed by the Vault
> **transit** secrets engine. The shape it must implement is fixed by
> the `KmsProvider` ABC; everything below marked UNTESTED has not been
> run against a live Vault.

### A.1 Provision Vault itself — UNTESTED

1. Run Vault in production mode (not `vault server -dev`): Raft
   integrated storage or Consul backend, TLS on the API listener,
   seal/unseal configured (Shamir shares or auto-unseal).
2. Enable the transit engine: `vault secrets enable transit`.
3. Create the master key: `vault write -f transit/keys/governance-log-master`
   (default type `aes256-gcm96` is correct for envelope wrap).
4. Create a policy granting ONLY the transit operations on that key:
   `transit/encrypt/governance-log-master`, `transit/decrypt/governance-log-master`,
   `transit/keys/governance-log-master` (read, for `describe_key`).
   No other paths.
5. Choose an auth method for the governance host (AppRole with a wrapped
   secret-id, or the agent's platform identity — e.g. AWS/GCP auth).
   The Vault token (or AppRole credentials) is the new root of trust:
   protect it like the key itself (env var or file, 0600, never in the
   repo).

### A.2 Write the `VaultKmsProvider` adapter — UNTESTED

Implement `gov.kms.KmsProvider` (`provider_name = "vault"`):

- `wrap_data_key(key_id, plaintext)` → `POST /v1/transit/encrypt/<key_id>`
  with `plaintext = base64(plaintext)`. Return the `ciphertext` string
  (`vault:v1:<b64>`) as the opaque wrapped blob.
- `unwrap_data_key(key_id, wrapped)` → `POST /v1/transit/decrypt/<key_id>`
  with the blob. **Key-id binding (mandatory):** the transit ciphertext
  embeds the key name and version (`vault:v1:...`). The adapter MUST
  verify the blob's embedded key name equals the requested `key_id`
  before returning plaintext; a blob minted under a different key name
  raises `KmsError` even if Vault would decrypt it. (This is the
  Attack-2 impersonator hardening from `gov/kms.py`.)
- `describe_key(key_id)` → `GET /v1/transit/keys/<key_id>`; map
  `deletion_allowed`, `exportable=false`, latest version → `KeyDescription`.
- Every transport/auth/outage failure raises `KmsError` — never a weaker
  key, never a cached plaintext, never a fallback.

### A.3 Enroll the first data key — UNTESTED

```python
from gov.kms import EnvelopeKeyRing
provider = VaultKmsProvider(...)          # UNTESTED adapter from A.2
ring = EnvelopeKeyRing.generate(provider,
                                kms_key_id="governance-log-master",
                                epoch="epoch-1")
ring.save("/etc/governance/log-envelope.json")  # wrapped only, 0600
```

Verify the file contains no plaintext: it must hold `wrapped_b64`,
`kms_key_id`, `key_id` (a fingerprint, not key material), epochs —
grep the file for anything that looks like 32 raw bytes; there is
nothing to find by construction.

### A.4 Wire it into process start — UNTESTED

`EnvelopeKmsProvider` is operator-driven, never auto-detected from env
(so no attacker-influenceable variable selects the KMS story). The
documented integration is materialize-once → activate:

```python
from gov.kms import EnvelopeKeyRing
from gov.keyprovider import EnvelopeKmsProvider
provider = VaultKmsProvider(...)                       # UNTESTED
ring = EnvelopeKeyRing.load("/etc/governance/log-envelope.json")
ring.activate(provider)   # publishes GOV_LOG_KEY / GOV_LOG_KEY_EPOCH /
                          # GOV_LOG_KEY_ARCHIVE into the process env
from gov.log import ActionLog
log = ActionLog("/var/lib/governance/actions.jsonl")  # EnvKeyProvider path
```

Notes:

- `activate()` deliberately unwraps every epoch (retired epochs are
  needed in the archive var). Prefer `materialize()` + `verify_log()`
  (lazy retired-epoch unwrap) for verification-only processes.
- If Vault is unreachable at startup, `activate()` raises `KmsError`
  and the process does not start. That is the fail-closed behavior —
  do not catch it and continue.

### A.5 Rehearse first (TESTED — synthetic)

Before touching Vault, rehearse the whole ceremony with
`FakeKmsProvider` (deterministic, zero production security — it exists
so the *protocol* is testable with no network):

```python
from gov.kms import FakeKmsProvider, EnvelopeKeyRing, rotate_envelope_keyring
provider = FakeKmsProvider(["governance-log-master"])  # test-only
ring = EnvelopeKeyRing.generate(provider, "governance-log-master")
ring.save("/tmp/rehearsal-envelope.json")
ring, new_epoch = rotate_envelope_keyring("/tmp/rehearsal-envelope.json",
                                          provider, log_path="/tmp/rehearsal-log.jsonl")
```

(The old `GOV_DEV_KEYS=1` + `kms_provider_from_config({"provider": "fake"})`
rehearsal documented in `workstreams/kms/CEREMONY_RUNBOOK.md` is stale:
wave-81 deleted that gate and the factory now refuses `"fake"`
unconditionally. Construct `FakeKmsProvider` directly, as above.)

---

## B. AWS KMS path (via `EnvelopeKmsProvider` + operator-built adapter)

> The AWS adapter is not shipped ($0 spend, no credentials, no network
> in this repo). `kms_provider_from_config({"provider": "aws"})` raises
> `KmsError` by design. Everything below marked UNTESTED has not been
> run against real AWS.

### B.1 Provision the KMS key — UNTESTED

1. Create a symmetric KMS key (`KeySpec SYMMETRIC_DEFAULT`, `KeyUsage
   ENCRYPT_DECRYPT`) in the deployment's region; attach an alias such
   as `alias/governance-log-master`.
2. Key policy: allow `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey`
   ONLY on this key ARN, ONLY for the governance host's IAM role
   (instance role / IRSA). No `kms:*`, no wildcard resources.
3. Enable CloudTrail data-plane logging for KMS in the account (audit
   of every wrap/unwrap call).
4. Decide the rotation story up front: AWS automatic rotation (yearly,
   old key material retained for decrypt) vs manual alias retarget +
   the `rewrap` ceremony (§C). Automatic rotation does NOT re-encrypt
   old blobs — it only changes what new Encrypt calls use.

### B.2 Write the AWS adapter — UNTESTED

Implement `gov.kms.KmsProvider` (`provider_name = "aws"`) over boto3:

- `wrap_data_key(key_id, plaintext)` →
  `kms.encrypt(KeyId=key_id, Plaintext=plaintext)`; return
  `CiphertextBlob`. The data key itself is generated locally by
  `EnvelopeKeyRing._wrap_new` (`secrets.token_bytes(32)`); the adapter
  only wraps.
- `unwrap_data_key(key_id, wrapped)` →
  `kms.decrypt(KeyId=key_id, CiphertextBlob=wrapped)`. **Always pass
  `KeyId`** — omitting it lets KMS infer the key from the blob and
  destroys key-id binding (the impersonator vector hardened in
  `gov/kms.py`). On any mismatch/failure raise `KmsError`.
- `describe_key(key_id)` → `kms.describe_key(KeyId=key_id)`; surface
  `KeyState` (`Enabled` vs `Disabled`/`PendingDeletion`) — a disabled
  or pending-deletion key must surface as unusable, fail-closed.

### B.3 Enroll and wire — UNTESTED

Identical to A.3/A.4 with `AwsKmsProvider(...)` in place of
`VaultKmsProvider(...)` and `kms_key_id="alias/governance-log-master"`.
Rehearse with `FakeKmsProvider` first (§A.5).

---

## C. Rotation

### C.1 Data-key rotation (both paths) — protocol TESTED synthetically, live steps UNTESTED

```python
from gov.kms import rotate_envelope_keyring
ring, new_epoch = rotate_envelope_keyring(
    "/etc/governance/log-envelope.json", provider,
    log_path="/var/lib/governance/actions.jsonl")
ring.activate(provider)  # publish the new epoch to the process env
```

What this does, in order: loads the envelope ring (wrapped only); if
`log_path` is given, verifies the existing log FIRST with per-epoch
keys (a KMS outage here means "cannot verify" and the ceremony
REFUSES — never rotate blind on top of an unverifiable log); mints a
fresh data key, wraps it under the KMS master, adds it as the new
ACTIVE epoch; retains the old wrapped key as RETIRED (history stays
verifiable); writes an atomic backup `<path>.bak`; persists atomically
(0600); all serialized under the rotation lock. Rehearse with
`FakeKmsProvider` before doing it against Vault/AWS.

### C.2 KMS master-key rotation (both paths) — UNTESTED live

```python
ring = EnvelopeKeyRing.load("/etc/governance/log-envelope.json")
ring.rewrap(provider, "governance-log-master-v2")  # or new alias
ring.save("/etc/governance/log-envelope.json")
```

`rewrap` unwraps every epoch under its current key id and re-wraps
under the new one; all fallible KMS calls complete before any ring
state is mutated (a mid-ceremony `KmsError` leaves the store
unmutated — abort, do not retry against a different key id without
recording the deviation).

### C.3 Other domains (for completeness)

- **Anchor seed:** provision a new `GOV_ANCHOR_KEY` / file; receipts are
  per-epoch, so rotation is naturally epoch-scoped. Old receipts keep
  verifying against the old pubkey (which must have been distributed to
  verifiers out of band).
- **Recovery/halt keys:** re-provision via the `RecoveryController`
  constructor; there is no in-protocol rotation — plan a maintenance
  window.
- **Custody root/shares:** the offline ceremony in
  `workstreams/kms/CEREMONY_RUNBOOK.md`.

---

## D. What breaks if keys are lost

Fail-closed is the design: loss never degrades silently into forged or
unverifiable evidence. It degrades into **refusal**.

- **Log HMAC data key lost (one epoch):** entries under that epoch can
  never verify again (`verify_log` fails for the epoch). The chain is
  still appendable under the ACTIVE epoch, but the lost epoch's history
  is unverifiable — treat any evidence claim over it as void.
- **All data keys lost / envelope file destroyed with no backup:** the
  log cannot start (`NoKeyConfiguredError` / `KmsError`) and no entry
  verifies. Evidence pipeline halts. Recovery: restore
  `<path>.bak` or the envelope file backup (wrapped blobs are safe to
  back up — they are useless without the KMS master).
- **KMS master key lost or deleted:** every unwrap fails → `KmsError`
  → no log start, no verification, no rotation. **AWS:** a key
  scheduled for deletion is irrecoverable after the waiting period —
  deletion is the one irreversible catastrophe in this design; guard
  the key policy accordingly. **Vault:** a deleted transit key version
  cannot decrypt blobs wrapped under it — keep `min_decryption_version`
  / backups per your Vault DR plan.
- **KMS master disabled (not deleted):** fail-closed refusal until
  re-enabled. Prefer disable over delete as the emergency brake.
- **Anchor seed lost:** no new anchors can be produced; the chain
  continues operator-attested-only. Existing receipts still verify
  against the previously distributed pubkey.
- **Recovery/halt keys lost:** no new halt or recovery operations can
  be authorized; existing MACs cannot be re-verified.
- **Lineage run key lost:** the tracker silently creates a new one on
  next start; old sidecar stamps become unverifiable (treated as
  lineage-unknown, which taints).
- **Custody root seed lost:** no new rosters or tip manifests can be
  signed; previously signed artifacts still verify via the root pubkey.

Back up the envelope file and `<path>.bak` somewhere the KMS master
is not (they are wrapped — theft without the master yields nothing).
Do NOT back up plaintext data keys anywhere; the design has no such
artifact by construction (`MaterializedKeyRing.save` refuses).

---

## E. Explicit non-goals

- **No HSM yet.** Custody here is software keys (0600 files, least-bad
  $0 local) or KMS envelope. No PKCS#11 / CloudHSM / physical HSM story.
- **No automatic rotation scheduler.** Rotations are operator-driven
  ceremonies, not cron.
- **No multi-region KMS story.** One master key per deployment; DR is
  the operator's backup/region plan, not this runbook's.
- **No key escrow / break-glass for a lost KMS master.** By design:
  loss is fail-closed and irrecoverable. The mitigation is backups of
  wrapped material + protecting the master, not a recovery backdoor.
- **`VaultKmsProvider` is not implemented.** The adapter shape is fixed
  (§A.2); the code is operator work, UNTESTED.
- **No ceremony CLI.** Ceremonies are Python API calls (limitation
...[truncated 1389 chars]