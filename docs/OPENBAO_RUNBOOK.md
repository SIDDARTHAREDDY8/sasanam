# OpenBao Operator Runbook — self-hosted transit key custody

Date: 2026-09-28. Companion to `docs/KEY_CUSTODY_RUNBOOK.md`
(path A there — HashiCorp Vault — is BSL-1.1 license-trapped; this
document is the license-clean replacement for the self-hosted path).
OpenBao is **MPL-2.0** (verified from the `LICENSE` file inside the
official `openbao_2.7.0_linux_amd64.tar.gz` distribution), governed
under the Linux Foundation / OpenSSF.

**Recommendation (from the wave-186 spike):** adopt OpenBao as the
documented self-hosted key-custody answer for the governance log's HMAC
data keys. It closes the "missing middle" between loopback-dev and
cloud-KMS-only with **zero adapter changes** — `gov/kms_vault.py`
(`provider: vault`) drove a live OpenBao v2.7.0 server unmodified.
Keep cloud KMS (AWS/GCP/Azure) as the recommended production default
for teams that do not want to operate a secrets server.

**Verification status convention** (same as `KEY_CUSTODY_RUNBOOK.md`):

- **LIVE** — exercised against a real OpenBao v2.7.0 server by the
  wave-186 spike (binary sha256-verified against the release
  `checksums.txt`; loopback dev server, all synthetic). These steps
  are proven, not read.
- **DOCS** — taken from openbao.org documentation (v2.7.x) or the
  transit HTTP API reference. Correct per the primary source; not
  exercised live in this repo. Verify in your environment before
  relying on it.

---

## 0. What this runbook covers (and the key domains)

This runbook covers the **KMS master key** domain only: the transit key
that wraps the governance log's per-epoch HMAC data keys (envelope
encryption via `gov/kms.py::EnvelopeKeyRing` + `gov/kms_vault.py::
VaultKmsProvider`). See `docs/KEY_CUSTODY_RUNBOOK.md` §0 for the full
key-domain table — provisioning the KMS master does not provision the
anchor seed, recovery keys, or custody root.

Two transit keys are provisioned:

| Transit key | Type | Purpose |
|---|---|---|
| `gov-audit-data` | `aes256-gcm96` (default) | wraps log HMAC data keys (envelope) — **the key this runbook is about** |
| `gov-audit-sign` | `ed25519` | reserved for the future `TransitSigner` (audit-entry signing). **Not wired to any product path yet** — creating it now is preparation, not integration. |

---

## 1. Provision OpenBao itself — DOCS (production steps)

**LIVE-equivalent:** the spike ran `bao server -dev
-dev-listen-address=127.0.0.1:8200`. Everything below is the
production-grade version — DOCS.

### 1.1 Server configuration

Run OpenBao in production mode (never `bao server -dev` — see
prohibitions §8):

```hcl
# /etc/openbao/openbao.hcl  (DOCS — adapt paths/addresses)
storage "raft" {
  path    = "/var/lib/openbao/raft"
  node_id = "openbao-1"
}
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/openbao/tls/fullchain.pem"
  tls_key_file  = "/etc/openbao/tls/privkey.pem"
}
api_addr = "https://openbao-1.internal:8200"
cluster_addr = "https://openbao-1.internal:8201"
ui = false
disable_mlock = false
```

Start: `bao server -config=/etc/openbao/openbao.hcl`.

> **Red-team this step:** if you skip TLS on the listener, the
> AppRole token (the new root of trust, §3) crosses the network in
> cleartext and `gov/kms_vault.py` will refuse to talk to the server
> at all unless `allow_http=true` is set — which you must never set
> outside loopback dev. Fail-closed by design; a plaintext deployment
> simply does not start.

### 1.2 Initialize and unseal — DOCS

```bash
export BAO_ADDR=https://openbao-1.internal:8200
export BAO_CACERT=/etc/openbao/tls/ca.pem

# One-time: generates the master key split into Shamir shares.
bao operator init -key-shares=5 -key-threshold=3
# -> prints 5 unseal keys + 1 INITIAL ROOT TOKEN. Record them
#    immediately: unseal shares go to 5 custodians (no two on the same
#    host), the root token goes into the bootstrap procedure below
#    and is then REVOKED.

# Each restart / seal event: 3 of 5 custodians run:
bao operator unseal   # paste one share; repeat until threshold
bao status            # Sealed: false
```

> **Red-team this step:** if unseal shares live on the same host as
> the server (or in the same password manager as the root token), the
> Shamir ceremony is theater — one host compromise unseals the
> cluster. If you lose quorum of shares with no backup, the cluster
> is a brick: every wrapped data key becomes permanently
> undecryptable and the log halts (fail-closed, §7).

### 1.3 Revoke the bootstrap root token — DOCS

The initial root token is a bootstrap credential, not an operator
credential. Immediately after provisioning:

```bash
# As the root token, provision the operator identities (§3), then:
bao token revoke -self
```

If a root token is ever needed again, generate one with quorum —
never reuse a stored copy:

```bash
bao operator generate-root -init        # then 3 custodians run:
bao operator generate-root             # (paste shares)
```

> **Red-team this step:** a root token that survives provisioning is
> a standing superuser credential. Anyone holding it can create keys,
> rotate, lower `min_decryption_version`, and read every transit
> operation — bypassing every least-privilege control in §3.

---

## 2. Enable transit and create the keys — LIVE

```bash
bao secrets enable transit
# Success! Enabled the transit secrets engine at: transit/

bao write -f transit/keys/gov-audit-data type=aes256-gcm96
# Success! Data written to: transit/keys/gov-audit-data

bao write -f transit/keys/gov-audit-sign type=ed25519
# Success! Data written to: transit/keys/gov-audit-sign
```

Key creation parameters are immutable after creation (LIVE-verified
via the API docs and the spike):

- `exportable` defaults to `false` — **leave it false.** Private key
  material never leaves the server. Once set true it can never be
  disabled.
- `allow_plaintext_backup` defaults to `false` — **leave it false**
  (same one-way door).
- `deletion_allowed` defaults to `false` — **leave it false** until
  you have a tested restore (a deleted transit key version cannot
  decrypt blobs wrapped under it).

Verify:

```bash
bao read transit/keys/gov-audit-data
# type: aes256-gcm96, latest_version: 1, min_decryption_version: 1, ...
```

> **Red-team this step:** creating the key with `exportable=true`
> "just in case" permanently opts the key material out of
> server-side custody — any future token with read access to the
> export path can exfiltrate the master key, and the flag can never
> be turned back off. The only fix is a new key and a full rewrap.

---

## 3. AppRole + transit-only policy — LIVE

The adapter is auth-method-agnostic (it only sends the token header),
so the least-privilege story is pure operator configuration — LIVE
proven: a policy token scoped as below drove `gov/kms_vault.py` fine
while key creation and rotation returned **HTTP 403**.

### 3.1 The application policy

```hcl
# gov-transit-app.hcl — the ONLY policy the governance host's token carries
path "transit/encrypt/gov-audit-data" {
  capabilities = ["update"]
}
path "transit/decrypt/gov-audit-data" {
  capabilities = ["update"]
}
path "transit/keys/gov-audit-data" {
  capabilities = ["read"]   # describe_key needs this
}
```

```bash
bao policy write gov-transit-app gov-transit-app.hcl
```

Notes:

- `update` only — **never `create`** on the encrypt path. With
  `create` capability the encrypt endpoint *upserts* unknown keys
  (auto-creates them with default parameters); `update`-only makes
  encrypt fail on a nonexistent key instead. Belt-and-suspenders:
  also set the global upsert guard —
  `bao write transit/config/keys disable_upsert=true`
  (POST `/transit/config/keys`, DOCS).
- The policy names exactly one key. The host can wrap/unwrap under
  `gov-audit-data` and nothing else.
- The host **cannot** rotate, rewrap, reconfigure, or export. Rotation
  is a separate operator identity (§5).

### 3.2 The AppRole

```bash
bao auth enable approle

bao write auth/approle/role/gov-app \
    token_policies="gov-transit-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=10m \
    secret_id_num_uses=0
# (token_policies is the canonical field name; `policies` is accepted
#  as an alias. secret_id_num_uses=0 = unlimited uses within the TTL.)

# RoleID is semi-public (distribute via config management):
bao read -field=role_id auth/approle/role/gov-app/role-id

# SecretID is a credential — deliver via response wrapping, never in chat/logs:
bao write -wrap-ttl=60s -f auth/approle/role/gov-app/secret-id
# -> wrapping token; the host unwraps it once:
# bao unwrap <wrapping-token>   (on the host, at provisioning time)
```

The host logs in and exports the token for the adapter:

```bash
# on the governance host (or its supervisor):
SECRET_ID=$(bao unwrap -field=secret_id <wrapping-token>)
export VAULT_ADDR=https://openbao-1.internal:8200
export VAULT_TOKEN=$(bao write -field=token auth/approle/login \
    role_id="$ROLE_ID" secret_id="$SECRET_ID")
# VAULT_TOKEN lifetime: token_ttl (1h), renewable to token_max_ttl (4h).
# Renew via `bao token renew` on a schedule, or re-login. A dead token
# is fail-closed: every wrap/unwrap raises KmsError (see §7).
```

> **Red-team this step:** (a) Skipping response wrapping and pasting
> the SecretID into chat/tickets/logs turns a short-lived credential
> into a standing one in someone's scrollback. (b) Granting the app
> policy `create` on `transit/encrypt/*` lets a compromised host mint
> new keys and encrypt under them — the blast radius escapes the one
> named key. (c) A token with `default` policy attached (the AppRole
> default) carries cubbyhole + token self-management — harmless here,
> but audit it anyway; least privilege means listing what you carry.
> (d) `secret_id_ttl=10m` with pull-mode delivery means the
> orchestrator must deliver fast; a stale SecretID fails closed at
> login (HTTP 400), which is the safe direction.

---

## 4. Client wiring — LIVE (zero adapter changes)

`gov/kms_vault.py` works **unmodified** against OpenBao v2.7.0
(spike: wrap/unwrap round-trip, `describe_key`, and the `VAULTKMS1`
key-id-binding envelope all behave per the fail-closed contract).

```python
from gov.kms import kms_provider_from_config
provider = kms_provider_from_config({
    "provider": "vault",
    # mount defaults to "transit"; VAULT_ADDR / VAULT_TOKEN from env
    "ca_bundle": "/etc/openbao/tls/ca.pem",  # fail-closed if unreadable
    "timeout_s": 10,
})
```

| Key | Default | Meaning |
|---|---|---|
| `mount` | `"transit"` | transit mount path (must match `bao secrets enable`) |
| `allow_http` | `false` | permit plaintext `http://` VAULT_ADDR — **loopback dev only**; refused fail-closed by default |
| `ca_bundle` | system trust | CA bundle for private-CA TLS; a missing path fails at config time |
| `timeout_s` | `10` | per-request timeout (seconds) |

Enroll the first data key (same ceremony as `KEY_CUSTODY_RUNBOOK.md`
§A.3, with the OpenBao backend):

```python
from gov.kms import EnvelopeKeyRing, kms_provider_from_config
provider = kms_provider_from_config({"provider": "vault"})
ring = EnvelopeKeyRing.generate(provider,
                                kms_key_id="gov-audit-data",
                                epoch="epoch-1")
ring.save("/etc/governance/log-envelope.json")  # wrapped only, 0600
```

Wire into process start (`KEY_CUSTODY_RUNBOOK.md` §A.4): materialize
once → activate. If OpenBao is unreachable at startup, `activate()`
raises `KmsError` and the process does not start — **do not catch it
and continue.**

> **Red-team this step:** (a) Pointing `VAULT_ADDR` at `http://` with
> `allow_http=true` outside loopback dev sends the AppRole token in
> cleartext — the adapter refuses this by default; overriding the
> refusal is the vulnerability. (b) Baking `VAULT_TOKEN` into a
> container image or repo file turns a 1h credential into a permanent
> one; inject at runtime from the supervisor. (c) Skipping
> `ca_bundle` against a private CA fails closed at config time — that
> is the safe failure; "fixing" it with `allow_http` is not.

---

## 5. Rotation SOP — rotate → rewrap → raise `min_decryption_version`

Cadence guidance comes from the OpenBao docs (NIST 800-38D): for
AES-GCM, rotate before ~2^32 encryptions per key version. Estimate
your wrap rate and set a calendar cadence (the docs' worked example:
40M ops/day → quarterly rotation is sufficient). **Do not rotate
hourly "to be safe"** — the docs warn that frequent rotation bloats
the Raft-backed archive entry past what the storage backend can
handle.

All three sub-steps are operator-driven ceremonies (no scheduler —
matches `KEY_CUSTODY_RUNBOOK.md` non-goals). Perform them with the
**operator identity** (a human/operator token with key-management
capabilities), never the app identity.

### 5.1 Rotate — LIVE

```bash
# operator identity:
bao write -f transit/keys/gov-audit-data/rotate
# Success! Data written to: transit/keys/gov-audit-data/rotate

bao read -field=latest_version transit/keys/gov-audit-data
# 2
```

After rotation, new wraps use v2; v1 ciphertexts still decrypt
(LIVE-verified). The governance envelope ring does not change yet —
its wrapped blobs still name v1.

### 5.2 Rewrap — LIVE (no plaintext exposure)

Upgrade every wrapped blob to the new version **without the plaintext
ever leaving the server** (LIVE-verified via raw HTTP; docs confirm
the CLI form):

```bash
bao write transit/rewrap/gov-audit-data ciphertext=vault:v1:<...>
# -> ciphertext: vault:v2:<...>
```

For the envelope ring, use the product ceremony (it rewraps every
epoch's blob and persists atomically — `KEY_CUSTODY_RUNBOOK.md`
§C.2):

```python
from gov.kms import EnvelopeKeyRing, kms_provider_from_config
provider = kms_provider_from_config({"provider": "vault"})  # operator token in env
ring = EnvelopeKeyRing.load("/etc/governance/log-envelope.json")
ring.rewrap(provider, "gov-audit-data")   # re-wraps under latest version
ring.save("/etc/governance/log-envelope.json")
```

All fallible KMS calls complete before any ring state is mutated — a
mid-ceremony `KmsError` leaves the store unmutated. Abort, do not
retry against a different key id without recording the deviation.

> **Red-team this step:** skipping rewrap leaves every historical
> blob on v1. Rotation without rewrap is *version theater* — the old
> key version remains load-bearing forever, so a v1 compromise still
> decrypts everything and `min_decryption_version` can never be
> raised (§5.3). Rewrap is the step that makes rotation real.

### 5.3 Raise `min_decryption_version` — DOCS (endpoint LIVE-read)

Only after 5.2 confirms every blob is on the new version:

```bash
bao write transit/keys/gov-audit-data/config min_decryption_version=2
# POST /v1/transit/keys/:name/config  {min_decryption_version: 2}
```

Effect (per the API docs): v1 ciphertexts can no longer be
decrypted (they were all rewrapped in 5.2, so nothing legitimate
needs v1); for signatures this controls the minimum verifiable
version. `min_encryption_version` must stay `0` (use latest) or be
≥ `min_decryption_version` — leave it `0`.

> **Red-team this step:** raising `min_decryption_version` BEFORE
> rewrapping bricks every v1 blob — unwraps fail, the log halts,
> verification of history fails. The order rotate → rewrap →
> raise is load-bearing. If you must roll back, the docs note the
> floor can be moved back down in an emergency — that is the
> break-glass, not the plan.

### 5.4 Verify the ceremony

```bash
bao read transit/keys/gov-audit-data
# latest_version: 2, min_decryption_version: 2
```

Then run the product verification: `EnvelopeKeyRing.load(...).activate(provider)`
(or `materialize()` + `verify_log()` for verification-only) against a
recent log — a green verification after rotation is the proof the
ceremony preserved history.

---

## 6. Backup and restore — DOCS

### 6.1 Raft snapshots (the unit of backup)

```bash
# backup (authenticated operator token):
bao operator raft snapshot save /mnt/backups/openbao-$(date +%Y%m%d).snap

# restore (to a fresh, initialized node; stops the cluster briefly):
bao operator raft snapshot restore /mnt/backups/openbao-20260928.snap
```

- Schedule snapshots (cron/systemd timer); retain per your DR
  policy. Store them **encrypted and offsite** — a snapshot contains
  the transit key ring (still sealed by the master key, but defense
  in depth).
- Snapshots are sealed by the cluster's master key: restoring to a
  cluster initialized with *different* unseal shares does not work.
  **Back up the unseal-share custody record alongside the
  snapshots** — a snapshot without quorum shares is a paperweight.
- Complement snapshots with a logical export of the key metadata
  (`bao read transit/keys/gov-audit-data` → `latest_version`,
  `min_decryption_version`) so a restore can be sanity-checked
  against the expected key state.

### 6.2 Envelope-file backup (product side)

The envelope file (`/etc/governance/log-envelope.json`) and its
`<path>.bak` hold **wrapped blobs only** — safe to copy, useless
without the transit key. Back them up somewhere the OpenBao cluster
is not (they are the restore path for "envelope file destroyed",
§7). Never back up plaintext data keys — the design has no such
artifact by construction.

> **Red-team this step:** (a) Snapshots without the unseal shares
> are unrecoverable — test the restore on a scratch cluster, not in
> the incident. (b) Backing up snapshots to the same disk/rack as
> the cluster makes backup and primary fate-share. (c) An
> *unencrypted* snapshot on shared storage hands the transit ring to
> anyone with read access; it is sealed, but you have now bet the
> cluster on seal strength alone.

---

## 7. Monitoring and alerting — DOCS

OpenBao exposes Prometheus metrics at `/v1/sys/metrics?format=prometheus`
(authenticated). Minimum alert set (metric names retain the `vault_`
prefix for dashboard compatibility):

| Signal | Alert when | Why |
|---|---|---|
| `vault_core_unsealed == 0` | sealed | every transit op fails; the log halts |
| no Raft leader (`vault_raft_leader`) | no leader | writes (rotate/rewrap) impossible |
| `vault_raft_peers < 3` | peer loss | HA degraded; next failure is an outage |
| transit error rate (5xx on `/v1/transit/*`) | spike | KMS outage → `KmsError` → fail-closed halt |
| `vault_token_count` | abnormal growth | token leak / runaway issuance |
| AppRole token TTL expiry | no successful login in > `token_max_ttl` | host silently unauthenticated; next restart fails |

Also alert on the product side: any `KmsError` at process start is a
page, not a log line — it means the log is not running.

> **Red-team this step:** unmonitored seal state means the first
> sign of a sealed cluster is a dead governance log at 3 AM.
> Unmonitored token expiry means the host's credential quietly dies
> and the next deploy/restart fails closed with no prior warning.

---

## 8. What breaks if keys are lost — fail-closed by design

Loss never degrades silently into forged or unverifiable evidence.
It degrades into **refusal** (same posture as `KEY_CUSTODY_RUNBOOK.md`
§D):

- **One transit key version retired + blobs rewrapped (§5):** old
  ciphertexts undecryptable by policy (`min_decryption_version`) —
  intended. Anything still on the old version is bricked; that is why
  5.2 precedes 5.3.
- **All transit key versions lost / cluster unrecoverable:** every
  unwrap fails → `KmsError` → no log start, no verification, no
  rotation. Recovery: Raft snapshot + quorum unseal shares (§6).
  There is no break-glass decryption without the master key — by
  design.
- **Transit key deleted** (`deletion_allowed` was flipped): a deleted
  key version cannot decrypt blobs wrapped under it. Prefer
  **disable** semantics (`min_decryption_version` as the emergency
  brake — reversible) over delete (irreversible).
- **Envelope file destroyed, backup intact:** restore the file;
  blobs are wrapped, still decryptable. Envelope destroyed *and* no
  backup: the log cannot start; history unverifiable.
- **AppRole token expired/revoked:** fail-closed refusal until
  re-authenticated. Not a key loss — re-login (§3.2).

---

## 9. PROHIBITIONS

1. **Never `bao server -dev` outside a spike.** Dev mode uses a
   well-known unseal key, no TLS, and an in-memory store that
   vanishes on restart. A "temporary" dev server that survives the
   spike becomes production with none of the controls in §1.
2. **Never use the root token for operations.** Bootstrap (§1.3),
   revoke it, and generate quorum roots only for emergencies.
3. **Never skip rewrap after rotation** (§5.2). Rotation without
   rewrap is version theater.
4. **Never raise `min_decryption_version` before rewrap completes**
   (§5.3). Order is load-bearing.
5. **Never set `exportable=true` or `allow_plaintext_backup=true`**
   (§2). One-way doors; they permanently exit server-side custody.
6. **Never set `allow_http=true` outside loopback dev** (§4). The
   token must not cross cleartext; the adapter refuses by default.
7. **Never delete a transit key** while any blob may reference it.
   Disable-via-version-floor is the reversible brake; delete is
   forever.
8. **Never store unseal shares and snapshots in the same place**
   (§6). Fate-sharing backup and primary is not a backup.
9. **Never move HMAC-per-entry into transit.** The envelope design
   (one unwrap per epoch, local HMAC chains) is deliberate — a
   network call per log entry is a latency, availability, and
   audit-surface regression (spike gap #4).

---

## 10. Explicit non-goals

- **Audit-entry signing via transit** — the `gov-audit-sign`
  (ed25519) key is provisioned (§2) but unwired. The product path
  needs a `TransitSigner(Signer)` adapter (spike next-work #2) that
  verifies locally against exported public keys to preserve offline
  verification. Do not hand-roll transit signing into the log path
  before that adapter exists and is reviewed.
- **Transit key versions ≠ keyset lineage.** Transit rotation is an
  operator API call with no signed lineage and no attested
  revocation record; the wave-185 keyset's previous-primary-signed
  rotation records and revocation attestations remain the stronger
  story for audit. Spike next-work #3 is binding the two version
  stories so they do not drift — until then, record every rotation
  in the keyset ceremony out of band.
- **No automatic rotation scheduler.** Rotations are operator
  ceremonies (§5), not cron — same as `KEY_CUSTODY_RUNBOOK.md`.
- **No multi-cluster transit story.** One OpenBao cluster per
  deployment; DR is §6, not this runbook.
- **BYOK import** (`/transit/keys/:name/import`) is documented in the
  API reference but not exercised here — importing external key
  material changes the custody story (the key existed outside the
  server). Prefer server-generated keys.

---

## 11. Command index (copy-paste checklist)

```bash
# --- one-time provisioning (operator, root token) ---
export BAO_ADDR=https://openbao-1.internal:8200
export BAO_CACERT=/etc/openbao/tls/ca.pem
bao operator init -key-shares=5 -key-threshold=3   # record shares + root token
bao operator unseal                                # x3 custodians
bao secrets enable transit
bao write -f transit/keys/gov-audit-data type=aes256-gcm96
bao write -f transit/keys/gov-audit-sign type=ed25519
bao write transit/config/keys disable_upsert=true
bao policy write gov-transit-app gov-transit-app.hcl
bao auth enable approle
bao write auth/approle/role/gov-app \
    token_policies="gov-transit-app" token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=10m secret_id_num_uses=0
bao token revoke -self                             # kill the bootstrap root

# --- host provisioning (orchestrator, response-wrapped SecretID) ---
ROLE_ID=$(bao read -field=role_id auth/approle/role/gov-app/role-id)
bao write -wrap-ttl=60s -f auth/approle/role/gov-app/secret-id  # -> wrapping token
# on host:
export VAULT_ADDR=https://openbao-1.internal:8200
export VAULT_TOKEN=$(bao write -field=token auth/approle/login \
    role_id="$ROLE_ID" secret_id="$(bao unwrap -field=secret_id <wrapping-token>)")

# --- rotation ceremony (operator identity) ---
bao write -f transit/keys/gov-audit-data/rotate
# ... rewrap every blob (product ceremony: ring.rewrap) ...
bao write transit/keys/gov-audit-data/config min_decryption_version=2
bao read transit/keys/gov-audit-data   # confirm latest_version / floor

# --- backup ---
bao operator raft snapshot save /mnt/backups/openbao-$(date +%Y%m%d).snap
```

---

*Verification ledger: §2 key creation, §3 policy/AppRole least-privilege
(403 on key create/rotate), §4 adapter-unmodified, §5.1 rotate, §5.2
rewrap, and ed25519 sign/verify + public-key export are LIVE
(wave-186 spike, OpenBao v2.7.0, 2026-09-28). §1 provisioning,
§5.3 config endpoint parameters, §6 snapshots, §7 metrics, and the
NIST cadence guidance are DOCS (openbao.org v2.7.x + transit API
reference). DOCS steps must be verified in your environment before
they carry production weight.*
