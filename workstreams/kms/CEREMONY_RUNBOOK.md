# KMS Custody Ceremony Runbook

Procedures for the key-custody ceremonies implemented in `gov/custody.py`
(threshold checkpoint-signing keys) and `gov/kms.py` (KMS envelope layer).
Every step below names the real public API it uses. Where the code does
not support a step, that is stated explicitly as a **limitation** — do not
improvise substitutes.

Related: `gov/custody.py` module docstring (design), `gov/signing.py`
(threshold signing, rosters), `gov/kms.py` module docstring (envelope
protocol, FakeKmsProvider limits).

## Trust model and fail-closed principles

- **Three separate key domains.** Checkpoint-signing seeds (`gov/custody.py`)
  ≠ log HMAC data keys (`gov/kms.py` `EnvelopeKeyRing`) ≠ offline root key.
  Compromise of one domain never implies the others.
- **Fail-closed.** Every KMS failure raises `KmsError` and aborts the
  ceremony. `add_share`, `rotate_share`, and `rewrap` wrap *before* touching
  store state, so a KMS failure can never leave the store half-mutated.
  An unwrapped seed whose pubkey mismatches the recorded key id raises
  `KmsError` — the store never adopts unauthenticated material.
- **Permissions.** Store files and root-seed files must be mode `0600`.
  `SignerShareStore.load` and `load_root_seed` *refuse* group/world-readable
  files (`PermissionError`). All writes are atomic (same-dir temp + fsync +
  `os.replace`).
- **The transcript is a hash chain with a root-signed tip** (F78). Every
  record commits to its predecessor; every ROOT ceremony (genesis,
  rotate-roster, tip-anchor) also writes a root-signed tip manifest binding
  `(record_count, tip_record_hash)` to `<transcript>.tip.json`. Verification
  fails closed on tail truncation, tip replacement, or a missing manifest
  for a manifest-scheme transcript. Legacy (pre-manifest) transcripts keep
  chain-only verification.

## Conventions used in this runbook

- `STORE=/etc/governance/signer-shares.json` — the share-store file
  (wrapped blobs + metadata only; safe to copy, never holds plaintext).
- `TRANSCRIPT=/var/lib/governance/ceremonies.jsonl` — the ceremony
  transcript (JSONL). Sidecar: `TRANSCRIPT.tip.json`
  (`tip_manifest_path()`).
- `ROOT_SEED` — raw 32-byte file on encrypted removable media, offline
  machine only. Never on a networked host.
- `ROSTER` — the current root-signed roster dict (JSON). Verifiers trust
  exactly one root public key, distributed **out of band** (no code path —
  see §3/§4).
- Python snippets run with the repo importable (`PYTHONPATH=<repo>`).
  **There is no ceremony CLI** — ceremonies are Python API calls; operators
  script them (limitation L1).

## Rehearsal (mandatory before any production ceremony)

Rehearse every ceremony below with `FakeKmsProvider` first. It is
**test-only** (fixed wrap secret, zero production security) and the config
factory refuses it **unconditionally** — wave-81 deleted the
`GOV_DEV_KEYS` opt-in, so the rehearsal constructs it directly in code
(this is the only supported way to get one):

```python
from gov.kms import FakeKmsProvider
provider = FakeKmsProvider(key_ids=["test-kms-1", "test-kms-2"])
```

Production KMS wiring: `kms_provider_from_config` raises `KmsError` for
`aws`/`gcp`/`azure` — **real cloud adapters are not shipped** ($0 spend, no
credentials, no network). A HashiCorp Vault transit-engine adapter IS
shipped (`gov/kms_vault.py`, `provider: vault`, credentials from
`VAULT_ADDR`/`VAULT_TOKEN` in the environment — never the config file);
it is validated against an in-memory fake transport only, so **real-server
validation is required before any production claim**. Otherwise a
production deployment requires an operator-built `KmsProvider` subclass
implementing `wrap_data_key`, `unwrap_data_key` (must authenticate
key-id binding), and `describe_key` (limitation L2).
`FakeKmsProvider.disable_key()` / `outage = True` exist only for
rehearsing failure paths.

---

## 1. Genesis ceremony

Creates the first root-signed roster: enrolls keyholder shares into a
`SignerShareStore`, initializes the offline root, builds the roster, and
opens the hash-chained ceremony transcript.

### 1.1 Prerequisites

- [ ] Offline ceremony machine: no network, encrypted removable media ready
      for the root seed. Two operators present (dual control).
- [ ] KMS key id chosen and reachable through your provider instance
      (`provider.describe_key(kms_key_id)` succeeds).
- [ ] Keyholder labels decided. Labels must match
      `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (else `ValueError`).
- [ ] Threshold `k` of `n` keyholders decided (`1 <= k <= n` enforced by
      `make_roster`).
- [ ] Rehearsal completed on throwaway files with `FakeKmsProvider`.

### 1.2 Step-by-step

**Step A — Enroll shares (operational host with KMS access).**

```python
from gov.custody import SignerShareStore, generate_seed

store = SignerShareStore()
# One call per keyholder. Seed defaults to generate_seed() (secrets-based);
# pass seed= explicitly only when the keyholder generated it offline (§4).
for label in ["alice", "bob", "carol"]:
    key_id = store.add_share(label, provider, kms_key_id="prod-kms-1",
                             note="genesis enrollment")
    print(label, "->", key_id)
store.save("/etc/governance/signer-shares.json")   # atomic, 0600
```

`add_share` wraps the seed under the KMS key *before* touching store
state; a wrap failure raises `KmsError` with the store unmutated.
A duplicate label raises `ValueError`.

**Step B — Initialize the offline root (offline machine).**

```python
from gov.custody import generate_seed, save_root_seed, root_signer_from_seed

root_seed = generate_seed()                      # secrets.token_bytes(32)
save_root_seed("/media/encrypted/root-seed.bin", root_seed)  # atomic, 0600
root = root_signer_from_seed(root_seed)          # memory only
print("ROOT PUBKEY (distribute out of band):", root.public_key.hex())
print("root key id:", root.key_id)
```

**Step C — Build and root-sign the genesis roster, open the transcript.**

The genesis ceremony needs the store's *public* metadata plus the root
seed, so carry the store file (wrapped blobs only — no plaintext) to the
offline machine on removable media, and run:

```python
from gov.custody import (SignerShareStore, make_genesis_roster,
                         verify_ceremony_chain)
from gov.signing import roster_hash

store = SignerShareStore.load("/media/transfer/signer-shares.json")
# load() refuses group/world-readable files — chmod 600 first if needed.

roster, record = make_genesis_roster(
    store, threshold=2, root_seed=root_seed,
    participants=["alice", "bob", "carol", "operator-1", "operator-2"],
    transcript_path="/media/transfer/ceremonies.jsonl")
# prev_roster_hash is "GENESIS" automatically; a root-signed tip manifest
# is written to ceremonies.jsonl.tip.json by the same call.

print("genesis roster hash:", roster_hash(roster))
```

then carry the roster, transcript, and tip manifest back to the
operational host. Publish the roster to verifiers and the root pubkey
out of band.

(Alternative without moving the store file: keyholders publish pubkeys;
build the roster with `PublicSigner(key_id, pubkey)` handles and
`gov.signing.make_roster(signers, threshold, root, prev_roster_hash=None)`
directly. `make_genesis_roster` is the preferred path because it also
opens the transcript and writes the tip manifest.)

### 1.3 Verification

On the operational host, with the out-of-band root pubkey:

```python
from gov.custody import verify_ceremony_chain, verify_transcript_tip
from gov.signing import verify_roster, roster_hash

ok, err = verify_ceremony_chain(TRANSCRIPT, trusted_root_pub=ROOT_PUB)
assert ok, err                                    # chain + tip binding
ok, err = verify_transcript_tip(TRANSCRIPT, trusted_root_pub=ROOT_PUB)
assert ok, err                                    # explicit tip check
assert verify_roster(roster, ROOT_PUB)            # root signature on roster
print("genesis roster:", roster_hash(roster))
```

Expected: all pass. `verify_roster` returns False (not an exception) on a
bad signature — treat False as failure.

### 1.4 What can go wrong

| Symptom | Cause | Response |
|---|---|---|
| `KmsError` during `add_share` | KMS outage / unknown / disabled key | Abort. Store is unmutated (wrap-first ordering). Fix KMS, retry. |
| `ValueError: no active shares to roster` | Store empty or all shares retired | Enroll shares first; genesis needs ≥1 active share. |
| `PermissionError` on `load` | File is group/world-readable | `chmod 600` the file, then load. Never bypass the check. |
| Transcript longer than manifest (`n > mcount`) | Non-root records appended after the last root ceremony | Run one `update_tip_manifest(TRANSCRIPT, ROOT_SEED)` root ceremony (§2.3). |
| Missing `TRANSCRIPT.tip.json` on a manifest-scheme transcript | Sidecar lost or never written | Fail-closed: do not trust the tail. Re-run `update_tip_manifest` from the offline root. |

---

## 2. Share rotation / rewrap ceremony

Two distinct operations. **Share rotation** replaces a keyholder's signing
key (roster changes; root ceremony required). **Rewrap** rotates the KMS
master key (no roster change; transcript entry only).

### 2.1 Prerequisites

- [ ] Current roster and its hash (`roster_hash(prev_roster)`).
- [ ] Store file loaded with `SignerShareStore.load` (0600 enforced).
- [ ] For share rotation: the new seed, generated on a clean machine via
      `generate_seed()`; the offline root seed available for the roster
      ceremony.
- [ ] For rewrap: the new KMS key id exists and `describe_key` succeeds.
- [ ] Scripted multi-operator ceremonies must hold the advisory file lock:
      `with gov.keys.rotation_lock(store_path):` around load→mutate→save
      (the in-process `_share_mutation_lock` does not serialize across
      processes — limitation L3).

### 2.2 Share rotation — step-by-step

```python
from gov.custody import SignerShareStore, record_ceremony, rotate_roster
from gov.keys import rotation_lock

with rotation_lock(STORE):
    store = SignerShareStore.load(STORE)
    old_kid, new_kid = store.rotate_share(
        "alice", provider, kms_key_id="prod-kms-1",
        note="routine rotation 2026-09-22")
    store.save(STORE)

# Root ceremony (offline machine): new roster chaining the old.
roster, record = rotate_roster(
    store, prev_roster, root_seed,
    participants=["alice", "operator-1", "operator-2"],
    transcript_path=TRANSCRIPT)
# threshold defaults to the previous roster's threshold.
```

Semantics, grounded in the code:

- `rotate_share` wraps the new seed FIRST; KMS failure leaves the store
  unmutated. The old record is **retained** as `status="retired"` (with
  `retired_utc`) in `store.retired_shares(label)` — old checkpoints must
  stay verifiable. There is **no API to purge a retired seed** (limitation
  L4; see §3).
- `rotate_share` on a non-active label raises `ValueError`.
- **The roster does not update itself.** Until `rotate_roster` runs, the
  new key is *not* authorized to sign checkpoints. Treat the window
  between `rotate_share` and `rotate_roster` as a pending change, not a
  completed rotation.
- `rotate_roster` writes the root-signed tip manifest for the new head.

Verification: same as §1.3, plus confirm the new roster's
`prev_roster_hash` equals `roster_hash(prev_roster)` and the retired key
id is absent from the new roster's `keys`.

### 2.3 Rewrap (KMS master-key rotation) — step-by-step

```python
from gov.custody import (SignerShareStore, record_ceremony,
                         update_tip_manifest, verify_transcript_tip)
from gov.keys import rotation_lock

with rotation_lock(STORE):
    store = SignerShareStore.load(STORE)
    store.rewrap(provider, new_kms_key_id="prod-kms-2")
    store.save(STORE)

# rewrap() writes NO transcript entry itself (limitation L5) — record it:
record_ceremony(TRANSCRIPT, "rewrap",
                participants=["operator-1", "operator-2"],
                detail={"new_kms_key_id": "prod-kms-2",
                        "note": "KMS master-key rotation; signing keys unchanged"})
# A non-root append leaves the transcript longer than the tip manifest,
# so verification now fails closed until a root ceremony re-binds the tip:
update_tip_manifest(TRANSCRIPT, root_seed,
                    participants=["operator-1", "operator-2"])
ok, err = verify_transcript_tip(TRANSCRIPT, trusted_root_pub=ROOT_PUB)
assert ok, err
```

Semantics: `rewrap` unwraps every share (active and retired history) and
re-wraps under the new KMS key id; all fallible KMS calls complete before
any store state is mutated. Key ids are over the seeds, which are
unchanged, so **no roster change is needed**.

### 2.4 What can go wrong

| Symptom | Cause | Response |
|---|---|---|
| `KmsError` mid-`rewrap` | New KMS key unreachable/disabled | Abort. Store unmutated. Do not retry against a different key id without recording the deviation. |
| `ValueError: share ... is not active` | Rotating an already-retired label | Check `store.active_labels()`; you may be rotating twice. |
| Verification fails with "transcript longer than the root-signed tip manifest" after rewrap | Expected: non-root `record_ceremony` cannot refresh the manifest | Run `update_tip_manifest` (§2.3). Never delete the manifest to silence this. |
| `update_tip_manifest` raises `ValueError: cannot anchor a broken transcript` | Chain tamper detected | Stop. Treat as a compromise (§3), not a verification glitch. |

---

## 3. Compromise response

The code has **no dedicated compromise/revoke API** — response is composed
from rotation primitives plus operational containment (limitation L6).
Assume the worst, verify everything, record every step in the transcript.

### 3.1 Suspected keyholder-share compromise

**Contain (immediately).**

1. Stop the signing host / checkpoint pipeline that uses the share.
   (`threshold_signer` / `active_signers` unwrap on demand; halting the
   host stops further unwraps.)
2. If the KMS layer itself may be involved, disable or rotate the KMS key
   at the provider (operator console — no code path for real providers;
   `FakeKmsProvider.disable_key()` exists for rehearsal only). Any further
   `unwrap_data_key` then raises `KmsError` fail-closed.
3. Preserve evidence: copy the store file and transcript (read-only) before
   mutating anything.

**Eradicate / recover.**

```python
from gov.custody import (SignerShareStore, generate_seed, rotate_roster,
                         record_ceremony, verify_ceremony_chain)
from gov.keys import rotation_lock

with rotation_lock(STORE):
    store = SignerShareStore.load(STORE)
    # Fresh seed generated on a CLEAN machine, never on the suspect host.
    old_kid, new_kid = store.rotate_share(
        "alice", provider, seed=generate_seed(),
        note="compromise response: suspected share compromise 2026-09-22")
    store.save(STORE)

# Root ceremony deauthorizes the old key id from the roster:
roster, record = rotate_roster(store, prev_roster, root_seed,
                               participants=["incident-commander",
                                             "operator-1", "operator-2"],
                               transcript_path=TRANSCRIPT)
record_ceremony(TRANSCRIPT, "compromise-response",
                participants=["incident-commander"],
                detail={"label": "alice", "old_key_id": old_kid,
                        "new_key_id": new_kid,
                        "note": "old key id deauthorized; see rotate-roster record"})
```

**Verify.**

- `verify_ceremony_chain(TRANSCRIPT, trusted_root_pub=ROOT_PUB)` → ok.
- Old `key_id` absent from the new roster's `keys`; new roster verifies
  with `verify_roster(roster, ROOT_PUB)`.
- `store.retired_shares("alice")` shows the old record as `retired`.

**Honest limits of recovery.**

- The compromised seed's *wrapped* blob remains in the store file and in
  `retired_shares` history — **retired records cannot be purged via any
  API** (L4). If the attacker exfiltrated the wrapped blob *and* can unwrap
  it (KMS breach), assume the seed is known: the rotation above already
  deauthorizes it, which is the effective mitigation.
- Checkpoints already signed by the old key remain verifiable under the
  retired key id **by design** (same argument as `gov/keys.py`: deleting a
  key orphans everything it signed). They cannot be "un-signed". If any
  checkpoint in the suspicious window may be attacker-signed, that is an
  application-level incident: identify affected checkpoints out of band.
- `signer_for` re-verifies the unwrapped seed against the recorded key id
  on every call, so a store file swapped by the attacker fails closed
  rather than silently adopting new material — but verify the transcript
  chain anyway; a full-transcript rewrite under a different root identity
  still verifies as a self-consistent chain (documented residual in
  `gov/custody.py` — roster signatures against the out-of-band root pub
  are what bind the lineage).

### 3.2 Suspected roster compromise (forged / untrusted roster)

Rosters are root-signed; a roster that does not verify against the
out-of-band trusted root pubkey is rejected:

```python
from gov.signing import verify_roster
if not verify_roster(suspect_roster, TRUSTED_ROOT_PUB):
    # Forgery or corruption — do not sign or verify checkpoints against it.
```

Response: (1) quarantine the suspect roster; (2) re-verify the full roster
lineage from genesis via the transcript (`prev_roster_hash` chain in each
`rotate-roster` record's detail); (3) redistribute the genuine roster from
the offline ceremony archive; (4) record a `compromise-response` transcript
entry. If the *root key* is what is suspect, go to §3.3.

### 3.3 Root-key compromise (break-glass)

There is **no root-rotation helper in the code** — this is a manual
procedure (documented in `gov/custody.py`):

1. On a fresh offline machine, `root_seed_new = generate_seed()` and
   `save_root_seed()` to *new* encrypted removable media. Destroy the old
   media per your media-destruction policy (procedural — no code path).
2. Build the new roster with the new root:
   `rotate_roster(store, prev_roster, root_seed_new, ...)` — it accepts any
   root seed; `root_key_id` in the record will be the new root's.
3. **Redistribute the new root public key out of band** to every verifier
   (procedural — no code path). Until verifiers pin the new root pub,
   `verify_roster` against the old pin keeps passing for old artifacts and
   fails for new ones; coordinate the cutover explicitly.
4. Run `update_tip_manifest(TRANSCRIPT, root_seed_new)` so the tip manifest
   binds the new root lineage (the manifest's `root_key_id` must equal the
   newest root ceremony record's `root_key_id` — enforced by
   `_check_tip_binding`).
5. Record a `root-rotation` transcript entry noting the reason. Note the
   lineage binding is by *record*, not by history rewrite: the old
   root-signed records remain in the chain (tamper-evident history of the
   compromise itself).

---

## 4. Air-gapped manual custody

**The code provides no manual-custody path** (`gov/custody.py`: "Manual
custody (air-gapped). No code path"). This section is pure procedure. The
ceremony functions still work because rosters need only *public* keys.

### 4.1 Prerequisites

- [ ] Offline ceremony machine, encrypted removable media (one per
      keyholder plus one for the root), two operators present for all
      handling (dual control).
- [ ] Media encryption and dual-control enforcement are **procedural** —
      the code cannot encrypt media or enforce two-person presence (L7).

### 4.2 Seed handling

1. On the offline machine, per keyholder:
   ```python
   from gov.custody import generate_seed, save_root_seed
   from gov.signing import Ed25519Signer, ed25519_key_id

   seed = generate_seed()                       # secrets-based, 32 bytes
   save_root_seed("/media/encrypted/alice-seed.bin", seed)  # atomic, 0600
   # save_root_seed writes raw 32 bytes; reuse the same discipline per keyholder.
   pub = Ed25519Signer(seed).public_key
   print("alice key_id:", ed25519_key_id(pub), "pub:", pub.hex())
   ```
   The printed key id / pubkey is what the keyholder publishes to the
   ceremony. **Private seeds never leave their media**; only pubkeys travel.
2. Hand each keyholder their media. Log custody transfers on paper / in the
   transcript participants list (procedural).

### 4.3 Ceremony with public keys only

Keyholders bring pubkeys; the ceremony never sees private seeds:

```python
from gov.custody import PublicSigner, make_genesis_roster  # or rotate_roster

# key_id must equal ed25519_key_id(public_key) — enforced by PublicSigner.
signers = [PublicSigner(key_id_alice, pub_alice),
           PublicSigner(key_id_bob, pub_bob),
           PublicSigner(key_id_carol, pub_carol)]
# PublicSigner.sign() always raises: this handle can never sign.

from gov.signing import make_roster
from gov.custody import (root_signer_from_seed, record_ceremony,
                         write_tip_manifest, tip_manifest_path,
                         read_ceremonies)
root = root_signer_from_seed(load_root_seed("/media/encrypted/root-seed.bin"))
roster = make_roster(signers, 2, root, prev_roster_hash=None)  # or "GENESIS"
```

Prefer `make_genesis_roster` / `rotate_roster` when a `SignerShareStore`
is available (they open the transcript and write the tip manifest in one
call); use `make_roster` + `record_ceremony(..., root_signer=root)` when
working from bare `PublicSigner` handles. Either way, pass `root_signer`
so the tip manifest is written — a root ceremony without it leaves the
transcript longer than the manifest and verification fails closed.

### 4.4 Signing checkpoints under manual custody

No share store is involved. Per checkpoint, on each keyholder's own
machine:

```python
from gov.custody import load_root_seed
from gov.signing import Ed25519Signer

seed = load_root_seed("/media/encrypted/alice-seed.bin")  # 0600 enforced
sig = Ed25519Signer(seed).sign(checkpoint_bytes)
# Keyholder returns (key_id, sig) to the coordinator out of band.
```

The coordinator assembles `sig_entries` and verifiers check them with
`gov.signing.verify_threshold(data, sig_entries, roster,
trusted_root_pub)`. `ThresholdSigner` is the KMS-path convenience (seeds
unwrapped to memory on the signing host via `threshold_signer` /
`active_signers`); under manual custody each keyholder signs locally and
only signature bytes cross the air gap.

### 4.5 What can go wrong

| Symptom | Cause | Response |
|---|---|---|
| `ValueError: key_id does not match public_key` from `PublicSigner` | Transcription error in the published pubkey | Re-transcribe from the keyholder's media; never "fix" the key id to match. |
| `RuntimeError: PublicSigner holds no private seed` | Ceremony script tried to sign with a public handle | By design. Signing happens on keyholder machines (§4.4). |
| Lost or damaged keyholder media | No backup | Restore from the encrypted backup copy held under dual control (procedural). If no backup exists, run a share rotation (§2.2): the lost key id is deauthorized by `rotate_roster`. There is no key-recovery API — a lost seed is unrecoverable by design. |
| `PermissionError` on `load_root_seed` | Media mounted with wrong perms | Remount / `chmod 600`; the check is fail-closed. |

---

## Appendix A — API quick reference (all names verified against the code)

| Function / class | Module | Used for |
|---|---|---|
| `SignerShareStore` (`add_share`, `get`, `labels`, `active_labels`, `describe`, `signer_for`, `threshold_signer`, `active_signers`, `public_signers`, `rotate_share`, `retired_shares`, `rewrap`, `save`, `load`, `from_dict`, `to_dict`) | `gov.custody` | KMS-envelope custody lifecycle |
| `generate_seed(rng=None)` | `gov.custody` | 32-byte seeds (`secrets`-based by default) |
| `PublicSigner(key_id, public_key)` | `gov.custody` | Public-only roster handle; `sign()` raises |
| `save_root_seed` / `load_root_seed` / `root_signer_from_seed` | `gov.custody` | Offline root custody (0600 enforced) |
| `make_genesis_roster` / `rotate_roster` | `gov.custody` | Root-signed roster ceremonies (+ transcript + tip manifest) |
| `record_ceremony` / `read_ceremonies` | `gov.custody` | Transcript append / read (JSONL, 0600) |
| `verify_ceremony_chain` / `verify_transcript_tip` | `gov.custody` | Chain + tip-manifest verification, fail-closed |
| `update_tip_manifest` | `gov.custody` | Root tip-anchor ceremony; legacy migration; post-non-root-append re-binding |
| `write_tip_manifest` / `read_tip_manifest` / `verify_tip_manifest` / `tip_manifest_path` | `gov.custody` | Tip-manifest primitives |
| `KmsProvider` / `KmsError` / `FakeKmsProvider` / `kms_provider_from_config` | `gov.kms` | Envelope API; test double; config factory |
| `make_roster` / `roster_hash` / `verify_roster` / `verify_threshold` / `ThresholdSigner` / `Ed25519Signer` / `ed25519_key_id` / `GENESIS_ROSTER` | `gov.signing` | Roster construction and checkpoint verification |
| `rotation_lock` | `gov.keys` | Advisory file lock for scripted multi-process ceremonies |

## Appendix B — Explicit limitations (no code support)

- **L1.** No ceremony CLI or interactive wizard — all ceremonies are Python
      API calls; operators script them.
- **L2.** No production cloud KMS adapter is shipped; `aws`/`gcp`/`azure`
      raise `KmsError` from the config factory. Operator-built
      `KmsProvider` subclass required (must authenticate key-id binding).
- **L3.** Ceremony functions take no file lock; cross-process scripted
      ceremonies must wrap load→mutate→save in `gov.keys.rotation_lock`.
- **L4.** No API purges retired share records; retired seeds are retained
      by design (old checkpoints stay verifiable).
- **L5.** `SignerShareStore.rewrap` writes no transcript entry; the
      operator must `record_ceremony` + `update_tip_manifest`.
- **L6.** No dedicated compromise/revoke API; response composes
      containment + `rotate_share` + `rotate_roster`.
- **L7.** Manual custody is procedure-only: no code encrypts media,
      enforces dual control, distributes the root pubkey out of band, or
      recovers a lost seed.
