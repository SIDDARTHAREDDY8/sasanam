# zot Signed-Only Registry — Operator Runbook (private v1)

Wave-199 lane E. This runbook is for the OPERATOR who runs Sasanam's
self-hosted zot registry for evidence-bundle distribution. It states
what zot is, what it is not, and what production actually requires.
Every step is marked **validated-live** (ran 2026-09-29 against real
zot v2.1.21 + cosign v3.1.3 + oras 1.3.4, all local, $0) or
**validated-by-docs** (read from zot source/README, not executed).
Nothing here is aspirational: every "not in v1" is marked.

## 1. What zot is in Sasanam (the layering contract)

zot is the **distribution point** for signed evidence bundles —
evidence bundles ship as OCI artifacts (wave-192,
`gov/evidence_distribute.py`), and zot answers the question
"where do signed evidence bundles live?" with a self-hosted,
vendor-neutral OCI registry. Apache-2.0, verified from LICENSE
bytes. We do not vendor zot; the operator runs the released binary.

A zot `imagetrust` report is a **signature-trust report only**:

- It reports, per artifact, `IsSigned` plus a `SignatureInfo` list:
  the signing tool (`cosign`/`notation`), whether the signature
  verifies against an operator-uploaded key (`IsTrusted`), and the
  author (the public key for cosign, the certificate subject for
  notation).
- It is **never** an authority proof and **never** a gate.
  Authority stays with Sasanam's own signed checkpoints and the
  witness quorum (`docs/REKOR_RUNBOOK.md` §1).

zot is **availability, not truth**: if the registry is wiped, the
offline evidence bundles (`build_offline_bundle()`) still verify
with zero server contact. The registry being down is an
availability incident, not an integrity incident.

## 2. Honest correction: imagetrust reports, it does not refuse

The wave-198 prospectus described this as "the registry itself
refuses unsigned artifacts." That is not what the code does.
Measured live and confirmed in
`pkg/extensions/extension_image_trust.go` + `pkg/extensions/imagetrust/`:

- `imagetrust` runs a verification task (scheduled every 2 hours,
  and observed re-running on signature push — trust state was
  visible within seconds of pushing a signature, validated-live)
  that checks signatures against the keys in `_cosign/` and stores
  the result in the metaDB, surfaced through the `search`
  extension's GraphQL.
- **Pushes and pulls are never refused for being unsigned or
  untrusted.** An unsigned artifact serves normally; a signature
  from an unknown key is reported with `IsTrusted: false`.

"Signed-only" is therefore an **auditor-side enforcement policy**,
not a registry property: the auditor pulls by digest pin, queries
the registry's trust report, and refuses the bundle unless the
report shows a trusted signature (§7). This composes cleanly with
the wave-191/192 design — the client (`gov/evidence_distribute.py`)
already refuses by digest discipline; the registry-side report
closes the "did anyone sign this" question at the distribution
point.

## 3. Self-hosted only (non-negotiable)

Sasanam distributes evidence through an **operator-run** zot.
There is no hosted registry in the story ($0 posture, no external
trust dependency). The signing keys come from the operator's own
key ceremony (§5) — never from a public identity service. The
cosign signing config used here carries **no transparency log**
(`rekorTlogConfig: {}`); artifact existence is anchored by
Sasanam's own Rekor lane, not by Sigstore's public log (§8).

## 4. Deployment config (local / lab VM, $0)

**Validated-live.** zot v2.1.21 `zot-linux-amd64` from the GitHub
release page (228 MB, no install, no Go toolchain needed):

```json
{
  "storage": {
    "rootDirectory": "/var/tmp/zot-root"
  },
  "http": {
    "address": "127.0.0.1",
    "port": "8080"
  },
  "log": { "level": "info" },
  "extensions": {
    "search": {
      "enable": true,
      "cve": { "updateInterval": "0h" }
    },
    "trust": {
      "enable": true,
      "cosign": true,
      "notation": true
    }
  }
}
```

Run: `zot serve /path/to/config.json`. Confirm with
`curl http://127.0.0.1:8080/v2/` → `200`.

Notes:

- `cve.updateInterval: "0h"` disables CVE scanning (no external
  database fetch — $0/air-gap posture). **Validated-live.**
- The lab-VM variant is the same file with `address` bound to the
  lab interface and TLS in front (§10). **Validated-by-docs.**
- The registry's trust state lives in the storage rootDir
  (`_cosign/`, `_notation/`, metaDB). Back it up with the rootDir
  (§9). **Validated-by-docs.**

## 5. The key ceremony (operator-owned)

The ceremony lives here, not in product code. **Validated-live**
unless noted.

1. Generate the evidence-signing keypair locally:

   ```bash
   cosign generate-key-pair --output-key-prefix sasanam-evidence
   ```

   (cosign v3.1.3 prompts twice for a key password; pipe the
   answers or set `COSIGN_PASSWORD`. An encrypted key whose
   password you lose is unrecoverable — store the password in the
   KMS, not on the registry host.)

2. Upload the public key to zot (admin channel, not a product
   seam):

   ```bash
   curl --data-binary @sasanam-evidence.pub -X POST \
     "http://127.0.0.1:8080/v2/_zot/ext/cosign"   # -> 200
   ```

   The key is stored under `<rootDir>/_cosign/` named by its
   content hash. **Validated-live.**

3. Verify the upload took effect by signing an artifact and
   querying the trust report (§6–7). A key that never appears as
   `Author` in any `SignatureInfo` is a misconfigured key.

**Rotation:** delete the old public key file from `<rootDir>/_cosign/`
and upload the new one. `PublicKeyLocalStorage.GetPublicKeys()`
re-reads the directory on every verification pass
(`os.ReadDir`, `pkg/extensions/imagetrust/cosign.go`), so rotation
takes effect on the next pass without a restart — the 2-hour
scheduled task bounds the propagation delay. **Validated-by-docs.**
The old key stays archived by the operator for auditors verifying
old bundles (same discipline as `docs/REKOR_RUNBOOK.md` §4).

**Notation** (certificates): same pattern via
`POST /v2/_zot/ext/notation?truststoreType=ca`, stored under
`_notation/truststore/x509/<type>/default/`. **Validated-by-docs
only** — not exercised live.

## 6. Push path: evidence bundle as a signed OCI artifact

**Validated-live** with oras 1.3.4 as the operator client. The
product seam (`gov/evidence_distribute.py`: `push_bundle`,
`attach_bom`, `attach_signature`, `pull_bundle`, `audit_bundle`)
defines the same shapes; the operator may use either the product
client adapter or the CLI below. The CLI commands below push the
bundle, the BOM, and the signature as OCI referrers of one subject
digest:

```bash
# 1. Pack the bundle (product: gov.evidence_distribute.pack_bundle —
#    deterministic tar; the digest below is the bundle's identity).
oras push --plain-http \
  localhost:8080/sasanam/evidence-bundle:v1 \
  evidence.tar:application/vnd.sasanam.evidence.tar
# -> Digest: sha256:c0c5fb6f9876...  (your digest will differ)

# 2. Sign the subject digest with the ceremony key. cosign v3.x needs
#    an explicit signing config to stay off the public transparency
#    log (self-hosted posture); generate it once:
cosign signing-config create --out signing-config.json
# signing-config.json carries rekorTlogConfig:{} and tsaConfig:{}.

COSIGN_PASSWORD="<key password>" cosign sign --yes \
  --signing-config signing-config.json \
  --key sasanam-evidence.key \
  --allow-insecure-registry \
  localhost:8080/sasanam/evidence-bundle@sha256:<DIGEST>
# -> "Pushing signature to: localhost:8080/sasanam/evidence-bundle"
```

The signature lands as a referrer (`application/vnd.oci.image.manifest.v1+json`
with `dev.sigstore.bundle.content: dsse-envelope`), discoverable via
`GET /v2/sasanam/evidence-bundle/referrers/sha256:<DIGEST>`.
**Validated-live.**

The BOM rides the same way (product: `attach_bom`; CLI: `oras attach`
with `artifactType` set) so the bundle, its BOM, and its signature
are one referrer graph under one subject digest.

## 7. Pull-side verification flow (the auditor's discipline)

**Validated-live.** The auditor enforces "signed-only"; the registry
only reports. Fail closed on every step:

1. **Pull by digest, never by tag mid-audit.**

   ```bash
   oras pull --plain-http \
     localhost:8080/sasanam/evidence-bundle@sha256:<DIGEST>
   ```

   Byte-compare the fetched blob against the recorded digest —
   `cmp` must be silent. A lying registry (serving wrong bytes for
   a digest) is caught here, exactly as `gov/evidence_distribute.py`
   already does (D2). **Validated-live (byte-identical).**

2. **Require the registry's trust report to show a trusted signature.**

   ```graphql
   { Image(image:"sasanam/evidence-bundle:v1") {
       IsSigned Tag SignatureInfo { Tool IsTrusted Author } } }
   ```

   Accept only when some entry has `IsTrusted: true` and its
   `Author` is a key in the operator's published key set.
   Observed live: trusted key → `IsSigned:true,
   IsTrusted:true, Author:<our pubkey>`; unsigned artifact →
   `IsSigned:false, SignatureInfo:[]`; unknown-key signature →
   `IsSigned:true, IsTrusted:false`. **Validated-live, all three.**

3. **Verify the signature client-side.**

   ```bash
   cosign verify --insecure-ignore-tlog \
     --key sasanam-evidence.pub --allow-insecure-registry \
     localhost:8080/sasanam/evidence-bundle@sha256:<DIGEST>
   ```

   (`--insecure-ignore-tlog` because the signing config has no
   transparency log by design — existence is anchored by Sasanam's
   Rekor lane, §8.) **Validated-live.**

4. Run the standalone bundle verifier against operator pins
   (`gov/evidence_verify.py`, product seam). A bundle that passes
   1–3 but fails the standalone verifier is refused — the registry
   says "signed", only Sasanam's verifier says "valid."

## 8. Composition with Rekor anchoring (who catches what)

The wave-194/198 Rekor lane (`docs/REKOR_RUNBOOK.md`) and this
registry lane are complementary; neither subsumes the other.
Consistent with the Rekor runbook's §1 layering contract:

| Threat | Caught by | Not caught by |
|---|---|---|
| Backdated bundle ("this existed last month") | **Rekor**: digest-existence entry with `integratedTime`; witness quorum detects equivocation | zot (registry has no time anchor) |
| Registry serves stale-but-valid bytes | **Digest pinning** (pull by digest + byte-compare, §7.1) | Rekor, zot trust report |
| Registry serves wrong bytes for a digest | **Digest pinning** (§7.1) | Rekor, zot trust report |
| Unsigned / unknown-key bundle presented as evidence | **zot trust report + auditor policy** (§7.2) and client-side `cosign verify` (§7.3) | Rekor (log accepts any digest) |
| Bundle contents tampered after signing | **cosign signature** (digest-bound) | Rekor |
| Registry claims a signature is trusted when it is not | **Client-side cosign verify** (§7.3) — never trust `IsTrusted` alone | zot itself |
| Log equivocation (same size, different root) | **Rekor witness** (`docs/REKOR_RUNBOOK.md` §5–6) | zot |

Grade reminder, shared with the Rekor runbook: a verified registry
signature proves "this bundle was signed by a trusted key"; a
verified Rekor receipt proves "this digest existed no later than T".
Neither is an authority proof. Authority stays with Sasanam's
signed checkpoints + witness quorum.

## 9. Failure modes and operator recovery

- **Registry down:** availability incident. Serve auditors the
  offline proof bundles; they verify with zero server contact
  (same posture as `docs/REKOR_RUNBOOK.md` §6). Restore the
  rootDir from backup; blobs are content-addressed, so a restored
  rootDir either serves the right digests or fails loudly.
  **Validated-by-docs.**
- **rootDir lost without backup:** the registry's trust state
  (`_cosign/`, metaDB) is gone with it. Bundles already held by
  auditors still verify offline; re-push bundles and re-upload keys
  to rebuild. This is why rootDir backup is a launch blocker
  (§10). **Validated-by-docs.**
- **Key compromise:** rotate per §5 (delete pub from `_cosign/`,
  upload new key; propagation ≤ 2h). Bundles signed by the old key
  keep verifying client-side for historical audit — the old key is
  quarantined, not deleted, in the operator's archive. Investigate
  before re-signing anything with the new key.
  **Validated-by-docs.**
- **Unsigned artifact appears in the repo:** expected — zot does
  not refuse it (§2). The auditor's pull discipline (§7.2) refuses
  it. If your policy requires the registry to *look* clean, delete
  the manifest by digest via the zot admin API. **Validated-live**
  (unsigned artifact served normally, reported `IsSigned:false`).
- **Untrusted-key signature:** reported `IsTrusted:false`
  (**validated-live**). The auditor refuses it at §7.2; client-side
  `cosign verify` with the operator key set also fails.
- **Trust report stale (signature pushed, report not updated):**
  the scheduled task runs every 2 hours; a signature push was
  observed to trigger re-verification within seconds
  (**validated-live** 2026-09-29). If staleness persists past 2h,
  check the zot log for the `imagetrust` task errors.
- **Registry accepts writes from anyone:** zot's write API has no
  auth in the dev config — same class of issue as
  `docs/REKOR_RUNBOOK.md` §3.3. Put it behind mTLS/API-gateway
  auth; never expose the write API to the open internet (§10).

## 10. What private v1 explicitly does NOT have

- **No push/pull refusal for unsigned artifacts** (§2). Signed-only
  is auditor-enforced. Any future "the registry refuses" claim must
  be re-validated against the imagetrust source first — this
  runbook corrects the wave-198 prospectus shorthand.
- **No TLS/auth/HA in the dev config** (§4). Production needs all
  three plus rootDir backup/rehearsed restore — same launch-blocker
  discipline as `docs/REKOR_RUNBOOK.md` §3.
- **No notation path live validation** (§5). The config enables it;
  the ceremony and trust-report shape for notation are
  validated-by-docs only.
- **No cosign transparency log** (§6). The signing config disables
  the tlog by design; transparency is Sasanam's own Rekor lane.
  Auditor tooling must not expect `cosign verify` to check a public
  log for these bundles.
- **No KMS integration in the signing ceremony** — the key lives
  on the operator's machine in the dev ceremony. Production moves
  the ceremony key into the KMS (same blocker class as
  `docs/REKOR_RUNBOOK.md` §3.1).

## 11. Validation ledger

| Step | Result | How |
|---|---|---|
| zot v2.1.21 serves with `trust{cosign,notation}` + `search` | PASS | validated-live 2026-09-29 |
| Cosign pub upload `POST /v2/_zot/ext/cosign` → 200, stored in `_cosign/` | PASS | validated-live |
| oras push evidence artifact → digest | PASS | validated-live (oras 1.3.4) |
| cosign sign with own key (tlog-less signing config) → signature referrer | PASS | validated-live (cosign v3.1.3) |
| GraphQL trust report: trusted / unsigned / untrusted | PASS/PASS/PASS | validated-live (all three states) |
| Digest-pinned pull byte-identical | PASS | validated-live |
| cosign verify (insecure-ignore-tlog) | PASS | validated-live |
| Trust re-evaluation on signature push (seconds, not 2h) | PASS | validated-live (observed) |
| Key rotation without restart (dir re-read) | PASS | validated-by-docs (source) |
| Notation ceremony + trust report | — | validated-by-docs only |
| TLS/auth/HA/rootDir backup | — | validated-by-docs only; launch blockers |

**Operator tool versions pinned for this runbook:** zot v2.1.21,
cosign v3.1.3, oras 1.3.4. Re-validate the live steps when any of
these moves a major version — especially cosign's signing-config
behavior, which changed in v3.
